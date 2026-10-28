"""Download the NVD's CVSS v3.1 assessment events from the NVD CVE Change History API.

The NVD JSON 2.0 feeds give each CVE's current NVD vector but not the time at which the NVD assessed it. The Change
History API (https://services.nvd.nist.gov/rest/json/cvehistory/2.0) records every analysis event with its time and the
values it added or changed. This script requests the events named "Initial Analysis", "Reanalysis" and
"Modified Analysis" from 1 June 2022 (the earliest CISA SSVC decision in the analysed sample) to 26 October 2026 (the
date of the NVD feeds), in windows of at most 120 days (the API limit), and keeps the CVSS v3.1 details of each event.

Requests are spaced at least 6.5 seconds apart (the public limit without an API key is 5 requests in 30 seconds); up to
four requests run at the same time. Completed pages are recorded, so an interrupted run resumes where it stopped.

Output: data/nvd_cvss_history.parquet, one row per CVSS v3.1 detail: cve, event, created (as given by the API),
source, action, old (oldValue), new (newValue); data/nvd_cvss_history.meta.json (query, windows, counts, download
time). The raw pages are collected in data/nvd_cvss_history.jsonl; a run after all pages are complete only rebuilds
the parquet file and the metadata.
Usage: python src/fetch_nvd_history.py
"""

import json
import threading
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "nvd_cvss_history.jsonl"
PARQUET = ROOT / "data" / "nvd_cvss_history.parquet"
STATE = ROOT / "data" / "nvd_cvss_history.state.json"
META = ROOT / "data" / "nvd_cvss_history.meta.json"
API = "https://services.nvd.nist.gov/rest/json/cvehistory/2.0"
EVENTS = ("Initial Analysis", "Reanalysis", "Modified Analysis")
FIRST, LAST = date(2022, 6, 1), date(2026, 10, 26)
WINDOW_DAYS = 120
PAGE = 2000
MIN_GAP = 6.5

_lock = threading.Lock()
_next_start = [0.0]


def wait_turn():
    with _lock:
        now = time.monotonic()
        start = max(now, _next_start[0])
        _next_start[0] = start + MIN_GAP
    time.sleep(max(0.0, start - time.monotonic()))


def get(params, retries=6):
    url = API + "?" + urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
    err = None
    for k in range(retries):
        wait_turn()
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "research-script (read-only)"})
            with urllib.request.urlopen(req, timeout=600) as r:
                return json.loads(r.read())
        except Exception as e:  # rate limit, server error or timeout: back off and retry
            err = e
            time.sleep(min(120, 10 * 2 ** k))
    raise RuntimeError(f"{url}: {err}")


def windows():
    d = FIRST
    while d <= LAST:
        e = min(d + timedelta(days=WINDOW_DAYS - 1), LAST)
        yield d, e
        d = e + timedelta(days=1)


def run_task(event, start, end, done, counts):
    key = f"{event}|{start}"
    params = {"eventName": event, "changeStartDate": f"{start}T00:00:00.000Z",
              "changeEndDate": f"{end}T23:59:59.999Z", "resultsPerPage": PAGE}
    index = done.get(key, {}).get("next", 0)
    total = done.get(key, {}).get("total")
    while total is None or index < total:
        page = get({**params, "startIndex": index})
        total = page.get("totalResults", 0)
        rows = []
        for item in page.get("cveChanges", []):
            c = item["change"]
            for det in c.get("details", []):
                if det.get("type") == "CVSS V3.1":
                    rows.append({"cve": c["cveId"], "event": c["eventName"], "created": c["created"],
                                 "source": c.get("sourceIdentifier"), "action": det.get("action"),
                                 "old": det.get("oldValue"), "new": det.get("newValue")})
        index += len(page.get("cveChanges", [])) or PAGE
        with _lock:
            with OUT.open("a", encoding="utf-8") as f:
                f.writelines(json.dumps(r) + "\n" for r in rows)
            done[key] = {"next": index, "total": total}
            STATE.write_text(json.dumps(done, indent=1), encoding="utf-8")
            counts[key] = total
        print(f"{event} {start}: {min(index, total)}/{total}", flush=True)


def main():
    done = json.loads(STATE.read_text(encoding="utf-8")) if STATE.exists() else {}
    if not done and OUT.exists():
        OUT.unlink()
    counts = {}
    tasks = [(e, s, t) for s, t in windows() for e in EVENTS]
    with ThreadPoolExecutor(max_workers=4) as pool:
        for f in [pool.submit(run_task, e, s, t, done, counts) for e, s, t in tasks]:
            f.result()
    rows = pd.read_json(OUT, lines=True, dtype=False).drop_duplicates()
    rows.to_parquet(PARQUET, index=False)
    old_meta = json.loads(META.read_text(encoding="utf-8")) if META.exists() else {}
    META.write_text(json.dumps({
        "api": API, "events": EVENTS, "first": str(FIRST), "last": str(LAST), "window_days": WINDOW_DAYS,
        "event_totals": {k: v["total"] for k, v in done.items()}, "cvss_v31_details": int(len(rows)),
        "downloaded": old_meta.get("downloaded", datetime.now(timezone.utc).isoformat(timespec="seconds"))},
        indent=1), encoding="utf-8")
    print(f"done: {len(rows)} CVSS v3.1 details")


if __name__ == "__main__":
    main()
