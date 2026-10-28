"""Retrieve, for sampled CVEs, the Vulnrichment version of each record that CISA published with its current SSVC decision.

Candidates: records in data/snapshot_records.parquet that have a CISA SSVC
decision and a CNA CVSS vector (v3.x or v4.0), and whose CNA container was updated after the SSVC timestamp.
A random sample (seed 20261026) is drawn from the candidates.

For each sampled CVE the script searches the commit list (data/vulnrichment_commits.tsv) for the earliest commit whose copy
of the record carries the snapshot's SSVC timestamp, and stores that copy's CNA CVSS vectors, description and dates.
Files are read from raw.githubusercontent.com (no GitHub API, no token).

Records analysed before the repository existed were added later with their original SSVC timestamp, so the copy found
here can be much later than the decision; whether its CNA container predates the decision is checked in the analysis
(then_cna_date_updated <= ssvc_timestamp), not here.

Search: start at the last commit before (SSVC timestamp - 2 h), probe commits i, i+1, i+2, i+4, ... (up to the last
commit) until a probe is a hit
(the copy carries the snapshot's SSVC timestamp), then binary-search between the last miss and the hit for the earliest hit.
A probe is a miss when the file does not exist yet (HTTP 404), has no SSVC, or carries an older SSVC timestamp; it is
"superseded" when it carries a later SSVC timestamp. Timestamps are compared as times (tolerance 1 s), not as strings.
When no commit carries the snapshot's timestamp, the latest commit is checked: "absent_at_head" (record not in the
repository), "ts_mismatch" (repository carries a different SSVC timestamp than the CVE List snapshot), else "not_found".

Output: data/asof_versions.jsonl, one JSON object per sampled CVE; the script resumes where it stopped.
Usage: python src/fetch_asof_versions.py [--n 5000] [--threads 8]
"""

import argparse
import bisect
import json
import random
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
RECORDS = ROOT / "data" / "snapshot_records.parquet"
COMMITS = ROOT / "data" / "vulnrichment_commits.tsv"
OUT = ROOT / "data" / "asof_versions.jsonl"
RAW = "https://raw.githubusercontent.com/cisagov/vulnrichment/{sha}/{path}"
SEED = 20261026


def vr_path(cve):
    _, year, num = cve.split("-")
    return f"{year}/{int(num) // 1000}xxx/{cve}.json"


def candidates():
    df = pd.read_parquet(RECORDS)
    ts = pd.to_datetime(df.ssvc_timestamp, utc=True, format="mixed")
    cu = pd.to_datetime(df.cna_date_updated, utc=True, format="mixed")
    has_cvss = df.cna_v3.notna() | df.cna_v4.notna()
    return df[ts.notna() & has_cvss & (cu > ts)].sort_values("cve").reset_index(drop=True)


def get(url, retries=6):
    for k in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "research-script (read-only)"})
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            err = e
        except Exception as e:  # network errors: retry with backoff
            err = e
        time.sleep(min(60, 2 ** k))
    raise RuntimeError(f"failed after {retries} tries: {err}")


def ssvc_ts(doc):
    for a in doc.get("containers", {}).get("adp", []) or []:
        for m in a.get("metrics", []) or []:
            o = m.get("other") or {}
            if o.get("type") == "ssvc":
                return (o.get("content") or {}).get("timestamp")
    return None


def extract(doc):
    cna = doc.get("containers", {}).get("cna", {}) or {}
    v3 = v4 = None
    for m in cna.get("metrics", []) or []:
        for k in ("cvssV3_1", "cvssV3_0"):
            if k in m and v3 is None:
                v3 = m[k].get("vectorString")
        if "cvssV4_0" in m and v4 is None:
            v4 = m["cvssV4_0"].get("vectorString")
    cisa_v3 = None
    for a in doc.get("containers", {}).get("adp", []) or []:
        if (a.get("providerMetadata") or {}).get("shortName") == "CISA-ADP":
            for m in a.get("metrics", []) or []:
                if "cvssV3_1" in m:
                    cisa_v3 = m["cvssV3_1"].get("vectorString")
    return {
        "then_cna_v3": v3, "then_cna_v4": v4, "then_cisa_v3": cisa_v3,
        "then_cna_desc": next((x.get("value") for x in cna.get("descriptions", []) or []
                               if str(x.get("lang", "")).startswith("en")), None),
        "then_cna_date_updated": (cna.get("providerMetadata") or {}).get("dateUpdated"),
    }


def search(rec, shas, dates):
    target_t = pd.Timestamp(rec["ssvc_timestamp"]).tz_convert("UTC")
    t = target_t - pd.Timedelta(hours=2)
    start = max(0, bisect.bisect_left(dates, t) - 1)
    path = vr_path(rec["cve"])
    cache = {}

    def probe(j):
        if j not in cache:
            doc = get(RAW.format(sha=shas[j], path=path))
            if doc is None or ssvc_ts(doc) is None:
                cache[j] = ("miss", None)
            else:
                delta = (pd.Timestamp(ssvc_ts(doc)).tz_convert("UTC") - target_t).total_seconds()
                if abs(delta) < 1:  # same decision; timestamps may be written with different precision
                    cache[j] = ("hit", doc)
                else:
                    cache[j] = ("after", None) if delta > 0 else ("miss", None)
        return cache[j]

    last_miss, hit, step, j = start - 1, None, 1, start
    while True:
        state, _ = probe(j)
        if state == "hit":
            hit = j
            break
        if state == "after":
            return {"status": "superseded", "fetches": len(cache)}
        last_miss = j
        if j == len(shas) - 1:
            break
        j = min(start + step, len(shas) - 1)  # gallop to the end of the history if needed
        step *= 2
    if hit is None:
        # Diagnose: is the record missing from the repository, or does the repository carry a different SSVC timestamp
        # than the CVE List snapshot (the two are not always in sync)?
        head = get(RAW.format(sha=shas[-1], path=path))
        if head is None:
            return {"status": "absent_at_head", "fetches": len(cache) + 1}
        head_ts = ssvc_ts(head)
        if head_ts is None or abs((pd.Timestamp(head_ts).tz_convert("UTC") - target_t).total_seconds()) >= 1:
            return {"status": "ts_mismatch", "fetches": len(cache) + 1, "head_ssvc_timestamp": head_ts}
        return {"status": "not_found", "fetches": len(cache) + 1}
    lo, hi = last_miss + 1, hit  # earliest hit lies in [lo, hi]
    while lo < hi:
        mid = (lo + hi) // 2
        state, _ = probe(mid)
        if state == "hit":
            hi = mid
        elif state == "after":
            lo = mid + 1  # should not happen between a miss and a hit; keep the later hit
        else:
            lo = mid + 1
    out = {"status": "ok", "fetches": len(cache), "commit": shas[hi], "commit_date": str(dates[hi])}
    out.update(extract(probe(hi)[1]))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=5000)
    ap.add_argument("--threads", type=int, default=8)
    ap.add_argument("--limit", type=int, default=None, help="process at most this many of the remaining CVEs (for testing)")
    args = ap.parse_args()

    cand = candidates()
    sample = cand.sample(n=min(args.n, len(cand)), random_state=SEED)
    commits = pd.read_csv(COMMITS, sep="\t")
    shas = commits.sha.tolist()
    dates = pd.to_datetime(commits.date, utc=True).tolist()
    done = set()
    if OUT.exists():
        for line in OUT.read_text(encoding="utf-8").splitlines():
            try:
                done.add(json.loads(line)["cve"])
            except json.JSONDecodeError:  # a line cut off by an interrupted run; that CVE is fetched again
                continue
    todo = [r for r in sample.to_dict("records") if r["cve"] not in done][: args.limit]
    print(f"candidates {len(cand)}, sample {len(sample)}, already done {len(done)}, to do {len(todo)}", flush=True)

    lock, counts, t0 = threading.Lock(), {"n": 0}, time.time()

    def work(rec):
        try:
            res = search(rec, shas, dates)
        except Exception as e:
            res = {"status": "error", "error": str(e)[:200]}
        res = {"cve": rec["cve"], "ssvc_timestamp": rec["ssvc_timestamp"], **res}
        with lock:
            with OUT.open("a", encoding="utf-8") as f:
                f.write(json.dumps(res, ensure_ascii=False) + "\n")
            counts["n"] += 1
            counts[res["status"]] = counts.get(res["status"], 0) + 1
            if counts["n"] % 100 == 0 or counts["n"] == len(todo):
                print(f"{counts['n']}/{len(todo)} {time.time() - t0:.0f}s "
                      + " ".join(f"{k}={v}" for k, v in counts.items() if k != "n"), flush=True)

    with ThreadPoolExecutor(args.threads) as ex:
        list(ex.map(work, todo))


if __name__ == "__main__":
    main()
