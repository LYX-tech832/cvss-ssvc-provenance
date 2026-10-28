"""Download the NVD CVE JSON 2.0 yearly feeds and verify them against the published SHA-256 (of the decompressed JSON).

Output: data/external/nvd/nvdcve-2.0-<year>.json.gz plus the matching .meta files, and
data/external/nvd/download_manifest.json (year, size, sha256, lastModifiedDate, download time).
Files whose SHA-256 already matches the current .meta are not downloaded again.
Usage: python src/fetch_nvd_feeds.py [--first 2002] [--last 2026]
"""

import argparse
import gzip
import hashlib
import json
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "external" / "nvd"
BASE = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.{ext}"


def fetch(url, retries=5):
    for k in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "research-script (read-only)"})
            with urllib.request.urlopen(req, timeout=300) as r:
                return r.read()
        except Exception as e:
            err = e
            time.sleep(min(60, 5 * 2 ** k))
    raise RuntimeError(f"{url}: {err}")


def sha256(path):
    """SHA-256 of the decompressed JSON; the NVD .meta file publishes the hash of the uncompressed feed."""
    h = hashlib.sha256()
    with gzip.open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--first", type=int, default=2002)
    ap.add_argument("--last", type=int, default=2026)
    args = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    manifest_path = OUT / "download_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {}
    for year in range(args.first, args.last + 1):
        meta_txt = fetch(BASE.format(year=year, ext="meta")).decode()
        meta = dict(line.split(":", 1) for line in meta_txt.strip().splitlines() if ":" in line)
        gz = OUT / f"nvdcve-2.0-{year}.json.gz"
        if not (gz.exists() and sha256(gz) == meta["sha256"].strip().upper()):
            gz.write_bytes(fetch(BASE.format(year=year, ext="json.gz")))
        got = sha256(gz)
        ok = got == meta["sha256"].strip().upper()
        (OUT / f"nvdcve-2.0-{year}.meta").write_text(meta_txt, encoding="utf-8")
        manifest[str(year)] = {"bytes": gz.stat().st_size, "sha256": got, "sha256_ok": ok,
                               "lastModifiedDate": meta.get("lastModifiedDate"),
                               "downloaded": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
        manifest_path.write_text(json.dumps(manifest, indent=1), encoding="utf-8")
        print(year, gz.stat().st_size, "sha256 ok" if ok else "SHA256 MISMATCH", flush=True)


if __name__ == "__main__":
    main()
