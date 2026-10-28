"""Extract NVD's own CVSS assessments from the NVD JSON 2.0 yearly feeds.

Input:  data/external/nvd/nvdcve-2.0-<year>.json.gz (downloaded by src/fetch_nvd_feeds.py)
Output: data/nvd_records.parquet, one row per CVE in the feeds:
  cve, nvd_published, nvd_last_modified, nvd_status,
  nvd_v31            vector of the cvssMetricV31 entry whose source is nvd@nist.gov (type Primary), if any
  nvd_v40            vector of the cvssMetricV40 entry whose source is nvd@nist.gov (type Primary), if any
  secondary_v31      v3.1 vectors from sources other than the NVD (usually the CNA), joined by "|"
  v31_entries, v40_entries   all v3.1 / v4.0 entries as a JSON list of [source, type, vector] (used by rq2_pairing.py)
and data/nvd_records.meta.json (feeds used with their SHA-256, row counts).
"""

import gzip
import json
from pathlib import Path

import orjson
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
FEEDS = ROOT / "data" / "external" / "nvd"
OUT = ROOT / "data" / "nvd_records.parquet"
NVD_SOURCE = "nvd@nist.gov"


def vectors(metrics, key):
    own, other = None, []
    for m in metrics.get(key, []) or []:
        v = (m.get("cvssData") or {}).get("vectorString")
        if not v:
            continue
        if m.get("source") == NVD_SOURCE:
            if m.get("type") == "Primary":  # the NVD's primary assessment only; its Secondary entries are left out
                own = own or v
        else:
            other.append(v)
    return own, other


def entries(metrics, key):
    out = [[m.get("source"), m.get("type"), (m.get("cvssData") or {}).get("vectorString")]
           for m in metrics.get(key, []) or [] if (m.get("cvssData") or {}).get("vectorString")]
    return json.dumps(out) if out else None


def main():
    rows, used = [], {}
    manifest = json.loads((FEEDS / "download_manifest.json").read_text(encoding="utf-8"))
    for gz in sorted(FEEDS.glob("nvdcve-2.0-*.json.gz")):
        year = gz.name.split("-")[2].split(".")[0]
        used[year] = manifest.get(year, {}).get("sha256")
        with gzip.open(gz, "rb") as f:
            data = orjson.loads(f.read())
        for v in data.get("vulnerabilities", []):
            c = v.get("cve", {})
            metrics = c.get("metrics", {}) or {}
            v31, other31 = vectors(metrics, "cvssMetricV31")
            v40, _ = vectors(metrics, "cvssMetricV40")
            rows.append({"cve": c.get("id"), "nvd_published": c.get("published"),
                         "nvd_last_modified": c.get("lastModified"), "nvd_status": c.get("vulnStatus"),
                         "nvd_v31": v31, "nvd_v40": v40, "secondary_v31": "|".join(other31) or None,
                         "v31_entries": entries(metrics, "cvssMetricV31"), "v40_entries": entries(metrics, "cvssMetricV40")})
    df = pd.DataFrame(rows).drop_duplicates("cve").sort_values("cve").reset_index(drop=True)
    df.to_parquet(OUT, index=False)
    meta = {"feeds_sha256": used, "rows": len(df), "with_nvd_v31": int(df.nvd_v31.notna().sum()),
            "with_nvd_v40": int(df.nvd_v40.notna().sum()), "status_counts": df.nvd_status.value_counts().to_dict()}
    OUT.with_suffix(".meta.json").write_text(json.dumps(meta, indent=1), encoding="utf-8")
    print(json.dumps(meta, indent=1))


if __name__ == "__main__":
    main()
