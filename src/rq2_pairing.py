"""RQ2: does the source of the v3.1 vector change the measured accuracy of a v3.1 -> v4.0 conversion?

Vieira et al. (Internet of Things 39, 2026, 102038) evaluate a v3.x -> v4.0 conversion on the CVEs with official scores of
both versions in the NVD (their dataset D4, NVD snapshot of 2026-07-12) and do not state whose v3.x vector is paired with
each v4.0 vector. This script rebuilds D4 approximately from the NVD JSON 2.0 feeds (CVEs published by the NVD from
2023-11-01 to 2026-07-12 with at least one v3.1 and one v4.0 entry) and applies the same fixed conversion, rule R, with
  cross-source pairing  the NVD's own (Primary) v3.1 vector with the CNA's v4.0 vector,
  same-source pairing   the CNA's v3.1 vector with the same CNA's v4.0 vector,
  strict pairing        the same CVEs with both an NVD and a CNA v3.1 vector, so that only the source of the v3.1 vector changes.
The v4.0 label is the first v4.0 entry of the NVD record (in this period almost always the CNA's).
This measures how much the pairing changes the result; it does not reproduce Vieira et al.'s method.

Input: data/nvd_records.parquet (columns v31_entries, v40_entries; written by extract_nvd.py)
Output: results/rq2/pairing.json, results/rq2/pairing.md
"""

import collections
import json
import sys
from pathlib import Path

import pandas as pd
from cvss import CVSS4

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cvss_utils import SEVERITY_ORDER, base_vector, parse_vector, rule_convert  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "rq2"
START, END = "2023-11-01", "2026-07-12"
NVD, VULDB = "nvd@nist.gov", "cna@vuldb.com"
_band = {}


def band(vec):
    if vec not in _band:
        _band[vec] = CVSS4(vec).severity
    return _band[vec]


def convert(v31):
    p = parse_vector(v31, "3.1")
    return base_vector(rule_convert(p), "4.0") if p else None


def main():
    nvd = pd.read_parquet(ROOT / "data" / "nvd_records.parquet", columns=["cve", "nvd_published", "v31_entries", "v40_entries"])
    nvd = nvd[nvd.v31_entries.notna() & nvd.v40_entries.notna()]
    nvd = nvd[(nvd.nvd_published.str[:10] >= START) & (nvd.nvd_published.str[:10] <= END)]
    d4 = [{"v31": json.loads(a), "v40": json.loads(b)} for a, b in zip(nvd.v31_entries, nvd.v40_entries)]

    def evaluate(rows, pick_v31):
        c = collections.Counter()
        for r in rows:
            s40, v40 = r["v40"][0][0], r["v40"][0][2]
            p40 = parse_vector(v40, "4.0")
            v31 = pick_v31(r)
            cv = convert(v31) if v31 else None
            if not p40 or not cv:
                continue
            tb, pb = band(base_vector(p40, "4.0")), band(cv)
            c["n"] += 1
            c["band"] += pb == tb
            c["under"] += SEVERITY_ORDER[pb] < SEVERITY_ORDER[tb]
            c["exact"] += cv == base_vector(p40, "4.0")
            c["vuldb"] += s40 == VULDB
        return c

    by_src = lambda r: {s: v for s, _, v in r["v31"]}  # noqa: E731
    nvd_primary = lambda r: next((v for s, t, v in r["v31"] if s == NVD and t == "Primary"), None)  # noqa: E731
    nvd_v31 = lambda r: nvd_primary(r) if r["v40"][0][0] != NVD else None  # noqa: E731
    cna_v31 = lambda r: by_src(r).get(r["v40"][0][0])  # noqa: E731
    paired = [r for r in d4 if nvd_v31(r) and cna_v31(r)]
    settings = [
        ("cross-source: NVD v3.1 with CNA v4.0", d4, nvd_v31),
        ("same-source: CNA v3.1 with CNA v4.0", d4, cna_v31),
        ("same-source, without VulDB", [r for r in d4 if r["v40"][0][0] != VULDB], cna_v31),
        ("strict pairing: NVD v3.1", paired, nvd_v31),
        ("strict pairing: CNA v3.1", paired, cna_v31),
        ("strict pairing without VulDB: NVD v3.1", [r for r in paired if r["v40"][0][0] != VULDB], nvd_v31),
        ("strict pairing without VulDB: CNA v3.1", [r for r in paired if r["v40"][0][0] != VULDB], cna_v31),
    ]
    src = collections.Counter(r["v40"][0][0] for r in d4)
    out = {"d4_size": len(d4), "v4_sources_top5": {s: n for s, n in src.most_common(5)}, "settings": {}}
    for name, subset, pick in settings:
        c = evaluate(subset, pick)
        n = c["n"]
        out["settings"][name] = {"n": n, "vuldb_share": c["vuldb"] / n, "band_acc": c["band"] / n,
                                 "under_rate": c["under"] / n, "exact": c["exact"] / n}
    same = sum(parse_vector(nvd_v31(r), "3.1") == parse_vector(cna_v31(r), "3.1") for r in paired)
    out["strict_pairs_identical_v31"] = same / len(paired)

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "pairing.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
    lines = [f"# Pairing provenance (approximate D4: NVD publication {START} to {END}, both v3.1 and v4.0 entries; {len(d4):,} CVEs)\n",
             "Top sources of the v4.0 labels: " + "; ".join(f"{s} {n:,} ({n / len(d4):.1%})" for s, n in src.most_common(5)) + "\n",
             "| Setting | n | VulDB share | Rule-R band accuracy | Underestimation | Exact vector |", "|---|---|---|---|---|---|"]
    for name, r in out["settings"].items():
        lines.append(f"| {name} | {r['n']:,} | {r['vuldb_share']:.1%} | {r['band_acc']:.1%} | {r['under_rate']:.1%} | {r['exact']:.1%} |")
    lines.append(f"\nOn the {len(paired):,} strictly paired CVEs, the NVD's and the CNA's v3.1 vectors are identical for {same / len(paired):.1%}.")
    (OUT / "pairing.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
