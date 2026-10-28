"""RQ3: how much do the BOD 26-04 remediation tiers depend on which CVSS assessment the SSVC decisions follow?

Sample (as in rq3_disagreement.py): records with a CISA SSVC decision, a CNA CVSS v3.x vector and an NVD primary v3.1
vector, whose CNA container was not updated after the SSVC timestamp, and without a CISA-added CVSS vector.

Tier rule: Table 1 of BOD 26-04, from KEV membership, public exposure, Automatable and Technical Impact. Exposure is
unknown, so every estimate is computed twice, assuming all assets are exposed and assuming none is.

Main estimate: the share of records whose tier changes when Automatable and Technical
Impact are taken from the NVD vector (crossing-line rules: Technical Impact total iff C, I and A are all High;
Automatable yes iff AV:N, PR:N and UI:N) instead of CISA's actual decisions; split into faster and slower tiers.
Supplementary decomposition: the share whose tier differs between the CNA vector and the NVD vector under the same
rules, which isolates the change of assessor with the mapping held fixed.
Sensitivity: VulnCheck's published rules. Breakdowns: KEV vs. non-KEV, the 12 largest CNAs, all records without VulDB.
Intervals: cluster bootstrap over vendors (10,000 resamples, seed 20261026).

Inputs: data/snapshot_records.parquet, data/nvd_records.parquet
Output: results/rq3/tiers.json
"""

import json
from pathlib import Path

import numpy as np
import pandas as pd

from rq3_stale_copies import au_rule, exploit, impacts, is_memcorr, parse, ti_rule, vc_au, vc_ti

ROOT = Path(__file__).resolve().parents[1]
RES = ROOT / "results" / "rq3"
RANK = {"3 days + forensic triage": 0, "3 days": 1, "14 days": 2, "60 days": 3, "next upgrade": 4}


def tier(kev, exposed, automatable, total):
    if kev:
        if total and (exposed or automatable):
            return "3 days + forensic triage"
        if exposed and automatable:
            return "3 days"
        return "14 days"
    if exposed:
        if automatable and total:
            return "3 days"
        return "14 days" if (automatable or total) else "60 days"
    return "60 days" if automatable else "next upgrade"


def cluster_ci(changed, faster, slower, clusters, n_boot=10000, seed=20261026):
    """Percentile intervals of three shares, resampling vendor clusters."""
    df = pd.DataFrame({"c": clusters, "chg": changed, "fast": faster, "slow": slower})
    g = df.groupby("c").agg(n=("chg", "size"), chg=("chg", "sum"), fast=("fast", "sum"), slow=("slow", "sum"))
    arr = g[["n", "chg", "fast", "slow"]].to_numpy(dtype=float)
    rng = np.random.default_rng(seed)
    k = len(arr)
    stats = []
    for start in range(0, n_boot, 500):
        idx = rng.integers(0, k, size=(min(500, n_boot - start), k))
        s = arr[idx].sum(axis=1)
        stats.append(s[:, 1:] / s[:, :1])
    stats = np.vstack(stats)
    lo, hi = np.percentile(stats, [2.5, 97.5], axis=0)
    return [[float(a), float(b)] for a, b in zip(lo, hi)]


def compare_tiers(d, a_auto, a_total, b_auto, b_total, exposed):
    ta = [tier(k, exposed, x == "yes", y == "total") for k, x, y in zip(d.kev, d[a_auto], d[a_total])]
    tb = [tier(k, exposed, x == "yes", y == "total") for k, x, y in zip(d.kev, d[b_auto], d[b_total])]
    ra = np.array([RANK[t] for t in ta])
    rb = np.array([RANK[t] for t in tb])
    changed, faster, slower = (ra != rb), (rb < ra), (rb > ra)
    ci = cluster_ci(changed, faster, slower, d.cluster.to_numpy())
    trans = pd.crosstab(pd.Series(ta, name="from"), pd.Series(tb, name="to"))
    return {"n": int(len(d)), "changed": float(changed.mean()), "changed_ci95": ci[0],
            "faster": float(faster.mean()), "faster_ci95": ci[1], "slower": float(slower.mean()), "slower_ci95": ci[2],
            "transitions": {f"{i} -> {j}": int(trans.loc[i, j]) for i in trans.index for j in trans.columns
                            if i != j and trans.loc[i, j] > 0}}


def main():
    rec = pd.read_parquet(ROOT / "data" / "snapshot_records.parquet")
    nvd = pd.read_parquet(ROOT / "data" / "nvd_records.parquet")
    df = rec.merge(nvd, on="cve", how="inner")
    ts = pd.to_datetime(df.ssvc_timestamp, utc=True, format="mixed")
    cu = pd.to_datetime(df.cna_date_updated, utc=True, format="mixed")
    d = df[ts.notna() & df.cna_v3.notna() & df.nvd_v31.notna() & (cu <= ts) & df.cisa_v3.isna()].copy()
    d = d[d.ssvc_automatable.isin(["yes", "no"]) & d.ssvc_technical_impact.isin(["total", "partial"])]
    d["cluster"] = [v.strip().lower() if isinstance(v, str) and v.strip() else c for v, c in zip(d.vendor, d.cve)]

    cna = [parse(v) for v in d.cna_v3]
    nv = [parse(v) for v in d.nvd_v31]
    mc = [is_memcorr(a, b) for a, b in zip(d.cwe_cna, d.cwe_adp)]
    d["nvd_au"], d["nvd_ti"] = [au_rule(exploit(v)) for v in nv], [ti_rule(impacts(v)) for v in nv]
    d["cna_au"], d["cna_ti"] = [au_rule(exploit(v)) for v in cna], [ti_rule(impacts(v)) for v in cna]
    d["nvd_au_vc"] = [vc_au(exploit(v), m) for v, m in zip(nv, mc)]
    d["nvd_ti_vc"] = [vc_ti(impacts(v)) for v in nv]
    d["cna_au_vc"] = [vc_au(exploit(v), m) for v, m in zip(cna, mc)]
    d["cna_ti_vc"] = [vc_ti(impacts(v)) for v in cna]

    top = d.cna.value_counts().head(12).index.tolist()
    out = {"sample": int(len(d)), "kev": int(d.kev.sum()), "top_cnas": top, "scenarios": {}}
    for exposed in (True, False):
        sc = {}
        groups = [("all", d), ("non-KEV", d[~d.kev]), ("KEV", d[d.kev]), ("all without VulDB", d[d.cna != "VulDB"])]
        for name, g in groups:
            if len(g) == 0:
                continue
            sc[name] = {
                "main_actual_vs_nvd": compare_tiers(g, "ssvc_automatable", "ssvc_technical_impact", "nvd_au", "nvd_ti", exposed),
                "decomposition_cna_vs_nvd": compare_tiers(g, "cna_au", "cna_ti", "nvd_au", "nvd_ti", exposed),
                "sensitivity_vulncheck_actual_vs_nvd": compare_tiers(g, "ssvc_automatable", "ssvc_technical_impact", "nvd_au_vc", "nvd_ti_vc", exposed),
            }
        by_cna = {}
        for c in top:
            g = d[d.cna == c]
            r = compare_tiers(g, "ssvc_automatable", "ssvc_technical_impact", "nvd_au", "nvd_ti", exposed)
            by_cna[c] = {k: r[k] for k in ("n", "changed", "faster", "slower")}
        sc["by_cna_main"] = by_cna
        out["scenarios"]["exposed" if exposed else "not exposed"] = sc
    RES.mkdir(parents=True, exist_ok=True)
    (RES / "tiers.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
    print(json.dumps({k: v for k, v in out.items() if k != "scenarios"}, indent=1))


if __name__ == "__main__":
    main()
