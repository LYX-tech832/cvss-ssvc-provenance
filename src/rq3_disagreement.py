"""RQ3, disagreement test: when the CNA and the NVD disagree, which assessment does CISA's SSVC decision follow?

Sample:
  * records with a CISA SSVC decision, a CNA CVSS v3.x vector and an NVD primary CVSS v3.1 vector (source nvd@nist.gov);
  * the CNA container was not updated after the SSVC timestamp, so the CNA vector is the one CISA could see;
  * records where CISA added its own CVSS vector are excluded.
Comparison: among records where the CNA and NVD vectors imply different SSVC values (crossing lines as in
rq3_stale_copies.py), agreement of SSVC with the CNA-implied value minus agreement with the NVD-implied value; 95% percentile
bootstrap interval that resamples CNAs (record-level within a single CNA). The agreement is also reported for each
direction of the disagreement. Technical Impact and Automatable are reported separately,
overall and for the largest CNAs. Sensitivity: VulnCheck's published rules.
Caveats reported with the results: the NVD's assessment date is unknown, the NVD may have consulted CISA's ADP data,
and the NVD feeds (2026-10-26) are one month newer than the CVE List snapshot (2026-09-25).

Inputs: data/snapshot_records.parquet, data/nvd_records.parquet
Output: results/rq3/disagreement.json
"""

import json
from pathlib import Path

import pandas as pd

from rq3_stale_copies import (au_rule, compare, exploit, impacts, is_memcorr, parse, ti_rule, vc_au, vc_ti)

ROOT = Path(__file__).resolve().parents[1]
RES = ROOT / "results" / "rq3"


def main():
    rec = pd.read_parquet(ROOT / "data" / "snapshot_records.parquet")
    nvd = pd.read_parquet(ROOT / "data" / "nvd_records.parquet")
    df = rec.merge(nvd, on="cve", how="inner")
    ts = pd.to_datetime(df.ssvc_timestamp, utc=True, format="mixed")
    cu = pd.to_datetime(df.cna_date_updated, utc=True, format="mixed")
    base = df[ts.notna() & df.cna_v3.notna() & df.nvd_v31.notna() & (cu <= ts) & df.cisa_v3.isna()].copy()

    cna = [parse(v) for v in base.cna_v3]
    nv = [parse(v) for v in base.nvd_v31]
    mc = [is_memcorr(a, b) for a, b in zip(base.cwe_cna, base.cwe_adp)]
    base["cna_ti"] = [ti_rule(impacts(v)) for v in cna]
    base["nvd_ti"] = [ti_rule(impacts(v)) for v in nv]
    base["cna_au"] = [au_rule(exploit(v)) for v in cna]
    base["nvd_au"] = [au_rule(exploit(v)) for v in nv]
    base["cna_ti_vc"] = [vc_ti(impacts(v)) for v in cna]
    base["nvd_ti_vc"] = [vc_ti(impacts(v)) for v in nv]
    base["cna_au_vc"] = [vc_au(exploit(v), m) for v, m in zip(cna, mc)]
    base["nvd_au_vc"] = [vc_au(exploit(v), m) for v, m in zip(nv, mc)]
    same_vec = [a.split("/", 1)[1] == b.split("/", 1)[1] for a, b in zip(base.cna_v3, base.nvd_v31)]

    out = {"sample": int(len(base)), "identical_vectors": int(sum(same_vec)),
           "cisa_value_shares": {"technical_impact_partial": float((base.ssvc_technical_impact == "partial").mean()),
                                 "automatable_no": float((base.ssvc_automatable == "no").mean())},
           "main": {"technical_impact": compare(base, "cna_ti", "nvd_ti", "ssvc_technical_impact", "total"),
                    "automatable": compare(base, "cna_au", "nvd_au", "ssvc_automatable", "yes")},
           "sensitivity_vulncheck": {"technical_impact": compare(base, "cna_ti_vc", "nvd_ti_vc", "ssvc_technical_impact", "total"),
                                     "automatable": compare(base, "cna_au_vc", "nvd_au_vc", "ssvc_automatable", "yes")},
           "by_cna": {}}
    nv = base[base.cna != "VulDB"]
    out["without_vuldb"] = {"sample": int(len(nv)),
                            "technical_impact": compare(nv, "cna_ti", "nvd_ti", "ssvc_technical_impact", "total"),
                            "automatable": compare(nv, "cna_au", "nvd_au", "ssvc_automatable", "yes")}
    for outcome, a, b, y in (("technical_impact", "cna_ti", "nvd_ti", "ssvc_technical_impact"),
                             ("automatable", "cna_au", "nvd_au", "ssvc_automatable")):
        dis = base[base[a] != base[b]]
        for cna_name in dis.cna.value_counts().head(8).index:
            r = compare(dis[dis.cna == cna_name], a, b, y, None, cluster=None)
            out["by_cna"].setdefault(outcome, {})[cna_name] = {k: r[k] for k in ("n", "agree_seen", "agree_snapshot", "diff", "ci95")}
    # in the comparison helper, "seen" = CNA-implied value and "snapshot" = NVD-implied value
    out["note"] = "agree_seen = agreement with the CNA-implied value; agree_snapshot = agreement with the NVD-implied value"
    RES.mkdir(parents=True, exist_ok=True)
    (RES / "disagreement.json").write_text(json.dumps(out, indent=1, default=str), encoding="utf-8")
    print(json.dumps(out, indent=1, default=str))


if __name__ == "__main__":
    main()
