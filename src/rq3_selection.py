"""RQ3, selection check: how do the stale-copy records differ from all records with a CISA SSVC decision?

Groups: all stale copies and the primary analysis set (CNA description unchanged), defined exactly as in
rq3_stale_copies.py, against all snapshot records with an SSVC decision. Compared: the share of the ten largest CNAs, the
year of the SSVC decision, the vulnerability type (CWE grouping of covariates.py) and the product type (covariates.py).
Shares are descriptive; no test is run. Also reported: how often the crossing-line rules of rq3_stale_copies.py reproduce
CISA's decisions on all records with an SSVC decision and a CNA CVSS vector, and the share of partial Technical Impact
decisions for VulDB's records and for those of the other CNAs.

Inputs: data/asof_versions.jsonl, data/snapshot_records.parquet
Output: results/rq3/selection.json
"""

import json
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from covariates import product_type, vuln_type  # noqa: E402
from rq3_stale_copies import au_rule, exploit, impacts, norm, pick, ti_rule  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def shares(s, top=None):
    v = s.value_counts(normalize=True)
    return {str(k): round(float(x), 4) for k, x in (v.head(top) if top else v).items()}


def main():
    rec = pd.read_parquet(ROOT / "data" / "snapshot_records.parquet")
    rec["vuln_type"] = [vuln_type(a, b) for a, b in zip(rec.cwe_cna, rec.cwe_adp)]
    rec["product_type"] = [product_type(a, b, c, d) for a, b, c, d in
                           zip(rec.cpe_parts, rec.collection_urls, rec.has_package_name, rec.cna_desc)]
    rec["ssvc_year"] = pd.to_datetime(rec.ssvc_timestamp, utc=True, format="mixed").dt.year
    rows = []
    for line in (ROOT / "data" / "asof_versions.jsonl").read_text(encoding="utf-8").splitlines():
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:  # a line cut off while the fetch was still writing
            continue
    av = pd.DataFrame(rows).drop_duplicates("cve", keep="last")
    df = av.merge(rec, on="cve", how="left", suffixes=("", "_snap"))
    ok = df[df.status == "ok"].copy()
    ok = ok[pd.to_datetime(ok.then_cna_date_updated, utc=True, format="mixed")
            <= pd.to_datetime(ok.ssvc_timestamp, utc=True, format="mixed")].copy()
    ok["seen_vec"] = [pick(a, b) for a, b in zip(ok.then_cna_v3, ok.then_cna_v4)]
    ok["final_vec"] = [pick(a, b) for a, b in zip(ok.cna_v3, ok.cna_v4)]
    ok = ok[[(s is None) or (f is None) or (("VC" in s) == ("VC" in f)) for s, f in zip(ok.seen_vec, ok.final_vec)]]
    stale = ok[ok.seen_vec.notna() & (ok.seen_vec != ok.final_vec)].copy()
    stale["desc_same"] = [norm(a) == norm(b) for a, b in zip(stale.then_cna_desc, stale.cna_desc)]
    groups = {"all SSVC records": rec[rec.ssvc_timestamp.notna()], "stale copies": stale,
              "stale copies, description unchanged": stale[stale.desc_same]}
    out = {name: {"n": int(len(g)), "cna_top10": shares(g.cna, 10), "ssvc_year": shares(g.ssvc_year.astype("Int64")),
                  "vulnerability_type_top10": shares(g.vuln_type, 10), "product_type": shares(g.product_type)}
           for name, g in groups.items()}
    d = rec[rec.ssvc_timestamp.notna() & (rec.cna_v3.notna() | rec.cna_v4.notna())]
    vec = [pick(a, b) for a, b in zip(d.cna_v3, d.cna_v4)]
    out["crossing_line_agreement"] = {
        "n": int(len(d)),
        "technical_impact": float(pd.Series([ti_rule(impacts(v)) for v in vec], index=d.index).eq(d.ssvc_technical_impact).mean()),
        "automatable": float(pd.Series([au_rule(exploit(v)) for v in vec], index=d.index).eq(d.ssvc_automatable).mean())}
    year = pd.to_datetime(rec.date_published, utc=True, format="mixed").dt.year
    out["cna_vector_share_of_ssvc_records_by_publication_year"] = {
        int(y): float((g.cna_v3.notna() | g.cna_v4.notna()).mean())
        for y, g in rec[rec.ssvc_timestamp.notna()].groupby(year[rec.ssvc_timestamp.notna()]) if y >= 2024}
    out["technical_impact_partial_share"] = {  # CISA decisions, records with an SSVC decision and a CNA vector
        "VulDB": float((d[d.cna == "VulDB"].ssvc_technical_impact == "partial").mean()),
        "other CNAs": float((d[d.cna != "VulDB"].ssvc_technical_impact == "partial").mean())}
    (ROOT / "results" / "rq3" / "selection.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
