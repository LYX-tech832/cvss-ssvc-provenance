"""When did the NVD assess? The disagreement analysis and the tier changes split by the time of the NVD's assessment.

Sample: as in rq3_tiers.py (records with a CISA SSVC decision, a CNA CVSS v3.x vector and an NVD primary CVSS v3.1
vector, CNA container not updated after the SSVC timestamp, no CISA-added vector).

Time of the NVD's assessment: from data/nvd_cvss_history.parquet (fetch_nvd_history.py), the latest NVD event
(source nvd@nist.gov; Initial Analysis, Reanalysis or Modified Analysis) that added or changed the CVE's CVSS v3.1 vector.
  * matched: that event's vector equals the NVD vector in the feeds; its time is the time of the assessment;
  * before the history window: no such event since 1 June 2022 and the CVE was published before that date, so the
    NVD vector predates every SSVC decision in the sample;
  * unknown: the latest event's vector differs from the feeds, or a CVE published since 1 June 2022 has no event.
Event times are read as UTC.

Groups: NVD assessment before the SSVC decision ("NVD first") and after it ("NVD later"). For each group:
  * the disagreement analysis of rq3_disagreement.py (agreement of SSVC with the CNA-implied minus the NVD-implied value,
    interval resampling CNAs);
  * the tier changes of rq3_tiers.py (CISA's decisions vs. values from the NVD vector; CNA vector vs. NVD vector), for
    exposed and unexposed assets, with intervals resampling vendors.

Inputs: data/snapshot_records.parquet, data/nvd_records.parquet, data/nvd_cvss_history.parquet
Output: results/rq3/nvd_timing.json
"""

import json
from pathlib import Path

import numpy as np
import pandas as pd

from rq3_stale_copies import au_rule, compare, exploit, impacts, parse, ti_rule
from rq3_tiers import compare_tiers

ROOT = Path(__file__).resolve().parents[1]
RES = ROOT / "results" / "rq3"
WINDOW_START = pd.Timestamp("2022-06-01", tz="UTC")


def nvd_assessment_times(path):
    h = pd.read_parquet(path)
    h = h[(h.source == "nvd@nist.gov") & h.action.isin(["Added", "Changed"]) & h.new.notna()]
    # the value is "NIST AV:..." in most events and "AV:..." in some
    h = h.assign(time=pd.to_datetime(h.created, utc=True, format="mixed"),
                 vector=h.new.str.replace(r"^NIST\s+", "", regex=True).str.strip())
    h = h.sort_values("time").drop_duplicates("cve", keep="last")
    return h.set_index("cve")[["time", "vector", "event"]]


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
    d["nvd_au"], d["nvd_ti"] = [au_rule(exploit(v)) for v in nv], [ti_rule(impacts(v)) for v in nv]
    d["cna_au"], d["cna_ti"] = [au_rule(exploit(v)) for v in cna], [ti_rule(impacts(v)) for v in cna]

    times = nvd_assessment_times(ROOT / "data" / "nvd_cvss_history.parquet")
    d = d.join(times, on="cve")
    d["decision"] = pd.to_datetime(d.ssvc_timestamp, utc=True, format="mixed")
    published = pd.to_datetime(d.date_published, utc=True, format="mixed")
    feed_vector = d.nvd_v31.str.split("/", n=1).str[1]
    matched = d.vector.notna() & (d.vector == feed_vector)
    before_window = d.vector.isna() & (published < WINDOW_START)
    d["status"] = np.select([matched, before_window], ["matched", "before window"], "unknown")
    d["timing"] = np.select(
        [before_window, matched & (d.time < d.decision), matched & (d.time >= d.decision)],
        ["NVD first", "NVD first", "NVD later"], "unknown")
    lag_days = ((d.time - d.decision).dt.total_seconds() / 86400)[matched]

    out = {"sample": int(len(d)),
           "status": d.status.value_counts().to_dict(),
           "timing": d.timing.value_counts().to_dict(),
           "matched_event": d[matched].event.value_counts().to_dict(),
           "lag_days_nvd_minus_decision": {q: float(lag_days.quantile(p)) for q, p in
                                            (("p10", .1), ("p25", .25), ("median", .5), ("p75", .75), ("p90", .9))},
           "groups": {}}
    def analyses(g):
        return {
            "n": int(len(g)),
            "n_vuldb": int((g.cna == "VulDB").sum()),
            "disagreement": {"technical_impact": compare(g, "cna_ti", "nvd_ti", "ssvc_technical_impact", "total"),
                             "automatable": compare(g, "cna_au", "nvd_au", "ssvc_automatable", "yes")},
            "tiers": {("exposed" if e else "not exposed"): {
                "main_actual_vs_nvd": compare_tiers(g, "ssvc_automatable", "ssvc_technical_impact", "nvd_au", "nvd_ti", e),
                "decomposition_cna_vs_nvd": compare_tiers(g, "cna_au", "cna_ti", "nvd_au", "nvd_ti", e)}
                for e in (True, False)},
        }
    # VulDB's share differs between the groups, so each group is also reported without VulDB
    for name in ("NVD first", "NVD later"):
        g = d[d.timing == name]
        out["groups"][name] = analyses(g)
        out["groups"][name + ", without VulDB"] = analyses(g[g.cna != "VulDB"])
    RES.mkdir(parents=True, exist_ok=True)
    (RES / "nvd_timing.json").write_text(json.dumps(out, indent=1, default=str), encoding="utf-8")
    print(json.dumps({k: v for k, v in out.items() if k != "groups"}, indent=1, default=str))
    for name, g in out["groups"].items():
        print(name, g["n"], {k: round(v["diff"], 3) for k, v in g["disagreement"].items()},
              {k: round(v["main_actual_vs_nvd"]["changed"], 3) for k, v in g["tiers"].items()})


if __name__ == "__main__":
    main()
