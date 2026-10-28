"""RQ3: does CISA's SSVC decision follow the CNA's CVSS vector that CISA could see when it decided?

Natural experiment on records whose CNA container changed after CISA's SSVC decision.
  * a fetched copy (data/asof_versions.jsonl, written by fetch_asof_versions.py) counts as the copy CISA could see only
    if its CNA container was last updated no later than the SSVC timestamp;
  * stale-copy group: the CNA had a CVSS vector in that copy and the snapshot's CNA vector differs; primary analysis =
    records whose CNA description is unchanged between the two versions; all stale copies = secondary analysis;
  * CISA-own group: the CNA had no CVSS vector in that copy; reported separately and never pooled;
  * crossing lines: Technical Impact total iff C/I/A (VC/VI/VA) are all High; Automatable yes iff AV:N, PR:N and UI:N;
  * sensitivity 1: a data-driven mapping (majority SSVC value per C/I/A or AV/AC/PR/UI tuple), estimated per SSVC year
    on SSVC records whose CNA container was not updated after the decision, so the analysed records are not reused; a
    tuple not seen in that year falls back to the mapping pooled over all years;
  * sensitivity 2: VulnCheck's published rules ("Automating SSVC", 2025-02-13): Technical Impact total if
    confidentiality and integrity are both High; Automatable yes if AV:N, AC:L, PR:N, UI:N and the vulnerability is not
    memory corruption (CWE-119, 120, 121, 122, 125, 131, 190, 415, 416, 476, 787 in the CNA or ADP CWE fields);
  * sensitivity 3 (timing): only records whose first commit carrying the decision is at most 2 hours after the SSVC
    timestamp (the repository is updated about hourly), so the order follows from the git history alone;
  * statistic: among records where the two versions imply different SSVC values, agreement of SSVC with the seen
    version minus agreement with the snapshot version; 95% percentile bootstrap interval (10,000 resamples, seed
    20261026).
All analyses are repeated without the records whose CNA container was written by VulDB.

Inputs: data/asof_versions.jsonl, data/snapshot_records.parquet
Output: results/rq3/stale_copies.json
"""

import json
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
RES = ROOT / "results" / "rq3"
RNG = np.random.default_rng(20261026)


def parse(v):
    return dict(p.split(":") for p in v.split("/")[1:]) if isinstance(v, str) else None


def impacts(d):
    if d is None:
        return None
    keys = ("VC", "VI", "VA") if "VC" in d else ("C", "I", "A")
    return tuple(d.get(k) for k in keys)


def exploit(d):
    return None if d is None else tuple(d.get(k) for k in ("AV", "AC", "PR", "UI"))


def ti_rule(imp):
    return None if imp is None else ("total" if all(x == "H" for x in imp) else "partial")


def au_rule(ex):
    return None if ex is None else ("yes" if ex[0] == "N" and ex[2] == "N" and ex[3] == "N" else "no")


MEMORY_CORRUPTION = {f"CWE-{n}" for n in (119, 120, 121, 122, 125, 131, 190, 415, 416, 476, 787)}


def vc_ti(imp):
    return None if imp is None else ("total" if imp[0] == "H" and imp[1] == "H" else "partial")


def vc_au(ex, memcorr):
    if ex is None:
        return None
    return "yes" if ex == ("N", "L", "N", "N") and not memcorr else "no"


def is_memcorr(cwe_cna, cwe_adp):
    ids = set()
    for field in (cwe_cna, cwe_adp):
        if isinstance(field, str):
            ids.update(field.split("|"))
    return bool(ids & MEMORY_CORRUPTION)


def pick(v3, v4):
    """Vector used for comparison: v3.x when present, else v4.0."""
    return parse(v3) if isinstance(v3, str) else parse(v4)


def norm(s):
    return " ".join(s.split()) if isinstance(s, str) else None


def boot_diff(agree_seen, agree_final, n=10000):
    a, b = np.asarray(agree_seen, float), np.asarray(agree_final, float)
    if len(a) == 0:
        return None, (None, None)
    idx = RNG.integers(0, len(a), size=(n, len(a)))
    d = a[idx].mean(1) - b[idx].mean(1)
    return float(a.mean() - b.mean()), (float(np.percentile(d, 2.5)), float(np.percentile(d, 97.5)))


def compare(df, seen_col, final_col, ssvc_col, positive):
    """Agreement of SSVC with the value implied by the seen vs the snapshot version, where the two differ."""
    x = df[df[seen_col].notna() & df[final_col].notna() & (df[seen_col] != df[final_col])]
    agree_seen = (x[seen_col] == x[ssvc_col]).astype(int)
    agree_final = (x[final_col] == x[ssvc_col]).astype(int)
    diff, (lo, hi) = boot_diff(agree_seen, agree_final)
    return {"n": int(len(x)), "agree_seen": float(agree_seen.mean()) if len(x) else None,
            "agree_snapshot": float(agree_final.mean()) if len(x) else None,
            "diff": diff, "ci95": [lo, hi]}


def majority_map(records, key_fn, ssvc_col):
    """Majority SSVC value per key, estimated per SSVC year; returns {year: {key: value}} and the pooled map under None."""
    t = pd.DataFrame({"k": records.apply(key_fn, axis=1), "y": records[ssvc_col],
                      "year": pd.to_datetime(records.ssvc_timestamp, utc=True, format="mixed").dt.year}).dropna()
    maps = {None: t.groupby("k").y.agg(lambda s: s.value_counts().idxmax()).to_dict()}
    for year, g in t.groupby("year"):
        maps[int(year)] = g.groupby("k").y.agg(lambda s: s.value_counts().idxmax()).to_dict()
    return maps


def lookup(maps, year, key):
    return maps.get(year, {}).get(key, maps[None].get(key))


def main():
    RES.mkdir(parents=True, exist_ok=True)
    rec = pd.read_parquet(ROOT / "data" / "snapshot_records.parquet")
    rows = []
    for line in (ROOT / "data" / "asof_versions.jsonl").read_text(encoding="utf-8").splitlines():
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:  # a line cut off while the fetch was still writing
            continue
    av = pd.DataFrame(rows).drop_duplicates("cve", keep="last")
    df = av.merge(rec, on="cve", how="left", suffixes=("", "_snap"))
    status = df.status.value_counts().to_dict()

    ok = df[df.status == "ok"].copy()
    ok["seen_valid"] = (pd.to_datetime(ok.then_cna_date_updated, utc=True, format="mixed")
                        <= pd.to_datetime(ok.ssvc_timestamp, utc=True, format="mixed"))
    valid = ok[ok.seen_valid].copy()

    valid["seen_vec"] = [pick(a, b) for a, b in zip(valid.then_cna_v3, valid.then_cna_v4)]
    valid["final_vec"] = [pick(a, b) for a, b in zip(valid.cna_v3, valid.cna_v4)]
    # compare like with like: both versions v3.x, or both v4.0
    same_ver = [(s is None) or (f is None) or (("VC" in s) == ("VC" in f)) for s, f in zip(valid.seen_vec, valid.final_vec)]
    valid = valid[same_ver].copy()
    for side in ("seen", "final"):
        valid[f"{side}_ti"] = [ti_rule(impacts(v)) for v in valid[f"{side}_vec"]]
        valid[f"{side}_au"] = [au_rule(exploit(v)) for v in valid[f"{side}_vec"]]
    valid["desc_same"] = [norm(a) == norm(b) for a, b in zip(valid.then_cna_desc, valid.cna_desc)]

    own = valid[valid.seen_vec.isna()]                      # CISA-own group (CNA had no CVSS when CISA decided)
    stale = valid[valid.seen_vec.notna() & (valid.seen_vec != valid.final_vec)]
    main_set = stale[stale.desc_same]

    out = {"fetch_status": status, "ok": int(len(ok)), "seen_valid": int(ok.seen_valid.sum()),
           "used_after_version_check": int(len(valid)), "cisa_own_group": int(len(own)),
           "stale_copy_group": int(len(stale)), "stale_copy_desc_unchanged": int(len(main_set))}

    # main and supplementary analyses on the crossing lines
    for name, data in (("main_desc_unchanged", main_set), ("all_stale", stale)):
        out[name] = {
            "technical_impact": compare(data, "seen_ti", "final_ti", "ssvc_technical_impact", "total"),
            "automatable": compare(data, "seen_au", "final_au", "ssvc_automatable", "yes"),
        }

    # sensitivity: data-driven mappings estimated on non-candidate SSVC records
    ts = pd.to_datetime(rec.ssvc_timestamp, utc=True, format="mixed")
    cu = pd.to_datetime(rec.cna_date_updated, utc=True, format="mixed")
    ref = rec[ts.notna() & (cu <= ts) & rec.cna_v3.notna()]
    ti_map = majority_map(ref, lambda r: impacts(parse(r.cna_v3)), "ssvc_technical_impact")
    au_map = majority_map(ref, lambda r: exploit(parse(r.cna_v3)), "ssvc_automatable")
    s3 = stale[[("VC" not in s) for s in stale.seen_vec]].copy()  # mapping estimated on v3.x vectors
    yr = pd.to_datetime(s3.ssvc_timestamp, utc=True, format="mixed").dt.year.astype(int).tolist()
    s3["seen_ti_map"] = [lookup(ti_map, y, impacts(v)) for y, v in zip(yr, s3.seen_vec)]
    s3["final_ti_map"] = [lookup(ti_map, y, impacts(v)) for y, v in zip(yr, s3.final_vec)]
    s3["seen_au_map"] = [lookup(au_map, y, exploit(v)) for y, v in zip(yr, s3.seen_vec)]
    s3["final_au_map"] = [lookup(au_map, y, exploit(v)) for y, v in zip(yr, s3.final_vec)]
    for name, data in (("sensitivity_map_desc_unchanged", s3[s3.desc_same]), ("sensitivity_map_all", s3)):
        out[name] = {
            "technical_impact": compare(data, "seen_ti_map", "final_ti_map", "ssvc_technical_impact", "total"),
            "automatable": compare(data, "seen_au_map", "final_au_map", "ssvc_automatable", "yes"),
        }

    # sensitivity: VulnCheck's published rules
    vc = stale.copy()
    mc = [is_memcorr(a, b) for a, b in zip(vc.cwe_cna, vc.cwe_adp)]
    for side in ("seen", "final"):
        vc[f"{side}_ti_vc"] = [vc_ti(impacts(v)) for v in vc[f"{side}_vec"]]
        vc[f"{side}_au_vc"] = [vc_au(exploit(v), m) for v, m in zip(vc[f"{side}_vec"], mc)]
    for name, data in (("sensitivity_vulncheck_desc_unchanged", vc[vc.desc_same]), ("sensitivity_vulncheck_all", vc)):
        out[name] = {
            "technical_impact": compare(data, "seen_ti_vc", "final_ti_vc", "ssvc_technical_impact", "total"),
            "automatable": compare(data, "seen_au_vc", "final_au_vc", "ssvc_automatable", "yes"),
        }

    # sensitivity: order established by git history alone (first commit with the decision within 2 hours)
    lag_h = (pd.to_datetime(stale.commit_date, utc=True, format="mixed")
             - pd.to_datetime(stale.ssvc_timestamp, utc=True, format="mixed")).dt.total_seconds() / 3600
    quick = stale[(lag_h >= 0) & (lag_h <= 2)]
    out["timing_le_2h_n"] = int(len(quick))
    for name, data in (("sensitivity_commit_le_2h_desc_unchanged", quick[quick.desc_same]), ("sensitivity_commit_le_2h_all", quick)):
        out[name] = {
            "technical_impact": compare(data, "seen_ti", "final_ti", "ssvc_technical_impact", "total"),
            "automatable": compare(data, "seen_au", "final_au", "ssvc_automatable", "yes"),
        }

    # robustness to the largest source: all analyses above without records whose CNA container was written by VulDB
    nv = stale[stale.cna != "VulDB"]
    out["stale_copy_without_vuldb"] = int(len(nv))
    for name, data in (("main_desc_unchanged_without_vuldb", nv[nv.desc_same]), ("all_stale_without_vuldb", nv)):
        out[name] = {
            "technical_impact": compare(data, "seen_ti", "final_ti", "ssvc_technical_impact", "total"),
            "automatable": compare(data, "seen_au", "final_au", "ssvc_automatable", "yes"),
        }

    # side evidence: CISA-own group, SSVC vs CISA's own vector and vs the CNA's later vector
    own = own.copy()
    own["cisa_vec"] = [parse(v) for v in own.then_cisa_v3]
    own["cisa_ti"] = [ti_rule(impacts(v)) for v in own.cisa_vec]
    own["cisa_au"] = [au_rule(exploit(v)) for v in own.cisa_vec]
    out["cisa_own_side_evidence"] = {
        "technical_impact": compare(own, "cisa_ti", "final_ti", "ssvc_technical_impact", "total"),
        "automatable": compare(own, "cisa_au", "final_au", "ssvc_automatable", "yes"),
    }

    # who is in the stale-copy group vs all SSVC records (selection bias check)
    allssvc = rec[ts.notna()]
    out["selection"] = {
        "stale_top_cnas": stale.cna.value_counts(normalize=True).head(10).round(3).to_dict(),
        "all_ssvc_top_cnas": allssvc.cna.value_counts(normalize=True).head(10).round(3).to_dict(),
        "stale_ssvc_year": pd.to_datetime(stale.ssvc_timestamp, utc=True, format="mixed").dt.year.value_counts(normalize=True).sort_index().round(3).to_dict(),
        "all_ssvc_year": ts[ts.notna()].dt.year.value_counts(normalize=True).sort_index().round(3).to_dict(),
    }

    (RES / "stale_copies.json").write_text(json.dumps(out, indent=1, default=str), encoding="utf-8")
    print(json.dumps(out, indent=1, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()
