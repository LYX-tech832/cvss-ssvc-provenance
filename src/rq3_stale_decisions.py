"""RQ3, descriptive: how long do SSVC decisions stay unchanged after the CNA changes a vector across a decision line?

Records: the stale-copy group of rq3_stale_copies.py (CISA's decision was made on an earlier version of the CNA container; the CNA
vector in the snapshot differs from the one CISA could see), with the same version check and the same crossing lines
(Technical Impact total iff C/I/A (VC/VI/VA) all High; Automatable yes iff AV:N, PR:N and UI:N).
For the records whose CNA change crosses at least one line, the script reports
  * how many still carry, on every crossed decision point, the value implied by the old vector;
  * the days between the CNA container's last update and the snapshot (2026-09-25), a lower bound on how long the decision has
    been stale.
By construction CISA has not re-decided these records after the CNA's change (a re-decision would carry a later timestamp and
would not be a candidate), so the shares describe stale decisions; they are not a rate at which corrections propagate.

Inputs: data/asof_versions.jsonl, data/snapshot_records.parquet
Output: results/rq3/stale_decisions.json
"""

import json
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rq3_stale_copies import au_rule, exploit, impacts, pick, ti_rule  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = pd.Timestamp("2026-09-25", tz="UTC")


def main():
    rec = pd.read_parquet(ROOT / "data" / "snapshot_records.parquet")
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
    same_ver = [(s is None) or (f is None) or (("VC" in s) == ("VC" in f)) for s, f in zip(ok.seen_vec, ok.final_vec)]
    ok = ok[same_ver]
    stale = ok[ok.seen_vec.notna() & (ok.seen_vec != ok.final_vec)].copy()
    for side in ("seen", "final"):
        stale[f"{side}_ti"] = [ti_rule(impacts(v)) for v in stale[f"{side}_vec"]]
        stale[f"{side}_au"] = [au_rule(exploit(v)) for v in stale[f"{side}_vec"]]
    ti_x = stale.seen_ti != stale.final_ti
    au_x = stale.seen_au != stale.final_au
    cross = stale[ti_x | au_x].copy()
    ti_x, au_x = ti_x[cross.index], au_x[cross.index]
    still_old = ((~ti_x) | (cross.ssvc_technical_impact == cross.seen_ti)) & ((~au_x) | (cross.ssvc_automatable == cross.seen_au))
    days = (SNAPSHOT - pd.to_datetime(cross.cna_date_updated, utc=True, format="mixed")).dt.days
    out = {"stale_copies": int(len(stale)), "crossing_a_line": int(len(cross)),
           "crossing_technical_impact": int(ti_x.sum()), "crossing_automatable": int(au_x.sum()),
           "still_old_value_on_all_crossed_points": int(still_old.sum()), "still_old_share": float(still_old.mean()),
           "days_since_cna_update": {"median": float(days.median()), "q25": float(days.quantile(0.25)),
                                     "q75": float(days.quantile(0.75)), "share_at_least_90": float((days >= 90).mean())},
           "days_since_cna_update_still_old": {"median": float(days[still_old].median())}}
    (ROOT / "results" / "rq3" / "stale_decisions.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
