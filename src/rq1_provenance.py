"""RQ1: how do CNAs implement CVSS v4.0? Dependence of each CNA's v4.0 vectors on its own v3.1 vectors, label types,
use of the values that v4.0 introduces, and quarterly agreement with rule R.

Measures (CNAs with at least 100 dual-scored CVEs)
  rule agreement  share of v4.0 vectors equal to rule R applied to the same CNA's v3.1 vector, and to three variants
                  (UI:R -> A; subsequent-system impacts always N; both)
  FD_in           in-sample functional dependence: share of v4.0 vectors equal to the most frequent v4.0 vector among the CNA's
                  CVEs with the same v3.1 vector (upper bound for any deterministic function of the v3.1 vector)
  FD_oos          out-of-sample functional dependence: the mapping "v3.1 vector -> most frequent v4.0 vector" is learned on the
                  CNA's earliest 70% of dual-scored CVEs (by publication date) and applied to the remaining 30%; v3.1 vectors not
                  seen in the first 70% are converted with rule R
  power           whether FD_oos reaches 0.90 when the CNA's v4.0 labels before 2026 are replaced by a deterministic
                  convention other than rule R (AC moved to AT, UI:R -> A, subsequent-system impacts N)
Typing (data before 2026 only, so that the type of a test CVE never depends on test-period labels)
  derived     at least 100 dual-scored CVEs and FD_oos >= 0.90 (0.80 and 0.95 reported as sensitivity)
  undetected  at least 100 dual-scored CVEs and FD_oos < 0.90
  v4_only     at least 100 v4.0 labels, of which fewer than 5% are dual-scored
  other       all remaining CNAs

Input: data/processed/cve_records.parquet
Output: results/rq1/source_types.json, results/rq1/provenance.json, results/rq1/provenance.md
"""

import json
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cvss_utils import M31, M40, rule_convert  # noqa: E402
from v4_labels import CUTOFF, collect_pairs, load  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "rq1"
THRESHOLD = 0.90
SENSITIVITY = [0.80, 0.90, 0.95]
MIN_PAIRS = 100
V4_SPECIFIC = ["AT", "UI", "SC", "SI", "SA"]


def variant(v31, ui_r="P", sub_from_scope=True):
    out = rule_convert(v31)
    if v31["UI"] == "R":
        out["UI"] = ui_r
    if not sub_from_scope:
        out.update({"SC": "N", "SI": "N", "SA": "N"})
    return out


RULES = {
    "rule_R": dict(ui_r="P", sub_from_scope=True),
    "UI:R->A": dict(ui_r="A", sub_from_scope=True),
    "subsequent_always_N": dict(ui_r="P", sub_from_scope=False),
    "UI:R->A_and_subsequent_always_N": dict(ui_r="A", sub_from_scope=False),
}


def alt_convention(d31):
    """A deterministic conversion that differs from rule R (used to check the power of the test)."""
    v = rule_convert(d31)
    v.update({"AC": "L", "AT": "P" if d31["AC"] == "H" else "N", "UI": "N" if d31["UI"] == "N" else "A",
              "SC": "N", "SI": "N", "SA": "N"})
    return tuple(v[k] for k in M40)


def wilson(k, n, z=1.96):
    if n == 0:
        return [float("nan"), float("nan")]
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [c - h, c + h]


def fd_oos(pairs):
    cut = int(0.7 * len(pairs))
    learn = defaultdict(Counter)
    for t31, _, t4, _ in pairs[:cut]:
        learn[t31][t4] += 1
    mapping = {k: c.most_common(1)[0][0] for k, c in learn.items()}
    test = pairs[cut:]
    hits = [mapping.get(t31, tuple(rule_convert(d31)[k] for k in M40)) == t4 for t31, d31, t4, _ in test]
    unseen = sum(t31 not in mapping for t31, _, _, _ in test)
    return {"fd_oos": sum(hits) / len(hits), "hits": int(sum(hits)), "n_test": len(test),
            "ci95": wilson(sum(hits), len(test)), "unseen_v31_share": unseen / len(test)}


def analyse(pairs):
    n = len(pairs)
    res = {"n_pairs": n}
    for name, kw in RULES.items():
        res[name] = sum(tuple(variant(d31, **kw)[k] for k in M40) == t4 for _, d31, t4, _ in pairs) / n
    groups = defaultdict(Counter)
    for t31, _, t4, _ in pairs:
        groups[t31][t4] += 1
    res["fd_in"] = sum(c.most_common(1)[0][1] for c in groups.values()) / n
    res["n_distinct_v31"] = len(groups)
    res.update({k: v for k, v in fd_oos(pairs).items()})
    return res


def main():
    df = load()
    n_v4 = df["source"].value_counts()
    pre = df[df["pub"] < CUTOFF]
    n_v4_pre = pre["source"].value_counts()
    pairs_all, pairs_pre = collect_pairs(df), collect_pairs(pre)

    # typing on data before 2026
    types, fd_pre = {}, {}
    for s, cnt in n_v4_pre.items():
        p = pairs_pre.get(s, [])
        if len(p) >= MIN_PAIRS:
            r = fd_oos(p)
            fd_pre[s] = r["fd_oos"]
            syn = [(t31, d31, alt_convention(d31), None) for t31, d31, _, _ in p]
            types[s] = {"type": "derived" if r["fd_oos"] >= THRESHOLD else "undetected",
                        "fd_oos_pre2026": r["fd_oos"], "fd_oos_pre2026_ci95": r["ci95"], "n_pairs_pre2026": len(p),
                        "power": bool(fd_oos(syn)["fd_oos"] >= THRESHOLD)}
        elif cnt >= MIN_PAIRS and len(p) / cnt < 0.05:
            types[s] = {"type": "v4_only", "n_v4_pre2026": int(cnt)}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "source_types.json").write_text(json.dumps(types, indent=1), encoding="utf-8")

    df["label_type"] = df["source"].map({s: v["type"] for s, v in types.items()}).fillna("other")
    rows = {s: analyse(p) | {"n_v4": int(n_v4[s]), **{k: v for k, v in types.get(s, {}).items() if k != "type"},
                             "type": types.get(s, {}).get("type", "other")}
            for s, p in pairs_all.items() if len(p) >= MIN_PAIRS}

    # agreement with rule R over all labels
    dual = df[df["has_v31"]]
    r_hit = int(sum(rule_convert({k: r["x31_" + k] for k in M31}) == {k: r["y_" + k] for k in M40} for _, r in dual.iterrows()))

    # use of the values that v4.0 introduces, by label type (and VulDB separately)
    usage = {}
    groups = {"VulDB": df["source"] == "VulDB"} | {t: df["label_type"] == t for t in ["derived", "undetected", "v4_only", "other"]}
    for name, m in groups.items():
        g = df[m]
        usage[name] = {"n": int(len(g)), "AT:P": int((g["y_AT"] == "P").sum()), "AT:P_share": float((g["y_AT"] == "P").mean()),
                       "UI:A": int((g["y_UI"] == "A").sum()), "UI:A_share": float((g["y_UI"] == "A").mean())}

    # quarterly agreement with rule R (CNAs with at least 500 dual-scored CVEs; quarters with at least 30)
    q = dual.copy()
    q["quarter"] = q["pub"].dt.tz_convert(None).dt.to_period("Q").astype(str)
    q["R"] = [rule_convert({k: r["x31_" + k] for k in M31}) == {k: r["y_" + k] for k in M40} for _, r in q.iterrows()]
    quarterly = {}
    for s in [s for s, p in pairs_all.items() if len(p) >= 500]:
        g = q[q["source"] == s].groupby("quarter")["R"].agg(["size", "mean"])
        g = g[g["size"] >= 30]
        quarterly[s] = {qq: {"n": int(n), "rule_R": float(m)} for qq, (n, m) in g.iterrows()}

    type_counts = df["label_type"].value_counts()
    out = {
        "n_v4_labels": int(len(df)), "n_cnas": int(df["source"].nunique()),
        "top_sources": {s: {"n": int(c), "share": float(c / len(df))} for s, c in n_v4.head(5).items()},
        "n_dual_scored": int(len(dual)),
        "rule_R_equal": {"n": r_hit, "share_of_all": r_hit / len(df), "share_of_dual_scored": r_hit / len(dual)},
        "label_type_counts": {t: {"n": int(type_counts.get(t, 0)), "share": float(type_counts.get(t, 0) / len(df))}
                              for t in ["derived", "undetected", "v4_only", "other"]},
        "threshold_sensitivity": {f"{th:.2f}": sorted(s for s, f in fd_pre.items() if f >= th) for th in SENSITIVITY},
        "per_cna": rows, "value_usage": usage, "quarterly_rule_R": quarterly,
    }
    (OUT / "provenance.json").write_text(json.dumps(out, indent=1), encoding="utf-8")

    lines = ["# RQ1: label provenance of CNA-provided CVSS v4.0 vectors\n",
             f"{out['n_v4_labels']:,} v4.0 labels from {out['n_cnas']} CNAs; {out['n_dual_scored']:,} dual-scored. "
             f"Equal to rule R: {r_hit:,} ({r_hit / len(df):.1%} of all labels, {r_hit / len(dual):.1%} of dual-scored).\n",
             "## CNAs with at least 100 dual-scored CVEs\n",
             "| CNA | v4.0 labels | Dual-scored | Rule R | UI:R->A | Subsequent N | Both | FD_in | FD_oos | FD_oos before 2026 | Power | Type |",
             "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for s, r in sorted(rows.items(), key=lambda x: -x[1]["n_v4"]):
        pre_fd = f"{r['fd_oos_pre2026']:.1%}" if "fd_oos_pre2026" in r else "-"
        power = ("yes" if r["power"] else "no") if "power" in r else "-"
        lines.append(f"| {s} | {r['n_v4']:,} | {r['n_pairs']:,} | " + " | ".join(f"{r[k]:.1%}" for k in RULES)
                     + f" | {r['fd_in']:.1%} | {r['fd_oos']:.1%} | {pre_fd} | {power} | {r['type']} |")
    lines.append("\n## Label types\n")
    for t, v in out["label_type_counts"].items():
        lines.append(f"- {t}: {v['n']:,} ({v['share']:.1%})")
    lines.append("\nThreshold sensitivity (CNAs typed as derived): "
                 + "; ".join(f">= {k}: {', '.join(v) or 'none'}" for k, v in out["threshold_sensitivity"].items()))
    lines.append("\n## Use of AT:P and UI:A\n")
    for name, u in usage.items():
        lines.append(f"- {name} (n={u['n']:,}): AT:P {u['AT:P']:,} ({u['AT:P_share']:.1%}), UI:A {u['UI:A']:,} ({u['UI:A_share']:.1%})")
    lines.append("\n## Quarterly agreement with rule R\n")
    for s, g in quarterly.items():
        lines.append(f"- {s}: " + ", ".join(f"{qq} {v['rule_R']:.1%} (n={v['n']})" for qq, v in g.items()))
    (OUT / "provenance.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
