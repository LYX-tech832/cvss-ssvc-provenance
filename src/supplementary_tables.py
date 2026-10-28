"""Tables of the supplementary material, written as LaTeX from the result files (no number is typed by hand).

Inputs: results/rq1/*.json, results/rq2/*.json, results/rq3/*.json
Output: paper/supplementary_tables.tex (included by paper/supplementary.tex)
"""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RES = ROOT / "results"
OUT = ROOT / "paper" / "supplementary_tables.tex"
NAMES = {"GitHub_M": "GitHub", "@huntrdev": "huntr", "icscert": "ICS-CERT", "mitre": "MITRE", "cisco": "Cisco", "ibm": "IBM",
         "zdi": "ZDI", "talos": "Talos", "oracle": "Oracle", "dell": "Dell", "fortinet": "Fortinet", "redhat": "Red Hat", "v4_only": "v4-only",
         "non_derived": "non-derived"}


def load(path):
    return json.loads((RES / path).read_text(encoding="utf-8"))


def esc(s):
    s = NAMES.get(s, s)
    return s.replace("\\", "").replace("_", r"\_").replace("&", r"\&").replace("%", r"\%").replace("#", r"\#")


def pct(x, d=1):
    return f"{100 * x:.{d}f}"


def ci(x, scale=100, d=1):
    return f"[{scale * x[0]:.{d}f}, {scale * x[1]:.{d}f}]"


def num(x, d=3):
    return f"{x:.{d}f}".replace("-", "$-$")


def table(label, caption, colspec, header, rows, size=r"\footnotesize"):
    lines = [r"\begin{table}[htbp]", r"\centering", rf"\caption{{{caption}}}", rf"\label{{{label}}}", size,
             rf"\begin{{tabular}}{{{colspec}}}", r"\toprule", header + r" \\", r"\midrule"]
    lines += [r + r" \\" if not r.startswith("\\") else r for r in rows]
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}", ""]
    return "\n".join(lines)


def t_provenance():
    p = load("rq1/provenance.json")
    rows = []
    for c, r in sorted(p["per_cna"].items(), key=lambda kv: -kv[1]["n_v4"]):
        pre = f"{pct(r['fd_oos_pre2026'])} {ci(r['fd_oos_pre2026_ci95'])}" if "fd_oos_pre2026" in r else "--"
        power = ("yes" if r["power"] else "no") if "power" in r else "--"
        rows.append(f"{esc(c)} & {r['n_v4']:,} & {r['n_pairs']:,} & {r['n_distinct_v31']} & {pct(r['rule_R'])} & {pct(r['UI:R->A'])} & "
                    f"{pct(r['subsequent_always_N'])} & {pct(r['UI:R->A_and_subsequent_always_N'])} & {pct(r['fd_in'])} & {pct(r['fd_oos'])} & "
                    f"{pct(r['unseen_v31_share'])} & {pre} & {power} & {r['type']}")
    return table("tab:s-provenance",
                 "Label provenance of all CNAs with at least 100 dual-scored CVEs (all data unless stated; shares in \\%). Rule~R and its "
                 "three variants: share of v4.0 vectors equal to the rule applied to the same CNA's v3.1 vector (UI:R$\\to$A; "
                 "subsequent-system impacts always None; both). FD$_\\mathrm{in}$: in-sample functional dependence. FD$_\\mathrm{oos}$: "
                 "out-of-sample functional dependence; Unseen: share of the test segment whose v3.1 vector does not occur in the first 70\\% "
                 "(converted with rule~R). Before 2026: FD$_\\mathrm{oos}$ on CVEs published before 2026 with its Wilson 95\\% interval, "
                 "used for typing. CNAs without a value before 2026 reach 100 dual-scored CVEs only with 2026 data and are typed as other.",
                 "lrrrrrrrrrrlll", r"CNA & v4.0 & Dual & Distinct v3.1 & R & UI:A & Sub.\,N & Both & FD$_\mathrm{in}$ & FD$_\mathrm{oos}$ & Unseen & Before 2026 & Power & Type",
                 rows, size=r"\scriptsize\setlength{\tabcolsep}{2.2pt}")


def t_usage():
    p = load("rq1/provenance.json")
    u, c = p["value_usage"], p["label_type_counts"]
    total = sum(v["n"] for v in c.values())
    assert u["derived"] == u["VulDB"], "derived labels are no longer exactly the VulDB labels"
    rows = []
    for t, v in c.items():
        name = "derived (VulDB)" if t == "derived" else esc(t)
        rows.append(f"{name} & {v['n']:,} & {pct(v['share'])} & {u[t]['AT:P']:,} & {pct(u[t]['AT:P_share'])} & "
                    f"{u[t]['UI:A']:,} & {pct(u[t]['UI:A_share'])}")
    return table("tab:s-usage", f"Use of the two values that CVSS v4.0 introduces and rule~R cannot produce, by label type, among the "
                 f"{total:,} CNA-provided v4.0 labels. Share: the label type's share of all labels (\\%).",
                 "lrrrrrr", r"Label type & $n$ & Share & AT:Present & \% & UI:Active & \%", rows)


def t_nvd():
    a = load("rq1/nvd_agreement.json")
    items = ["AV", "AC", "PR", "UI", "C", "I", "A"]
    rows = [r"\multicolumn{12}{l}{\emph{A. CNA v4.0 label against the NVD's v3.1 vector}} \\"]
    for g, r in a["A_v4_label_vs_nvd"].items():
        rows.append(f"{esc(g)} & v4.0 & {r['n']:,} & " + " & ".join(pct(r['items'][k]) for k in items)
                    + f" & {pct(r['all_7_equal'])} & {pct(r['same_band'])}")
    rows.append(r"\addlinespace")
    rows.append(r"\multicolumn{12}{l}{\emph{B. Dual-scored CVEs: the CNA's v3.1 and v4.0 vectors against the NVD's v3.1 vector}} \\")
    for g, r in a["B_same_cves"].items():
        if g == "n":
            continue
        for comp, lab in (("cna_v31_vs_nvd", "v3.1"), ("cna_v40_vs_nvd", "v4.0")):
            x = r[comp]
            rows.append(f"{esc(g) if lab == 'v3.1' else ''} & {lab} & {x['n']:,} & " + " & ".join(pct(x['items'][k]) for k in items)
                        + f" & {pct(x['all_7_equal'])} & {pct(x['same_band'])}")
    return table("tab:s-nvd", "Agreement of CNA assessments with the NVD's own (Primary) v3.1 vector on seven items that both versions "
                 "share (\\%): AV, AC, PR; whether user interaction is required; confidentiality, integrity and availability impact (for "
                 "v4.0 the larger of the vulnerable-system and subsequent-system values). Same band: the CNA's band (v3.1 rating or "
                 "CVSS-B rating of the v4.0 vector) equals the NVD's v3.1 rating. Non-derived: all CNAs not typed as derived.",
                 "llrrrrrrrrrr", r"CNAs & CNA vector & $n$ & AV & AC & PR & UI & C & I & A & All 7 & Same band", rows,
                 size=r"\footnotesize\setlength{\tabcolsep}{4pt}")


def t_rq1():
    s = load("rq3/stale_copies.json")
    d = load("rq3/disagreement.json")
    spec = [("Stale copies, description unchanged", "main_desc_unchanged"), ("Stale copies, all", "all_stale"),
            ("Data-driven mapping, unchanged", "sensitivity_map_desc_unchanged"), ("Data-driven mapping, all", "sensitivity_map_all"),
            ("VulnCheck rules, unchanged", "sensitivity_vulncheck_desc_unchanged"), ("VulnCheck rules, all", "sensitivity_vulncheck_all"),
            ("Commit within 2 h, unchanged", "sensitivity_commit_le_2h_desc_unchanged"), ("Commit within 2 h, all", "sensitivity_commit_le_2h_all"),
            ("Without VulDB, unchanged", "main_desc_unchanged_without_vuldb"), ("Without VulDB, all", "all_stale_without_vuldb"),
            ("CISA-own group", "cisa_own_side_evidence")]
    rows = []

    def cells(x):
        return f"{x['n']:,} & {pct(x['agree_seen'])} & {pct(x['agree_snapshot'])} & {pct(x['diff'])} {ci(x['ci95'])}"
    for name, key in spec:
        rows.append(f"{name} & {cells(s[key]['technical_impact'])} & {cells(s[key]['automatable'])}")
    rows.append(r"\addlinespace")
    for name, key in (("CNA vs NVD, crossing lines", "main"), ("CNA vs NVD, VulnCheck rules", "sensitivity_vulncheck"),
                      ("CNA vs NVD, without VulDB", "without_vuldb")):
        rows.append(f"{name} & {cells(d[key]['technical_impact'])} & {cells(d[key]['automatable'])}")

    def dcells(x, value):
        v = next(r for k, r in x["by_direction"].items() if k.startswith(f"seen {value},"))
        return f"{v['n']:,} & {pct(v['agree_seen'])} & {pct(v['agree_snapshot'])} & {pct(v['agree_seen'] - v['agree_snapshot'])}"
    rows.append(r"\addlinespace")
    rows.append(r"\multicolumn{9}{l}{\emph{By direction: A implies partial / no (CISA's more frequent values) or total / yes}} \\")
    for name, x in (("Stale copies, unchanged", s["main_desc_unchanged"]), ("Stale copies, all", s["all_stale"]),
                    ("CISA-own group", s["cisa_own_side_evidence"]), ("CNA vs NVD", d["main"]),
                    ("CNA vs NVD, without VulDB", d["without_vuldb"])):
        rows.append(f"{name}: A partial / no & {dcells(x['technical_impact'], 'partial')} & {dcells(x['automatable'], 'no')}")
        rows.append(f"{name}: A total / yes & {dcells(x['technical_impact'], 'total')} & {dcells(x['automatable'], 'yes')}")

    rows.append(r"\addlinespace")
    rows.append(r"\multicolumn{9}{l}{\emph{Stale copies, unchanged, without one of the five CNAs with the most records}} \\")
    loo = s["main_desc_unchanged_leave_one_cna_out"]
    n_all = {k: s["main_desc_unchanged"][k]["n"] for k in ("technical_impact", "automatable")}

    def lcells(k, cna):
        r = loo[k].get(cna)
        return f"{n_all[k] - r['n_removed']:,} & & & {pct(r['diff'])}" if r else "& & &"
    for cna in dict.fromkeys(list(loo["technical_impact"]) + list(loo["automatable"])):
        rows.append(f"Without {esc(cna)} & {lcells('technical_impact', cna)} & {lcells('automatable', cna)}")
    shares = d["cisa_value_shares"]
    return table("tab:s-rq1", "All analyses of RQ1. ``Unchanged'': records whose CNA description is unchanged; ``all'': all stale "
                 "copies. A and B as in the corresponding table of the paper (stale copies: CNA vector at decision time and later; "
                 "CISA-own group: CISA's vector and the CNA's later vector; CNA vs NVD: the CNA's and the NVD's vector). Shares and "
                 "differences in \\%, with 95\\% bootstrap intervals that resample CNAs. In the CNA vs NVD sample, CISA's Technical "
                 f"Impact is partial for {pct(shares['technical_impact_partial'])}\\% of the records and Automatable is no for "
                 f"{pct(shares['automatable_no'])}\\%.",
                 "lrrrlrrrl", r" & \multicolumn{4}{c}{Technical Impact} & \multicolumn{4}{c}{Automatable} \\ \cmidrule(lr){2-5}\cmidrule(lr){6-9}"
                 r"Analysis & $n$ & A & B & A$-$B & $n$ & A & B & A$-$B", rows, size=r"\scriptsize\setlength{\tabcolsep}{3pt}")


def t_selection():
    s = load("rq3/selection.json")
    groups = ["all SSVC records", "stale copies", "stale copies, description unchanged"]
    rows = [f"Records & " + " & ".join(f"{s[g]['n']:,}" for g in groups)]
    for block, key in (("CNA (ten largest among all SSVC records)", "cna_top10"), ("Year of the SSVC decision", "ssvc_year"),
                       ("Vulnerability type (CWE)", "vulnerability_type_top10"), ("Product type", "product_type")):
        rows.append(r"\addlinespace")
        rows.append(rf"\multicolumn{{4}}{{l}}{{\emph{{{block}}}}} \\")
        if key == "ssvc_year":
            early = "2023 or earlier"
            merged = {g: {early: sum(v for y, v in s[g][key].items() if int(y) <= 2023),
                          **{y: v for y, v in s[g][key].items() if int(y) > 2023}} for g in groups}
            for k in [early] + sorted(y for y in merged[groups[0]] if y != early):
                rows.append(f"{k} & " + " & ".join(pct(merged[g].get(k, 0.0)) for g in groups))
            continue
        keys = list(s[groups[0]][key].keys())
        for k in keys:
            rows.append(f"{esc(k)} & " + " & ".join(pct(s[g][key].get(k, 0.0)) for g in groups))
    return table("tab:s-selection", "Composition of the stale copies and of all records with an SSVC decision (\\% of each group). Shares "
                 "are descriptive. Vulnerability type: the first of the 25 most frequent CWE identifiers in the record, ``other CWE'' for "
                 "the rest and ``unknown'' without CWE; product type from CPE parts, package sources and the description.",
                 "lrrr", r"Category & All SSVC records & Stale copies & Description unchanged", rows)


def t_tiers():
    t = load("rq3/tiers.json")
    rows = []
    cnas = list(t["scenarios"]["exposed"]["by_cna_main"].keys())
    for c in sorted(cnas, key=lambda c: -t["scenarios"]["exposed"]["by_cna_main"][c]["changed"]):
        e, n = t["scenarios"]["exposed"]["by_cna_main"][c], t["scenarios"]["not exposed"]["by_cna_main"][c]
        rows.append(f"{esc(c)} & {e['n']:,} & {pct(e['changed'])} & {pct(e['faster'])} & {pct(e['slower'])} & "
                    f"{pct(n['changed'])} & {pct(n['faster'])} & {pct(n['slower'])}")
    rows.append(r"\addlinespace")
    rows.append(r"\multicolumn{8}{l}{\emph{Sensitivity analysis: VulnCheck's rules in place of the crossing lines, all CNAs}} \\")
    for g, gn in (("all", "All"), ("non-KEV", "Not in KEV"), ("KEV", "In KEV"), ("all without VulDB", "Without VulDB")):
        e = t["scenarios"]["exposed"][g]["sensitivity_vulncheck_actual_vs_nvd"]
        n = t["scenarios"]["not exposed"][g]["sensitivity_vulncheck_actual_vs_nvd"]
        rows.append(f"{gn} & {e['n']:,} & {pct(e['changed'])} & {pct(e['faster'])} & {pct(e['slower'])} & "
                    f"{pct(n['changed'])} & {pct(n['faster'])} & {pct(n['slower'])}")
    return table("tab:s-tiers", "BOD 26-04 tier changes (\\%) when Automatable and Technical Impact are derived from the NVD's vector "
                 "instead of being taken from CISA's decision: for the twelve CNAs with the most records (crossing lines), and for "
                 "all records with VulnCheck's rules.",
                 "lrrrrrrr", r" & & \multicolumn{3}{c}{Assets exposed} & \multicolumn{3}{c}{Assets not exposed} \\ "
                 r"\cmidrule(lr){3-5}\cmidrule(lr){6-8} Records & $n$ & Changed & Shorter & Longer & Changed & Shorter & Longer", rows)


def t_benchmark():
    b = load("rq2/benchmark.json")
    names = {"majority": "Majority", "tfidf_lr": "TF-IDF classifier", "pipeline_R": "Conversion pipeline"}
    scopes = [("all", "All"), ("non_derived", "Non-derived"), ("derived", "Derived"), ("undetected", "Undetected"),
              ("v4_only", "v4-only"), ("other", "Other")]
    rows = []
    for m, mn in names.items():
        rows.append(rf"\multicolumn{{10}}{{l}}{{\emph{{{mn}}}}} \\")
        for s, sn in scopes:
            r = b["methods"][m][s]
            rows.append(f"{sn} & {r['n']:,} & {num(r['mean_macro_f1'])} & {num(r['v4_specific_f1'])} & {num(r['exact_match'])} & "
                        f"{num(r['score_mae'], 2)} & {num(r['band_acc'])} & {num(r['under_rate'])} & {num(r['hc_recall'])} & {num(r['kappa_band'], 2)}")
        rows.append(r"\addlinespace")
    rows.append(r"\multicolumn{10}{l}{\emph{Source profiles (all v4.0 labels)}} \\")
    prof = b["source_profiles"]
    assert prof["derived"] == prof["VulDB"], "derived labels are no longer exactly the VulDB labels"
    for g, v in prof.items():
        if g == "derived":
            continue
        name = "VulDB (derived)" if g == "VulDB" else ("type " + esc(g) if g in ("undetected", "v4_only", "other") else esc(g))
        rows.append(f"{name} & {v['n']:,} & \\multicolumn{{8}}{{l}}{{{v['distinct_vectors']:,} distinct vectors; most frequent vector "
                    f"{pct(v['most_frequent_vector_share'])}\\%}}")
    return table("tab:s-benchmark", "Severity prediction on the temporal test set, all metrics. F1: mean macro-F1 over the eleven base "
                 "metrics; v4-F1: over AT, UI, SC, SI, SA; Exact: share of completely correct vectors; MAE: mean absolute error of the "
                 "CVSS-B score; Band: band accuracy; Under: share of predicted bands below the labelled band; H+C: recall of High and "
                 "Critical labels; $\\kappa$: Cohen's $\\kappa$ of the bands. The majority classifier predicts the most frequent training "
                 "value of each metric.",
                 "lrrrrrrrrr", r"Test labels & $n$ & F1 & v4-F1 & Exact & MAE & Band & Under & H+C & $\kappa$", rows,
                 size=r"\scriptsize\setlength{\tabcolsep}{4pt}")


def t_reversal():
    r = load("rq2/reversal.json")
    rb = load("rq2/robustness.json")["equal_weight_per_cna"]
    rows = [r"\multicolumn{5}{l}{\emph{Pooled over test CVEs}} \\"]
    for scope, sn in (("all", "All test labels"), ("non_derived", "Non-derived labels")):
        for m, x in r["models"].items():
            rows.append(f"{sn if m == 'TF-IDF + LR' else ''} & {m} & {num(x[scope]['band_acc'])} & {num(r['pipeline_band_acc'][scope])} & "
                        f"{num(x[scope]['diff_vs_pipeline'])} {ci(x[scope]['ci95'], 1, 3).replace('-', '$-$')}")
    rows.append(r"\addlinespace")
    rows.append(r"\multicolumn{5}{l}{\emph{Equal weight per CNA (interval from resampling CNAs)}} \\")
    for setting, v in rb.items():
        first = setting.replace("at least ", r"$\geq$") + f" ({v['n_cnas']} CNAs)"
        for m, x in v["models"].items():
            rows.append(f"{first if m == 'TF-IDF + LR' else ''} & {m} & {num(x['band_acc'])} & {num(v['pipeline_band_acc'])} & "
                        f"{num(x['diff'])} {ci(x['ci95'], 1, 3).replace('-', '$-$')}")
    return table("tab:s-reversal", "Band accuracy of the models trained on v4.0 labels and of the conversion pipeline, and their "
                 "difference with a 95\\% bootstrap interval. Encoders: mean over five seeds.",
                 "llrrl", r"Scope & Model & Model & Pipeline & Difference", rows, size=r"\footnotesize")


def t_cgrid():
    o = load("rq2/robustness.json")["validation_selected_C"]
    rows = [r"\multicolumn{3}{l}{\emph{Validation mean macro-F1}} \\"]
    for c, v in o["validation_macro_f1"]["classifier"].items():
        p = o["validation_macro_f1"]["pipeline_first_stage"].get(c)
        rows.append(f"$C={c}$ & {num(v, 4)} & {num(p, 4) if p is not None else '--'}")
    sel = o["selected"]
    rows.append(r"\addlinespace")
    rows.append(rf"\multicolumn{{3}}{{l}}{{\emph{{Selected: classifier $C={sel['classifier_C']:g}$, pipeline $C={sel['pipeline_C']:g}$; band accuracy difference}}}} \\")
    for s, sn in (("all", "All test labels"), ("non_derived", "Non-derived labels")):
        lo, hi = o["all_pairs_range"][s]
        rows.append(f"{sn} & {num(sel[s]['diff'])} {ci(sel[s]['ci95'], 1, 3).replace('-', '$-$')} & range over 18 pairs: {num(lo)} to {num(hi)}")
    return table("tab:s-cgrid", "Sensitivity analysis of the regularisation strength; the main analysis uses $C=4$ for both TF-IDF "
                 "models. Regularisation strength of the two TF-IDF models chosen on validation data (the latest 10\\% of each "
                 "training set by publication date). Classifier: mean macro-F1 over the eleven v4.0 metrics; pipeline first stage: over "
                 "the eight v3.1 metrics.",
                 "lll", r" & Classifier & Pipeline (first stage)", rows)


def t_pairing():
    p = load("rq2/pairing.json")
    rows = [f"{esc(k[0].upper() + k[1:])} & {v['n']:,} & {pct(v['vuldb_share'])} & {pct(v['band_acc'])} & {pct(v['under_rate'])} & {pct(v['exact'])}"
            for k, v in p["settings"].items()]
    return table("tab:s-pairing", f"Rule~R applied to the NVD's or to the CNA's v3.1 vector, scored against the CNA's v4.0 label (\\%), "
                 f"on the rebuilt sample of CVEs with both versions in the NVD feeds ({p['d4_size']:,} CVEs). Strict pairing: CVEs with "
                 f"both an NVD and a CNA v3.1 vector; the NVD's and the CNA's v3.1 vectors are identical for "
                 f"{pct(p['strict_pairs_identical_v31'])}\\% of them.",
                 "lrrrrr", r"Setting & $n$ & VulDB & Band & Under & Exact", rows)


TIMING_GROUPS = ("NVD first", "NVD first, without VulDB", "NVD later", "NVD later, without VulDB")


def label(name):
    return r"{\quad}without VulDB" if name.endswith("without VulDB") else name


def t_nvd_timing_rq1():
    r = load("rq3/nvd_timing.json")
    rows = []
    for name in TIMING_GROUPS:
        g = r["groups"][name]
        cells = [f"{x['n']:,} & {pct(x['agree_seen'])} & {pct(x['agree_snapshot'])} & {pct(x['diff'])} {ci(x['ci95'])}"
                 for x in (g["disagreement"]["technical_impact"], g["disagreement"]["automatable"])]
        rows.append(f"{label(name)} & {g['n']:,} & {pct(g['n_vuldb'] / g['n'])} & " + " & ".join(cells))
    st, lag = r["status"], r["lag_days_nvd_minus_decision"]
    return table("tab:s-nvd-timing",
                 "Disagreement analysis of RQ1 by the time of the NVD's assessment, taken from the NVD's CVE Change History. NVD "
                 "first: the NVD's current vector was set before CISA's decision; NVD later: after it. Of the "
                 f"{r['sample']:,} records, the time comes from a matching NVD event for {st.get('matched', 0):,}, predates the "
                 f"history window (1 June 2022) for {st.get('before window', 0):,} and is unknown for {st.get('unknown', 0):,}; "
                 f"among the matched records, the median NVD assessment is {lag['median']:.1f} days after the decision. "
                 "VulDB: share of VulDB's records. A: CNA's vector; B: NVD's vector; shares and differences in \\% as in Table~S1, "
                 "with intervals resampling CNAs.",
                 "lrrrrrlrrrl", r" & & & \multicolumn{4}{c}{Technical Impact} & \multicolumn{4}{c}{Automatable} \\ "
                 r"\cmidrule(lr){4-7}\cmidrule(lr){8-11}"
                 r"Records & $n$ & VulDB & $n$ & A & B & A$-$B & $n$ & A & B & A$-$B",
                 rows, size=r"\scriptsize\setlength{\tabcolsep}{3pt}")


def t_nvd_timing_rq2():
    r = load("rq3/nvd_timing.json")
    rows = []
    for name in TIMING_GROUPS:
        g = r["groups"][name]
        cells = []
        for e in ("exposed", "not exposed"):
            m, a = g["tiers"][e]["main_actual_vs_nvd"], g["tiers"][e]["decomposition_cna_vs_nvd"]
            cells.append(f"{pct(m['changed'])} {ci(m['changed_ci95'])} & {pct(m['faster'])} & {pct(m['slower'])} & "
                         f"{pct(a['changed'])} {ci(a['changed_ci95'])}")
        rows.append(f"{label(name)} & {g['n']:,} & " + " & ".join(cells))
    return table("tab:s-nvd-timing-tiers",
                 "BOD 26-04 tier changes (\\%) by the time of the NVD's assessment (groups as in Table~S11): CISA's decisions "
                 "against the values derived from the NVD's vector, with the shares that receive a shorter and a longer "
                 "deadline, and the CNA's against the NVD's vector (Assessor); intervals resample vendors.",
                 "lrlrrllrrl", r" & & \multicolumn{4}{c}{Assets exposed} & \multicolumn{4}{c}{Assets not exposed} \\ "
                 r"\cmidrule(lr){3-6}\cmidrule(lr){7-10}"
                 r"Records & $n$ & Changed & Shorter & Longer & Assessor & Changed & Shorter & Longer & Assessor",
                 rows, size=r"\scriptsize\setlength{\tabcolsep}{1.8pt}")


def main():
    groups = [("RQ1: SSVC decisions and the CNA assessment at decision time", [t_rq1(), t_selection()]),
              ("RQ2: BOD 26-04 remediation tiers", [t_tiers(), t_nvd()]),
              ("RQ3: Severity prediction benchmarks", [t_provenance(), t_usage(), t_benchmark(), t_reversal(), t_cgrid(), t_pairing()]),
              ("RQ1 and RQ2 by the time of the NVD's assessment", [t_nvd_timing_rq1(), t_nvd_timing_rq2()])]
    parts = []
    for title, tables in groups:
        parts += [r"\clearpage", rf"\section*{{{title}}}", ""] + tables
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("% Generated by src/supplementary_tables.py; do not edit by hand.\n" + "\n".join(parts), encoding="utf-8")
    print(f"written {OUT} ({sum(len(t) for _, t in groups)} tables)")


if __name__ == "__main__":
    main()
