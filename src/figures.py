"""Figures 2, 3 and S1 of the paper (pubfig on matplotlib; fonts embedded as TrueType).

Figure S1 quarterly share of the dual-scored CVEs of VulDB and VulnCheck whose v4.0 vector equals rule R applied to the same
          CNA's v3.1 vector (quarters with at least 30 dual-scored CVEs; results/rq1/provenance.json)
Figure 3  band-accuracy difference between models trained on v4.0 labels and the conversion pipeline, on all test labels and
          on the non-derived labels of the temporal split, with paired-bootstrap 95% intervals (results/rq2/reversal.json)
Figure 2  share of CVEs whose BOD 26-04 tier changes when Automatable and Technical Impact are derived from the NVD's vector
          instead of taken from CISA's decision, assuming every asset is publicly exposed, overall and for the 12 CNAs with
          the most records; split into shorter and longer deadlines (results/rq3/tiers.json)

Output: paper/figures/fig2_tiers_by_cna.{pdf,png}, paper/figures/fig3_reversal.{pdf,png}, paper/figures/figS1_quarterly.{pdf,png}
"""

import json
from pathlib import Path

import matplotlib
import numpy as np
import pubfig as pf

matplotlib.rcParams["pdf.fonttype"] = 42
matplotlib.rcParams["ps.fonttype"] = 42

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "paper" / "figures"
BLUE, ORANGE = "#2a78d6", "#eb6834"  # categorical slots 1 and 2, validated for colour-vision deficiency on white
MINUS = chr(0x2212)  # typographic minus, as on the axes
CNA_NAMES = {"VulDB": "VulDB", "GitHub_M": "GitHub", "cisco": "Cisco", "ibm": "IBM", "zdi": "ZDI", "icscert": "ICS-CERT",
             "talos": "Talos", "mitre": "MITRE", "oracle": "Oracle", "dell": "Dell", "@huntrdev": "huntr", "fortinet": "Fortinet"}


def fig_quarterly():
    q = json.loads((ROOT / "results" / "rq1" / "provenance.json").read_text(encoding="utf-8"))["quarterly_rule_R"]
    series = {"VulDB": q["VulDB"], "VulnCheck": q["VulnCheck"]}
    quarters = sorted({k for s in series.values() for k in s})
    data = np.array([[s[k]["rule_R"] if k in s else np.nan for k in quarters] for s in series.values()])
    fig = pf.line(list(data), x=np.arange(len(quarters)), series_names=list(series), x_label="Quarter of publication",
                  y_label="v4.0 vectors equal to rule R (share)", color_palette=[BLUE, ORANGE])
    ax = fig.axes[0]
    ax.set_xticks(np.arange(len(quarters)))
    ax.set_xticklabels(quarters, rotation=45, ha="right")
    ax.set_ylim(0, 1.05)
    from matplotlib.ticker import PercentFormatter
    ax.yaxis.set_major_formatter(PercentFormatter(1.0, decimals=0))
    if ax.get_legend() is not None:  # text in ink colour; the marker carries the series identity
        for text in ax.get_legend().get_texts():
            text.set_color("0.1")
    return fig


def fig_reversal():
    r = json.loads((ROOT / "results" / "rq2" / "reversal.json").read_text(encoding="utf-8"))
    bench = json.loads((ROOT / "results" / "rq2" / "benchmark.json").read_text(encoding="utf-8"))
    n = {s: bench["base_rate"][s]["n"] for s in ("all", "non_derived")}
    names = {"TF-IDF + LR": "TF-IDF + LR", "DeBERTa-v3-base": "DeBERTa-v3-base", "SecureBERT": "SecureBERT"}
    labels, groups, eff, lo, hi, right = [], [], [], [], [], []
    for scope, title in (("all", f"All test labels (n = {n['all']:,})"), ("non_derived", f"Non-derived labels (n = {n['non_derived']:,})")):
        for m in names:
            x = r["models"][m][scope]
            labels.append(names[m])
            groups.append(title)
            eff.append(x["diff_vs_pipeline"])
            lo.append(x["ci95"][0])
            hi.append(x["ci95"][1])
            right.append(f"{x['diff_vs_pipeline']:+.3f} [{x['ci95'][0]:+.3f}, {x['ci95'][1]:+.3f}]".replace("-", MINUS))
    fig = pf.forest_plot(np.array(eff), np.array(lo), np.array(hi), labels=labels, group_labels=groups, right_labels=right,
                         x_label="Band accuracy of the model minus that of the conversion pipeline", reference=0.0,
                         x_min=-0.06, x_max=0.10, point_color="0.15")
    return fig


def fig_tiers():
    s = json.loads((ROOT / "results" / "rq3" / "tiers.json").read_text(encoding="utf-8"))
    sc = s["scenarios"]["exposed"]
    rows = [(f"All CNAs (n = {sc['all']['main_actual_vs_nvd']['n']:,})", sc["all"]["main_actual_vs_nvd"]),
            (f"Without VulDB (n = {sc['all without VulDB']['main_actual_vs_nvd']['n']:,})", sc["all without VulDB"]["main_actual_vs_nvd"])]
    cnas = sorted(sc["by_cna_main"].items(), key=lambda kv: -kv[1]["changed"])
    rows += [(f"{CNA_NAMES.get(c, c)} (n = {v['n']:,})", v) for c, v in cnas]
    rows = rows[::-1]  # the first row is drawn at the bottom; put the overall rows on top
    data = np.array([[[v["faster"], v["slower"]]] for _, v in rows])
    fig = pf.stacked_bar(data, group_names=[name for name, _ in rows], normalize=False,
                         x_label="Share of CVEs whose BOD 26-04 tier changes (assets exposed)",
                         color_palette=[BLUE, ORANGE], legend_show=False)
    ax = fig.axes[0]
    ax.set_ylabel("")
    # secondary encoding for greyscale print: hatch the second segment; the legend names both segments
    for container_index, container in enumerate(ax.containers):
        for patch in container:
            if container_index % 2 == 1:
                patch.set_hatch("////")
                patch.set_edgecolor("white")
    size = ax.get_xticklabels()[0].get_fontsize()
    # total share at the end of each bar
    ends = {}
    for container in ax.containers:
        for patch in container:
            y = round(patch.get_y() + patch.get_height() / 2, 6)
            ends[y] = max(ends.get(y, 0.0), patch.get_x() + patch.get_width())
    for y, x in ends.items():
        ax.text(x + 0.008, y, f"{x:.1%}", va="center", ha="left", fontsize=size, color="0.2")
    # separate the two overall rows from the CNAs
    ys = sorted(ends)
    ax.axhline((ys[-2] + ys[-3]) / 2, color="0.75", linewidth=0.6)
    from matplotlib.patches import Patch
    from matplotlib.ticker import PercentFormatter
    ax.legend(handles=[Patch(facecolor=BLUE, label="Shorter deadline with the NVD's vector"),
                       Patch(facecolor=ORANGE, hatch="////", edgecolor="white", label="Longer deadline with the NVD's vector")],
              loc="lower center", bbox_to_anchor=(0.5, 1.0), ncol=2, frameon=False, fontsize=size)
    ax.set_xlim(0, 0.75)
    ax.xaxis.set_major_formatter(PercentFormatter(1.0, decimals=0))
    return fig


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for name, make, width in (("fig2_tiers_by_cna", fig_tiers, 140), ("fig3_reversal", fig_reversal, 140), ("figS1_quarterly", fig_quarterly, 120)):
        fig = make()
        paths = pf.batch_export(fig, OUT / name, formats=("pdf", "png"), spec="nature", width=width, dpi=300)
        print(name, [str(p) for p in paths])


if __name__ == "__main__":
    main()
