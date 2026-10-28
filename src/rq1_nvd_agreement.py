"""RQ1: agreement of the CNA-provided assessments with a second assessor, the NVD.

The NVD's own CVSS v3.1 vector (source nvd@nist.gov) is compared with
  (A) the CNA's v4.0 label, on all v4.0-labelled CVEs with an NVD vector, and
  (B) the same CNA's v3.1 vector and its v4.0 label, on the dual-scored CVEs with an NVD vector
      (same version: only the assessor differs; v4.0: assessor and version differ).
Seven items that both versions share are compared: AV, AC, PR; whether user interaction is required (v4.0's P and A both
count as required); and the confidentiality, integrity and availability impacts (v4.0: the larger of the vulnerable-system
and subsequent-system values). Severity bands: the NVD's v3.1 band against the band of the CNA's v3.1 vector or the CVSS-B
band of its v4.0 vector. Agreement describes two assessors and does not show which is correct.

Inputs: data/processed/cve_records.parquet, data/nvd_records.parquet (written by extract_nvd.py)
Output: results/rq1/nvd_agreement.json, results/rq1/nvd_agreement.md
"""

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from cvss import CVSS3

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cvss_utils import M31, SEVERITY_ORDER, parse_vector  # noqa: E402
from v4_labels import bands, label_types, load  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "rq1"
SHARED = ["AV", "AC", "PR", "UI", "C", "I", "A"]
LEVEL = {"N": 0, "L": 1, "H": 2}
GROUPS = [("VulDB", "VulDB"), ("VulnCheck", "VulnCheck"), ("GitHub", "GitHub_M")]


def v31_band(vec):
    return SEVERITY_ORDER[CVSS3(vec).severities()[0]]


def shared_from_v4(frame, prefix):
    g = lambda k: frame[prefix + k].to_numpy()  # noqa: E731
    mx = lambda a, b: np.where(np.vectorize(LEVEL.get)(a) >= np.vectorize(LEVEL.get)(b), a, b)  # noqa: E731
    return {"AV": g("AV"), "AC": g("AC"), "PR": g("PR"), "UI": np.where(g("UI") == "N", "N", "R"),
            "C": mx(g("VC"), g("SC")), "I": mx(g("VI"), g("SI")), "A": mx(g("VA"), g("SA"))}


def match(a, b):
    return np.column_stack([(a[k] == b[k]).astype(float) for k in SHARED])


def masks(d):
    out = [(n, (d["source"] == s).to_numpy()) for n, s in GROUPS]
    out.append(("other CNAs", (~d["source"].isin([s for _, s in GROUPS])).to_numpy()))
    out.append(("non-derived", (d["label_type"] != "derived").to_numpy()))
    out.append(("all", np.ones(len(d), bool)))
    return out


def summarise(m_items, cna_band, nvd_band, m):
    return {"n": int(m.sum()), "items": {k: float(m_items[m][:, j].mean()) for j, k in enumerate(SHARED)},
            "all_7_equal": float(m_items[m].all(1).mean()), "same_band": float((cna_band[m] == nvd_band[m]).mean()),
            "cna_lower": float((cna_band[m] < nvd_band[m]).mean()), "cna_higher": float((cna_band[m] > nvd_band[m]).mean())}


def main():
    df = load()
    df["label_type"] = df["source"].map(label_types()).fillna("other")
    nvd = pd.read_parquet(ROOT / "data" / "nvd_records.parquet", columns=["cve", "nvd_v31"]).dropna()
    nvd = dict(zip(nvd.cve, nvd.nvd_v31))
    d = df[df["cve_id"].isin(nvd)].reset_index(drop=True)
    parsed = [parse_vector(nvd[c], "3.1") for c in d["cve_id"]]
    ref = {k: np.array([p[k] for p in parsed]) for k in M31}
    ref_band = np.array([v31_band(nvd[c]) for c in d["cve_id"]])
    cna4_band = bands(d, "y_")

    out = {"coverage": {"v4_labels": int(len(df)), "with_nvd_v31": int(len(d))}, "A_v4_label_vs_nvd": {}, "band_distribution": {}}
    m4 = match(shared_from_v4(d, "y_"), ref)
    for name, m in masks(d):
        out["A_v4_label_vs_nvd"][name] = summarise(m4, cna4_band, ref_band, m)
        if name in ("VulDB", "VulnCheck", "GitHub", "other CNAs"):
            out["band_distribution"][name] = {
                "nvd_v31": {b: float((ref_band[m] == i).mean()) for b, i in SEVERITY_ORDER.items()},
                "cna_v40": {b: float((cna4_band[m] == i).mean()) for b, i in SEVERITY_ORDER.items()}}

    # B. the same CVEs: CNA v3.1 vs NVD v3.1 (assessor differs) and CNA v4.0 vs NVD v3.1 (assessor and version differ)
    dual = d["has_v31"].to_numpy()
    dd = d[dual].reset_index(drop=True)
    rref = {k: v[dual] for k, v in ref.items()}
    own31 = {k: dd["x31_" + k].to_numpy() for k in M31}
    own31_shared = {k: own31[k] for k in ["AV", "AC", "PR", "C", "I", "A"]} | {"UI": own31["UI"]}
    m31 = match(own31_shared, rref)
    m40 = match(shared_from_v4(dd, "y_"), rref)
    b31 = np.array([v31_band("CVSS:3.1/" + "/".join(f"{k}:{own31[k][i]}" for k in M31)) for i in range(len(dd))])
    b40 = cna4_band[dual]
    rb = ref_band[dual]
    vector_equal = np.all(np.column_stack([own31[k] == rref[k] for k in M31]), axis=1)
    out["B_same_cves"] = {"n": int(len(dd))}
    for name, m in masks(dd):
        if m.sum() < 30:
            continue
        out["B_same_cves"][name] = {"cna_v31_vs_nvd": summarise(m31, b31, rb, m) | {"vector_equal": float(vector_equal[m].mean())},
                                    "cna_v40_vs_nvd": summarise(m40, b40, rb, m)}

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "nvd_agreement.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
    lines = ["# RQ1: agreement of CNA assessments with the NVD's v3.1 assessment\n",
             f"v4.0-labelled CVEs with an NVD v3.1 vector: {len(d):,} of {len(df):,}.\n",
             "## A. CNA v4.0 label vs NVD v3.1\n",
             "| Group | n | " + " | ".join(SHARED) + " | All 7 equal | Same band | CNA lower / higher |", "|---|---|" + "---|" * (len(SHARED) + 3)]
    for name, r in out["A_v4_label_vs_nvd"].items():
        lines.append(f"| {name} | {r['n']:,} | " + " | ".join(f"{r['items'][k]:.3f}" for k in SHARED)
                     + f" | {r['all_7_equal']:.3f} | {r['same_band']:.3f} | {r['cna_lower']:.3f} / {r['cna_higher']:.3f} |")
    lines.append("\nBand distributions (None / Low / Medium / High / Critical):")
    for name, r in out["band_distribution"].items():
        lines.append(f"- {name}: NVD " + " / ".join(f"{x:.2f}" for x in r["nvd_v31"].values())
                     + "; CNA v4.0 " + " / ".join(f"{x:.2f}" for x in r["cna_v40"].values()))
    lines += [f"\n## B. Same CVEs ({len(dd):,} dual-scored with an NVD vector)\n",
              "| Group | Comparison | n | " + " | ".join(SHARED) + " | All 7 equal | Vector equal | Same band | CNA lower / higher |",
              "|---|---|---|" + "---|" * (len(SHARED) + 4)]
    for name, r in out["B_same_cves"].items():
        if name == "n":
            continue
        for comp, label in (("cna_v31_vs_nvd", "CNA v3.1"), ("cna_v40_vs_nvd", "CNA v4.0")):
            x = r[comp]
            ve = f"{x['vector_equal']:.3f}" if "vector_equal" in x else "-"
            lines.append(f"| {name} | {label} | {x['n']:,} | " + " | ".join(f"{x['items'][k]:.3f}" for k in SHARED)
                         + f" | {x['all_7_equal']:.3f} | {ve} | {x['same_band']:.3f} | {x['cna_lower']:.3f} / {x['cna_higher']:.3f} |")
    (OUT / "nvd_agreement.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
