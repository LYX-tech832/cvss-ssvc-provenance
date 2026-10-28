"""CNA-provided CVSS v4.0 labels: loading, the v3.1 pool, label types and evaluation metrics (shared by the RQ1 and RQ2 scripts).

Input: data/processed/cve_records.parquet (written by extract_cve_records.py).

Definitions
  source       providerMetadata.shortName of the CNA container (the CNA that wrote the vector).
  v4.0 label   the first valid CVSS v4.0 base vector of the CNA container; records without an English description are dropped.
  dual-scored  the same CNA container also has a valid v3.1 base vector (the first one is used).
  v3.1 pool    CVEs with a v3.1 vector (CNA container, else the first ADP container) and no CNA-provided v4.0 vector;
               used only to train the first stage of the conversion pipeline.
  text         English description followed by the CWE identifiers of the CNA and ADP containers.
  label type   from results/rq1/source_types.json (written by rq1_provenance.py, data before 2026 only):
               derived, undetected (enough dual-scored CVEs but not derived), v4_only, other.
"""

import json
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cvss_utils import M31, M40, SEVERITY_ORDER, V40_METRICS, parse_vector, to_vector, v4_score  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
RECORDS = ROOT / "data" / "processed" / "cve_records.parquet"
TYPES = ROOT / "results" / "rq1" / "source_types.json"
CUTOFF = pd.Timestamp("2026-01-01", tz="UTC")
V4_SPECIFIC = ["AT", "UI", "SC", "SI", "SA"]


def _text(df):
    cwe = df["cwe_cna"].map(list) + df["cwe_adp"].map(list)
    return df["description"].str.strip() + " " + cwe.map(lambda c: " ".join(dict.fromkeys(c)))


def load():
    """One row per CVE with a CNA-provided v4.0 label: y_<metric> (v4.0), x31_<metric> (same-CNA v3.1 or None), source, pub, text."""
    df = pd.read_parquet(RECORDS)
    df = df[(df["cna_v40"].str.len() > 0) & df["description"].notna()].copy()
    df["pub"] = pd.to_datetime(df["date_published"], utc=True, errors="coerce")
    df["source"] = df["cna_short_name"].fillna("UNKNOWN")
    v40 = df["cna_v40"].map(lambda v: parse_vector(v[0], "4.0"))
    v31 = df["cna_v31"].map(lambda v: parse_vector(v[0], "3.1") if len(v) else None)
    for k in M40:
        df["y_" + k] = v40.map(lambda p: p[k] if p else None)
    for k in M31:
        df["x31_" + k] = v31.map(lambda p: p[k] if p else None)
    df["has_v31"] = v31.notna()
    df["text"] = _text(df)
    return df.dropna(subset=["y_AV"]).reset_index(drop=True)


def v31_pool(before_cutoff=True):
    """CVEs with a v3.1 vector and no CNA-provided v4.0 vector (z_<metric>); by default only those published before the cut-off."""
    df = pd.read_parquet(RECORDS)
    df = df[(df["cna_v40"].str.len() == 0) & df["description"].notna()].copy()
    df["pub"] = pd.to_datetime(df["date_published"], utc=True, errors="coerce")
    if before_cutoff:
        df = df[df["pub"] < CUTOFF]

    def pick(r):
        if len(r["cna_v31"]):
            return parse_vector(r["cna_v31"][0], "3.1")
        if len(r["adp_v31"]):
            return parse_vector(r["adp_v31"][0].split("|", 1)[1], "3.1")
        return None

    v31 = df.apply(pick, axis=1)
    df = df[v31.notna()].copy()
    v31 = v31[v31.notna()]
    for k in M31:
        df["z_" + k] = v31.map(lambda p: p[k])
    df["text"] = _text(df)
    return df


def label_types():
    """{source: type} from rq1_provenance.py; sources not listed are 'other'."""
    if not TYPES.exists():
        raise FileNotFoundError("run src/rq1_provenance.py first")
    return {s: v["type"] for s, v in json.loads(TYPES.read_text(encoding="utf-8")).items()}


def collect_pairs(df):
    """{source: [(v31 tuple, v31 dict, v4 tuple, v4 dict), ...]} for dual-scored CVEs, in order of publication."""
    by_src = defaultdict(list)
    for r in df[df["has_v31"]].sort_values("pub").itertuples():
        d31 = {k: getattr(r, "x31_" + k) for k in M31}
        d40 = {k: getattr(r, "y_" + k) for k in M40}
        by_src[r.source].append((tuple(d31[k] for k in M31), d31, tuple(d40[k] for k in M40), d40))
    return by_src


def bands(frame, prefix=""):
    """Severity band index (0 = None ... 4 = Critical, -1 = invalid) of each row's v4.0 vector."""
    vecs = frame[[prefix + k for k in M40]].set_axis(M40, axis=1).apply(to_vector, axis=1)
    return np.array([SEVERITY_ORDER.get(v4_score(v)[1], -1) for v in vecs])


def evaluate(true_df, pred_df):
    """Metrics of predicted v4.0 vectors (pred_df columns = metric names) against labels (true_df columns y_<metric>).

    mean_macro_f1   mean over the 11 metrics of the macro-F1 over all values defined for the metric
    v4_specific_f1  the same mean over AT, UI, SC, SI and SA
    exact_match     share of vectors with all 11 metrics correct
    score_mae       mean absolute error of the CVSS-B score
    band_acc        share with the correct severity band
    under_rate      share whose predicted band is lower than the labelled band
    hc_recall       share of labels rated High or Critical that are predicted High or Critical
    """
    res = {"n": len(true_df), "per_metric": {}}
    for k in M40:
        t, p = true_df["y_" + k].values, pred_df[k].values
        res["per_metric"][k] = {"acc": accuracy_score(t, p),
                                "macro_f1": f1_score(t, p, average="macro", labels=V40_METRICS[k], zero_division=0)}
    res["mean_macro_f1"] = float(np.mean([v["macro_f1"] for v in res["per_metric"].values()]))
    res["v4_specific_f1"] = float(np.mean([res["per_metric"][k]["macro_f1"] for k in V4_SPECIFIC]))
    true_vec = true_df[["y_" + k for k in M40]].set_axis(M40, axis=1).apply(to_vector, axis=1)
    pred_vec = pred_df[M40].apply(to_vector, axis=1)
    res["exact_match"] = float((true_vec.values == pred_vec.values).mean())
    t_sc = [v4_score(v) for v in true_vec.values]
    p_sc = [v4_score(v) for v in pred_vec.values]
    ts, ps = np.array([s for s, _ in t_sc]), np.array([s for s, _ in p_sc])
    tb = np.array([SEVERITY_ORDER.get(b, -1) for _, b in t_sc])
    pb = np.array([SEVERITY_ORDER.get(b, -1) for _, b in p_sc])
    res["score_mae"] = float(np.nanmean(np.abs(ts - ps)))
    res["band_acc"] = float((tb == pb).mean())
    res["under_rate"] = float((pb < tb).mean())
    hc = tb >= SEVERITY_ORDER["High"]
    res["hc_recall"] = float((pb[hc] >= SEVERITY_ORDER["High"]).mean()) if hc.any() else float("nan")
    return res
