"""Data loading and evaluation for encoders/train_encoder.py.

load(): one row per CVE in data/processed/cve_records.parquet (written by src/extract_cve_records.py) with a valid
CNA-provided CVSS v4.0 base vector and a description. The model input ("text") is the description followed by the CWE
identifiers of the CNA and ADP containers; the labels are the eleven v4.0 base metrics (columns y_<metric>).

evaluate(): per-metric accuracy and macro-F1, exact match of the whole vector, mean absolute error of the CVSS-B score,
severity band accuracy, share of predicted bands below the labelled band, recall of High and Critical labels and the
Spearman correlation of the scores. Scores and bands come from the cvss library (FIRST's formula and ranges).
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd
from cvss import CVSS4
from scipy.stats import spearmanr
from sklearn.metrics import accuracy_score, f1_score

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from cvss_utils import V31_METRICS, V40_METRICS, parse_vector  # noqa: E402

CUTOFF = pd.Timestamp("2026-01-01", tz="UTC")
M40 = list(V40_METRICS)
M31 = list(V31_METRICS)
SEVERITY_ORDER = {"None": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
_score_cache = {}


def load():
    df = pd.read_parquet(ROOT / "data" / "processed" / "cve_records.parquet")
    df = df[(df["cna_v40"].str.len() > 0) & df["description"].notna()].copy()
    df["pub"] = pd.to_datetime(df["date_published"], utc=True, errors="coerce")
    df["source"] = df["cna_short_name"].fillna("UNKNOWN")
    v40 = df["cna_v40"].map(lambda v: parse_vector(v[0], "4.0"))
    for k in M40:
        df["y_" + k] = v40.map(lambda p: p[k] if p else None)
    cwe = df["cwe_cna"].map(list) + df["cwe_adp"].map(list)
    df["text"] = df["description"].str.strip() + " " + cwe.map(lambda c: " ".join(dict.fromkeys(c)))
    return df.dropna(subset=["y_AV"]).reset_index(drop=True)


def v4_score(vec):
    """(CVSS-B score, severity band) of a v4.0 vector; (nan, None) if the cvss library rejects it."""
    if vec not in _score_cache:
        try:
            c = CVSS4(vec)
            _score_cache[vec] = (float(c.base_score), c.severity)
        except Exception:
            _score_cache[vec] = (np.nan, None)
    return _score_cache[vec]


def to_vector(row):
    return "CVSS:4.0/" + "/".join(f"{k}:{row[k]}" for k in M40)


def evaluate(true_df, pred_df):
    res = {"n": len(true_df), "per_metric": {}}
    for k in M40:
        t, p = true_df["y_" + k].values, pred_df[k].values
        res["per_metric"][k] = {
            "acc": accuracy_score(t, p),
            "macro_f1": f1_score(t, p, average="macro", labels=V40_METRICS[k], zero_division=0),
        }
    res["mean_macro_f1"] = float(np.mean([v["macro_f1"] for v in res["per_metric"].values()]))
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
    # the rank correlation is undefined when all predicted (or true) scores are equal
    defined = len(ts) > 2 and np.nanstd(ps) > 0 and np.nanstd(ts) > 0
    res["spearman"] = float(spearmanr(ts, ps, nan_policy="omit").correlation) if defined else float("nan")
    return res
