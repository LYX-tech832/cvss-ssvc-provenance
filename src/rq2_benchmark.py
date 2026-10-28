"""RQ2: how does the composition of label sources change the evaluation of automated CVSS v4.0 assessment?

Task: predict the CNA-provided v4.0 base vector of a CVE from its description and CWE identifiers.
Split: temporal; training = CVEs published before 2026-01-01, test = CVEs published from that date until the snapshot.
Methods (all deterministic, CPU only)
  majority       most frequent value of each metric in the training labels
  tfidf_lr       TF-IDF (word 1-2 grams, min_df 2, at most 200,000 features, sublinear tf) + one logistic regression per
                 metric (C = 4, not tuned)
  pipeline_R     no v4.0 training label: TF-IDF + logistic regression (min_df 3, at most 300,000 features, C = 4) predicts the
                 v3.1 vector, trained on the v3.1 pool published before 2026; the predicted vector is converted with rule R
Reported on all test labels, on the non-derived labels (all labels except those of CNAs typed as derived) and per label type:
  mean macro-F1, v4-specific F1, exact match, MAE of the CVSS-B score, band accuracy, underestimation rate, High+Critical recall,
  the base rate (share of the most frequent band) and Cohen's kappa of the bands.
Source profiles (all v4.0 labels): number of distinct vectors, share of the most frequent vector.
Paired bootstrap (test CVEs resampled 1,000 times, seed 20261026): tfidf_lr minus pipeline_R in band accuracy and mean macro-F1.

Inputs: data/processed/cve_records.parquet, results/rq1/source_types.json
Output: results/rq2/benchmark.json, results/rq2/benchmark.md, results/rq2/predictions/*.parquet
"""

import json
import sys
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import cohen_kappa_score

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cvss_utils import M31, M40, SEVERITY_ORDER, V40_METRICS, rule_convert, to_vector, v4_score  # noqa: E402
from v4_labels import CUTOFF, evaluate, label_types, load, v31_pool  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "rq2"
PRED = OUT / "predictions"
SEED_LR = 0
SEED_BOOT = 20261026
B = 1000
TYPES = ["derived", "undetected", "v4_only", "other"]


def pred_majority(train, test):
    return pd.DataFrame({k: [train["y_" + k].mode()[0]] * len(test) for k in M40}, index=test.index)


def pred_tfidf_lr(train, test):
    vec = TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_features=200_000, sublinear_tf=True)
    xtr, xte = vec.fit_transform(train["text"]), vec.transform(test["text"])
    out = {}
    for k in M40:
        y = train["y_" + k].values
        if len(set(y)) == 1:
            out[k] = [y[0]] * len(test)
            continue
        out[k] = LogisticRegression(C=4.0, max_iter=3000, random_state=SEED_LR).fit(xtr, y).predict(xte)
    return pd.DataFrame(out, index=test.index)


def pred_pipeline(test):
    pool = v31_pool(before_cutoff=True)
    vec = TfidfVectorizer(ngram_range=(1, 2), min_df=3, max_features=300_000, sublinear_tf=True)
    x, xq = vec.fit_transform(pool["text"]), vec.transform(test["text"])
    v31 = pd.DataFrame({k: LogisticRegression(C=4.0, max_iter=3000, random_state=SEED_LR).fit(x, pool["z_" + k].values).predict(xq)
                        for k in M31})
    rows = [rule_convert({k: r[k] for k in M31}) for _, r in v31.iterrows()]
    return pd.DataFrame(rows, index=test.index)[M40], len(pool)


class Encoded:
    """Integer codes of each metric and the band index of each vector, for fast resampling."""

    def __init__(self, frame, prefix=""):
        self.codes = {k: frame[prefix + k].map({v: i for i, v in enumerate(V40_METRICS[k])}).to_numpy() for k in M40}
        vecs = frame[[prefix + k for k in M40]].set_axis(M40, axis=1).apply(to_vector, axis=1)
        self.band = np.array([SEVERITY_ORDER.get(v4_score(v)[1], -1) for v in vecs])


def fast_scores(t, p, idx):
    """Mean macro-F1 (same definition as evaluate()) and band accuracy on the CVEs idx."""
    f1s = []
    for k in M40:
        n = len(V40_METRICS[k])
        cm = np.bincount(t.codes[k][idx] * n + p.codes[k][idx], minlength=n * n).reshape(n, n)
        tp = np.diag(cm)
        denom = 2 * tp + (cm.sum(0) - tp) + (cm.sum(1) - tp)
        f1s.append(np.where(denom > 0, 2 * tp / np.maximum(denom, 1), 0.0).mean())
    return np.array([np.mean(f1s), (t.band[idx] == p.band[idx]).mean()])


def main():
    df = load()
    df["label_type"] = df["source"].map(label_types()).fillna("other")
    train, test = df[df["pub"] < CUTOFF], df[df["pub"] >= CUTOFF].reset_index(drop=True)
    print(f"training {len(train):,}, test {len(test):,}", flush=True)

    preds = {"majority": pred_majority(train, test), "tfidf_lr": pred_tfidf_lr(train, test.copy())}
    print("tfidf_lr done", flush=True)
    preds["pipeline_R"], n_pool = pred_pipeline(test)
    print("pipeline_R done", flush=True)
    PRED.mkdir(parents=True, exist_ok=True)
    for name, p in preds.items():
        p.assign(cve_id=test["cve_id"].values).to_parquet(PRED / f"temporal_{name}.parquet", index=False)

    scopes = [("all", np.ones(len(test), bool)), ("non_derived", (test["label_type"] != "derived").to_numpy())]
    scopes += [(t, (test["label_type"] == t).to_numpy()) for t in TYPES]
    t_enc = Encoded(test, "y_")
    results = {"n_train": int(len(train)), "n_test": int(len(test)), "n_v31_pool": int(n_pool), "methods": {}, "base_rate": {}}
    for scope, m in scopes:
        tb = t_enc.band[m]
        results["base_rate"][scope] = {"n": int(m.sum()), "most_frequent_band_share": float(np.bincount(tb[tb >= 0]).max() / len(tb))}
    for name, p in preds.items():
        p_enc = Encoded(p)
        results["methods"][name] = {}
        for scope, m in scopes:
            r = evaluate(test[m], p[m])
            r.pop("per_metric")
            r["kappa_band"] = float(cohen_kappa_score(t_enc.band[m], p_enc.band[m]))
            results["methods"][name][scope] = r

    # source profiles (all v4.0 labels)
    vec = df[["y_" + k for k in M40]].astype(str).agg("/".join, axis=1)
    profiles = {}
    for name, m in [("VulDB", df["source"] == "VulDB"), ("VulnCheck", df["source"] == "VulnCheck"), ("GitHub", df["source"] == "GitHub_M")] \
            + [(t, df["label_type"] == t) for t in TYPES]:
        c = Counter(vec[m])
        profiles[name] = {"n": int(m.sum()), "distinct_vectors": len(c), "most_frequent_vector_share": c.most_common(1)[0][1] / int(m.sum())}
    results["source_profiles"] = profiles

    # paired bootstrap: tfidf_lr - pipeline_R
    rng = np.random.default_rng(SEED_BOOT)
    ea, eb = Encoded(preds["tfidf_lr"]), Encoded(preds["pipeline_R"])
    results["tfidf_minus_pipeline"] = {}
    for scope, m in scopes[:2]:
        idx = np.flatnonzero(m)
        point = fast_scores(t_enc, ea, idx) - fast_scores(t_enc, eb, idx)
        bs = np.array([fast_scores(t_enc, ea, ix) - fast_scores(t_enc, eb, ix)
                       for ix in (rng.choice(idx, size=len(idx), replace=True) for _ in range(B))])
        results["tfidf_minus_pipeline"][scope] = {
            key: {"diff": float(point[j]), "ci95": [float(np.percentile(bs[:, j], 2.5)), float(np.percentile(bs[:, j], 97.5))]}
            for j, key in enumerate(["mean_macro_f1", "band_acc"])}

    (OUT / "benchmark.json").write_text(json.dumps(results, indent=1), encoding="utf-8")
    lines = ["# RQ2: label sources and the evaluation of automated v4.0 assessment (temporal split)\n",
             f"Training {len(train):,} CVEs (before 2026); test {len(test):,}; v3.1 pool for the pipeline {n_pool:,}.\n",
             "| Method | Scope | n | Macro-F1 | v4-F1 | Exact | MAE | Band | Under | H+C rec. | kappa |", "|---|---|---|---|---|---|---|---|---|---|---|"]
    for name, rs in results["methods"].items():
        for scope, r in rs.items():
            lines.append(f"| {name} | {scope} | {r['n']:,} | {r['mean_macro_f1']:.3f} | {r['v4_specific_f1']:.3f} | {r['exact_match']:.3f} | "
                         f"{r['score_mae']:.2f} | {r['band_acc']:.3f} | {r['under_rate']:.3f} | {r['hc_recall']:.3f} | {r['kappa_band']:.2f} |")
    lines.append("\nBase rate (share of the most frequent band among the test labels): "
                 + "; ".join(f"{s} {v['most_frequent_band_share']:.1%} (n={v['n']:,})" for s, v in results["base_rate"].items()))
    lines.append("\nSource profiles (all v4.0 labels): "
                 + "; ".join(f"{s}: {v['distinct_vectors']:,} distinct vectors, most frequent {v['most_frequent_vector_share']:.1%} (n={v['n']:,})"
                             for s, v in profiles.items()))
    lines.append("\nTF-IDF + LR minus pipeline (rule R), paired bootstrap 95% intervals:")
    for scope, r in results["tfidf_minus_pipeline"].items():
        lines.append(f"- {scope}: band accuracy {r['band_acc']['diff']:+.3f} [{r['band_acc']['ci95'][0]:+.3f}, {r['band_acc']['ci95'][1]:+.3f}]; "
                     f"mean macro-F1 {r['mean_macro_f1']['diff']:+.3f} [{r['mean_macro_f1']['ci95'][0]:+.3f}, {r['mean_macro_f1']['ci95'][1]:+.3f}]")
    (OUT / "benchmark.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
