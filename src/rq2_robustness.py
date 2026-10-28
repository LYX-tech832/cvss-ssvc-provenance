"""Robustness of the band-accuracy reversal between models trained on v4.0 labels and the conversion pipeline (temporal split).

A. Regularisation strength selected on validation data. The main analysis fixes C = 4 for both TF-IDF models. Here the
   classifier uses C in {0.25, 1, 4, 16, 64, 256} and the first stage of the pipeline C in {1, 4, 16}; each is fitted on the
   earliest 90% of its training data (by publication date), scored on the latest 10% (mean macro-F1 of v4.0 or v3.1 metrics),
   and the selected C is refitted on all training data. The band-accuracy difference of the selected pair is reported with a
   paired bootstrap over test CVEs (1,000 resamples, seed 20261026), together with the differences of all 18 pairs.
B. Equal weight per CNA. Band accuracy is computed for each CNA with at least 30 (or 100) test CVEs and averaged with equal
   weight, for all such CNAs and without VulDB; the difference "model minus pipeline" gets an interval from resampling CNAs
   (2,000 times, seed 20261026). Models: TF-IDF + LR, DeBERTa-v3-base and SecureBERT (as in rq2_reversal.py).

Predictions of part A are cached in results/rq2/tfidf_sensitivity/ (part A takes about an hour; part B seconds).
Inputs: data/processed/cve_records.parquet, results/rq1/source_types.json, results/rq2/predictions/, data/encoder_predictions/
Output: results/rq2/robustness.json
Usage: python src/rq2_robustness.py [a|b|all]
"""

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cvss_utils import M31, M40, V31_METRICS, rule_convert  # noqa: E402
from rq2_benchmark import Encoded, fast_scores  # noqa: E402
from rq2_reversal import MODELS  # noqa: E402
from v4_labels import CUTOFF, label_types, load, v31_pool  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "rq2"
CACHE = OUT / "tfidf_sensitivity"
PRED = OUT / "predictions"
C_CLF, C_PIPE = [0.25, 1.0, 4.0, 16.0, 64.0, 256.0], [1.0, 4.0, 16.0]
SEED = 20261026


def fit_predict(train_text, ys, query_text, C, min_df, max_features):
    vec = TfidfVectorizer(ngram_range=(1, 2), min_df=min_df, max_features=max_features, sublinear_tf=True)
    x, xq = vec.fit_transform(train_text), vec.transform(query_text)
    out = {}
    for k, y in ys.items():
        out[k] = [y[0]] * xq.shape[0] if len(set(y)) == 1 else LogisticRegression(C=C, max_iter=3000, random_state=0).fit(x, y).predict(xq)
    return pd.DataFrame(out)


def cached(name, fn):
    f, g = CACHE / f"{name}.parquet", CACHE / f"{name}.json"
    if f.exists() and g.exists():
        return pd.read_parquet(f), json.loads(g.read_text())["validation"]
    pred, val = fn()
    pred.to_parquet(f, index=False)
    g.write_text(json.dumps({"validation": val}))
    print(f"  {name}: validation {val:.4f}", flush=True)
    return pred, val


def part_a(df, test, t_enc, scopes):
    CACHE.mkdir(parents=True, exist_ok=True)
    train = df[df["pub"] < CUTOFF].sort_values("pub", kind="stable")
    n_val = int(0.1 * len(train))
    fit, val = train.iloc[:-n_val], train.iloc[-n_val:].reset_index(drop=True)
    pool = v31_pool(before_cutoff=True).sort_values("pub", kind="stable")
    p_val_n = int(0.1 * len(pool))
    pfit, pval = pool.iloc[:-p_val_n], pool.iloc[-p_val_n:]
    v_enc = Encoded(val, "y_")
    ys4 = lambda d: {k: d["y_" + k].values for k in M40}  # noqa: E731
    ys3 = lambda d: {k: d["z_" + k].values for k in M31}  # noqa: E731

    def clf(C):
        def run():
            pv = fit_predict(fit["text"], ys4(fit), val["text"], C, 2, 200_000)
            v = float(fast_scores(v_enc, Encoded(pv), np.arange(len(val)))[0])
            return fit_predict(train["text"], ys4(train), test["text"], C, 2, 200_000).assign(cve_id=test["cve_id"].values), v
        return cached(f"classifier_C{C:g}", run)

    def pipe(C):
        def run():
            pv = fit_predict(pfit["text"], ys3(pfit), pval["text"], C, 3, 300_000)
            v = float(np.mean([f1_score(pval["z_" + k].values, pv[k].values, labels=V31_METRICS[k], average="macro", zero_division=0) for k in M31]))
            p31 = fit_predict(pool["text"], ys3(pool), test["text"], C, 3, 300_000)
            p4 = pd.DataFrame([rule_convert({k: r[k] for k in M31}) for _, r in p31.iterrows()])[M40]
            return p4.assign(cve_id=test["cve_id"].values), v
        return cached(f"pipeline_C{C:g}", run)

    clfs = {C: clf(C) for C in C_CLF}
    pipes = {C: pipe(C) for C in C_PIPE}
    hit = lambda p: (Encoded(p.set_index("cve_id").loc[test["cve_id"]].reset_index()).band == t_enc.band).astype(float)  # noqa: E731
    hc = {C: hit(p) for C, (p, _) in clfs.items()}
    hp = {C: hit(p) for C, (p, _) in pipes.items()}
    grid = {f"classifier C={cc:g} vs pipeline C={cp:g}": {s: float(hc[cc][idx].mean() - hp[cp][idx].mean()) for s, idx in scopes.items()}
            for cc in C_CLF for cp in C_PIPE}
    bc = max(clfs, key=lambda c: clfs[c][1])
    bp = max(pipes, key=lambda c: pipes[c][1])
    rng = np.random.default_rng(SEED)
    selected = {"classifier_C": bc, "pipeline_C": bp}
    for s, idx in scopes.items():
        d = hc[bc][idx] - hp[bp][idx]
        bs = [d[rng.integers(len(d), size=len(d))].mean() for _ in range(1000)]
        selected[s] = {"diff": float(d.mean()), "ci95": [float(np.percentile(bs, 2.5)), float(np.percentile(bs, 97.5))]}
    return {"validation_macro_f1": {"classifier": {f"{c:g}": v for c, (_, v) in clfs.items()},
                                    "pipeline_first_stage": {f"{c:g}": v for c, (_, v) in pipes.items()}},
            "selected": selected, "all_pairs": grid,
            "all_pairs_range": {s: [min(g[s] for g in grid.values()), max(g[s] for g in grid.values())] for s in scopes}}


def part_b(test, t_enc):
    src = test["source"].to_numpy()
    counts = test["source"].value_counts()
    pipe = (Encoded(pd.read_parquet(PRED / "temporal_pipeline_R.parquet").set_index("cve_id").loc[test["cve_id"]].reset_index()).band
            == t_enc.band).astype(float)
    models = {m: np.mean([(Encoded(pd.read_parquet(p).set_index("cve_id").loc[test["cve_id"]].reset_index()).band == t_enc.band)
                          for p in paths], axis=0) for m, paths in MODELS.items()}
    rng = np.random.default_rng(SEED)
    out = {}
    for min_n in (30, 100):
        keep_all = [s for s, n in counts.items() if n >= min_n]
        for label, keep in (("all CNAs", keep_all), ("without VulDB", [s for s in keep_all if s != "VulDB"])):
            key = f"at least {min_n} test CVEs, {label}"
            out[key] = {"n_cnas": len(keep), "n_cves": int(sum(counts[s] for s in keep)),
                        "pipeline_band_acc": float(np.mean([pipe[src == s].mean() for s in keep])), "models": {}}
            for m, acc in models.items():
                d = np.array([acc[src == s].mean() - pipe[src == s].mean() for s in keep])
                bs = np.array([d[rng.integers(len(d), size=len(d))].mean() for _ in range(2000)])
                out[key]["models"][m] = {"band_acc": float(np.mean([acc[src == s].mean() for s in keep])), "diff": float(d.mean()),
                                         "ci95": [float(np.percentile(bs, 2.5)), float(np.percentile(bs, 97.5))],
                                         "cnas_where_model_higher": int((d > 0).sum())}
    return out


def main():
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    df = load()
    df["label_type"] = df["source"].map(label_types()).fillna("other")
    test = df[df["pub"] >= CUTOFF].reset_index(drop=True)
    t_enc = Encoded(test, "y_")
    scopes = {"all": np.arange(len(test)), "non_derived": np.flatnonzero((test["label_type"] != "derived").to_numpy())}
    path = OUT / "robustness.json"
    out = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    if which in ("b", "all"):
        out["equal_weight_per_cna"] = part_b(test, t_enc)
    if which in ("a", "all"):
        out["validation_selected_C"] = part_a(df, test, t_enc, scopes)
    path.write_text(json.dumps(out, indent=1), encoding="utf-8")
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
