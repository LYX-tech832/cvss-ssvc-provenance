"""RQ2: does the band-accuracy ranking of models trained on v4.0 labels against the conversion pipeline depend on the derived labels?

For each model that predicts v4.0 vectors directly, the difference in band accuracy to the conversion pipeline (rule R applied
to TF-IDF-predicted v3.1 vectors, no v4.0 training label) is computed on all test labels and on the non-derived labels of the
temporal split, with a paired bootstrap over test CVEs (1,000 resamples, seed 20261026). For encoders, band accuracy is the
mean over five seeds of each configuration; each resample uses the same CVEs for all seeds.
Models
  TF-IDF + LR      results/rq2/predictions/temporal_tfidf_lr.parquet (written by rq2_benchmark.py)
  DeBERTa-v3-base  fine-tuned for 25 epochs with class weights, 5 seeds   } predictions from the replication package
  SecureBERT       fine-tuned for 5 epochs with class weights, 5 seeds    } doi:10.5281/zenodo.23276178, copied
                                                                            to data/encoder_predictions/<run>/pred_latent.parquet;
                                                                            configurations selected on validation data there
Inputs: data/processed/cve_records.parquet, results/rq1/source_types.json, the predictions above
Output: results/rq2/reversal.json
"""

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rq2_benchmark import Encoded  # noqa: E402
from v4_labels import CUTOFF, label_types, load  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
PRED = ROOT / "results" / "rq2" / "predictions"
ENC = ROOT / "data" / "encoder_predictions"
B = 1000
SEED = 20261026
MODELS = {
    "TF-IDF + LR": [PRED / "temporal_tfidf_lr.parquet"],
    "DeBERTa-v3-base": [ENC / f"T2_temporal_deberta-v3-base_none_e25_cwinv_sqrt_s{s}" / "pred_latent.parquet" for s in range(5)],
    "SecureBERT": [ENC / f"T2_temporal_SecureBERT_none_e5_cwinv_sqrt_s{s}" / "pred_latent.parquet" for s in range(5)],
}


def main():
    df = load()
    df["label_type"] = df["source"].map(label_types()).fillna("other")
    test = df[df["pub"] >= CUTOFF].reset_index(drop=True)
    ids = test["cve_id"]
    truth = Encoded(test, "y_").band

    def bands(path):
        return Encoded(pd.read_parquet(path).set_index("cve_id").loc[ids].reset_index()).band

    pipe = bands(PRED / "temporal_pipeline_R.parquet") == truth
    correct = {m: np.array([bands(p) == truth for p in paths]) for m, paths in MODELS.items()}  # seeds x CVEs
    scopes = {"all": np.arange(len(test)), "non_derived": np.flatnonzero((test["label_type"] != "derived").to_numpy())}
    rng = np.random.default_rng(SEED)
    draws = {s: [rng.choice(idx, size=len(idx), replace=True) for _ in range(B)] for s, idx in scopes.items()}
    out = {"pipeline_band_acc": {s: float(pipe[idx].mean()) for s, idx in scopes.items()}, "models": {}}
    for m, c in correct.items():
        acc = c.mean(axis=0)  # per-CVE share of seeds with the correct band
        out["models"][m] = {"n_seeds": int(c.shape[0])}
        for s, idx in scopes.items():
            diff = acc[idx].mean() - pipe[idx].mean()
            bs = np.array([acc[ix].mean() - pipe[ix].mean() for ix in draws[s]])
            out["models"][m][s] = {"band_acc": float(acc[idx].mean()), "diff_vs_pipeline": float(diff),
                                   "ci95": [float(np.percentile(bs, 2.5)), float(np.percentile(bs, 97.5))]}
    (ROOT / "results" / "rq2" / "reversal.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
