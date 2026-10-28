#!/usr/bin/env bash
# Fine-tunes the two encoders of the paper, five seeds each, on a GPU (see encoders/train_encoder.py for the settings).
# Run from the repository root after steps 1 and 2 of README.md:  bash encoders/run_encoders.sh
# The runs are written to results/encoder/<run>/. src/rq2_reversal.py reads the predictions stored in
# data/encoder_predictions/<run>/pred_latent.parquet; copy a new pred_latent.parquet there to use it. GPU training is
# not bit-for-bit deterministic, so new runs can differ slightly from the stored predictions.
set -euo pipefail
for SEED in 0 1 2 3 4; do
  python encoders/train_encoder.py --model microsoft/deberta-v3-base --epochs 25 --seed "$SEED"
  python encoders/train_encoder.py --model ehsanaghaei/SecureBERT --epochs 5 --seed "$SEED"
done
