"""Fine-tune a pretrained encoder with one classification head per CVSS v4.0 base metric on the temporal split.

The test predictions in data/encoder_predictions/ come from ten runs of this training procedure (encoders/run_encoders.sh):
  DeBERTa-v3-base  python encoders/train_encoder.py --model microsoft/deberta-v3-base --epochs 25 --seed S   (S = 0..4)
  SecureBERT       python encoders/train_encoder.py --model ehsanaghaei/SecureBERT --epochs 5 --seed S       (S = 0..4)
A GPU is needed. --smoke_test runs the whole pipeline on the CPU with a small randomly initialised model and 700 CVEs,
without downloading anything.

Data (encoders/common.py): CVEs with a CNA-provided v4.0 vector. Training: published before 2026, of which the latest
10% by publication date form the validation set; test: published from 2026 onwards. Input: the description followed by
the CWE identifiers, truncated to --max_len tokens.
Model: the encoder's first-token representation, dropout 0.1, and one linear head per metric.
Loss: mean over the eleven metrics of the class-weighted negative log-likelihood, with weights (N / (K n_c))^0.5 from
the training labels of each metric (counts smoothed by +1).
Optimiser: AdamW (weight decay 0.01) with learning rate --lr for the encoder and --head_lr for the heads, linear
warm-up over 6% of the steps and linear decay, gradient clipping at 1.0, bfloat16 autocast on GPUs that support it.
The epoch with the best mean macro-F1 on the validation set is kept.

Output: results/encoder/<run>/pred_latent.parquet (predicted v4.0 metrics, cve_id and source of every test CVE),
results.json (validation log and test metrics) and args.json. <run> is T2_temporal_<model>_none_e<epochs>_cwinv_sqrt_s<seed>,
the folder names used in data/encoder_predictions/.
"""

import argparse
import json
import random
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, Dataset

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import CUTOFF, M40, V40_METRICS, evaluate, load  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
LABELS = {k: V40_METRICS[k] for k in M40}
L2I = {k: {v: i for i, v in enumerate(vals)} for k, vals in LABELS.items()}
IGNORE = -100


def set_seed(seed):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)


def label_matrix(df):
    cols = [df["y_" + k].map(idx).fillna(IGNORE).astype(np.int64).values for k, idx in L2I.items()]
    return np.stack(cols, axis=1)


class CVEDataset(Dataset):
    def __init__(self, df, tokenizer, max_len):
        self.texts = df["text"].tolist()
        self.labels = label_matrix(df)
        self.tok, self.max_len = tokenizer, max_len

    def __len__(self):
        return len(self.texts)

    def __getitem__(self, i):
        return self.texts[i], self.labels[i]

    def collate(self, batch):
        texts, labels = zip(*batch)
        enc = self.tok(list(texts), truncation=True, max_length=self.max_len, padding=True, return_tensors="pt")
        enc["labels"] = torch.tensor(np.stack(labels))
        return enc


class MultiHeadCVSS(nn.Module):
    def __init__(self, encoder, hidden, dropout=0.1):
        super().__init__()
        self.encoder = encoder
        self.dropout = nn.Dropout(dropout)
        self.heads = nn.ModuleDict({k: nn.Linear(hidden, len(v)) for k, v in LABELS.items()})

    def forward(self, input_ids, attention_mask):
        out = self.encoder(input_ids=input_ids, attention_mask=attention_mask)
        h = self.dropout(out.last_hidden_state[:, 0])
        return {k: head(h) for k, head in self.heads.items()}


def masked_nll(log_probs, target, weight=None):
    """Negative log-likelihood that skips missing labels; 0 (with the graph kept) when a batch has none."""
    m = target != IGNORE
    return F.nll_loss(log_probs[m], target[m], weight=weight) if m.any() else log_probs.sum() * 0.0


def class_weights(train, device):
    out = {}
    for k in M40:
        counts = train["y_" + k].map(L2I[k]).dropna().astype(int).value_counts()
        n = np.array([counts.get(i, 0) for i in range(len(LABELS[k]))], dtype=float) + 1.0
        w = (n.sum() / (len(n) * n)) ** 0.5
        out[k] = torch.tensor(w, dtype=torch.float32, device=device)
    return out


def compute_loss(logits, labels, cw):
    return sum(masked_nll(F.log_softmax(logits[k], -1), labels[:, i], cw.get(k)) for i, k in enumerate(M40)) / len(M40)


@torch.no_grad()
def predict(model, loader, device, amp_dtype):
    model.eval()
    probs_all = {k: [] for k in M40}
    for batch in loader:
        batch = {k: v.to(device) for k, v in batch.items()}
        with torch.autocast(device_type=device.type, dtype=amp_dtype, enabled=amp_dtype is not None):
            logits = model(batch["input_ids"], batch["attention_mask"])
        for k in M40:
            probs_all[k].append(torch.softmax(logits[k].float(), -1).cpu().numpy())
    probs_all = {k: np.concatenate(v) for k, v in probs_all.items()}
    return pd.DataFrame({k: np.array(LABELS[k])[p.argmax(1)] for k, p in probs_all.items()})


def make_split(df):
    train, test = df[df["pub"] < CUTOFF], df[df["pub"] >= CUTOFF]
    train = train.sort_values("pub")
    n_val = max(1, int(0.1 * len(train)))
    return train.iloc[:-n_val], train.iloc[-n_val:], test


def smoke_components(texts):
    from tokenizers import Tokenizer, models, normalizers, pre_tokenizers, trainers
    from transformers import BertConfig, BertModel, PreTrainedTokenizerFast
    tk = Tokenizer(models.WordPiece(unk_token="[UNK]"))
    tk.normalizer = normalizers.BertNormalizer(lowercase=True)
    tk.pre_tokenizer = pre_tokenizers.BertPreTokenizer()
    tk.train_from_iterator(texts, trainers.WordPieceTrainer(vocab_size=3000, special_tokens=["[PAD]", "[UNK]", "[CLS]", "[SEP]"]))
    tok = PreTrainedTokenizerFast(tokenizer_object=tk, unk_token="[UNK]", pad_token="[PAD]", cls_token="[CLS]", sep_token="[SEP]")
    enc = BertModel(BertConfig(vocab_size=3000, hidden_size=64, num_hidden_layers=2, num_attention_heads=2, intermediate_size=128))
    return tok, enc, 64


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="microsoft/deberta-v3-base")
    ap.add_argument("--epochs", type=int, default=25)
    ap.add_argument("--lr", type=float, default=2e-5)
    ap.add_argument("--head_lr", type=float, default=1e-3)
    ap.add_argument("--batch_size", type=int, default=32)
    ap.add_argument("--max_len", type=int, default=256)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--smoke_test", action="store_true")
    args = ap.parse_args()
    if args.smoke_test:
        args.epochs, args.batch_size, args.model = 1, 16, "smoke-bert-tiny"

    run_name = f"T2_temporal_{Path(args.model).name}_none_e{args.epochs}_cwinv_sqrt_s{args.seed}"
    out_dir = ROOT / "results" / "encoder" / run_name
    set_seed(args.seed)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    amp_dtype = torch.bfloat16 if device.type == "cuda" and torch.cuda.is_bf16_supported() else None

    train, val, test = make_split(load())
    if args.smoke_test:
        train, val, test = train.sample(400, random_state=0), val.sample(100, random_state=0), test.sample(200, random_state=0)

    if args.smoke_test:
        tok, encoder, hidden = smoke_components(train["text"].tolist())
    else:
        from transformers import AutoModel, AutoTokenizer
        tok = AutoTokenizer.from_pretrained(args.model)
        # recent transformers versions load deberta-v3 weights in float16; AdamW on float16 weights produces NaN after
        # the first update, so the master weights are kept in float32 and the forward pass runs under bfloat16 autocast
        encoder = AutoModel.from_pretrained(args.model).float()
        hidden = encoder.config.hidden_size

    ds = {n: CVEDataset(d, tok, args.max_len) for n, d in [("train", train), ("val", val), ("test", test)]}
    loaders = {n: DataLoader(d, batch_size=args.batch_size, shuffle=(n == "train"), collate_fn=d.collate) for n, d in ds.items()}
    model = MultiHeadCVSS(encoder, hidden).to(device)
    enc_params = list(model.encoder.parameters())
    other = [p for n, p in model.named_parameters() if not n.startswith("encoder.")]
    opt = torch.optim.AdamW([{"params": enc_params, "lr": args.lr}, {"params": other, "lr": args.head_lr}], weight_decay=0.01)
    total = args.epochs * len(loaders["train"])
    sched = torch.optim.lr_scheduler.LambdaLR(opt, lambda s: min(1.0, (s + 1) / max(1, int(0.06 * total))) * max(0.0, (total - s) / total))
    cw = class_weights(train, device)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "args.json").write_text(json.dumps(vars(args), indent=1), encoding="utf-8")

    best_f1, best_epoch, best_state, log = -1.0, -1, None, []
    t0, nan_steps = time.time(), 0
    for epoch in range(args.epochs):
        model.train()
        for step, batch in enumerate(loaders["train"]):
            batch = {k: v.to(device) for k, v in batch.items()}
            with torch.autocast(device_type=device.type, dtype=amp_dtype, enabled=amp_dtype is not None):
                logits = model(batch["input_ids"], batch["attention_mask"])
            loss = compute_loss({k: v.float() for k, v in logits.items()}, batch["labels"], cw)
            nan_steps = nan_steps + 1 if not torch.isfinite(loss) else 0
            if nan_steps >= 20:
                raise RuntimeError(f"loss was NaN or infinite for {nan_steps} consecutive steps: {run_name}")
            opt.zero_grad(set_to_none=True)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            sched.step()
            if step % 100 == 0:
                print(f"epoch {epoch} step {step}/{len(loaders['train'])} loss {loss.item():.4f} ({time.time() - t0:.0f}s)", flush=True)
        val_res = evaluate(val.reset_index(drop=True), predict(model, loaders["val"], device, amp_dtype))
        log.append({"epoch": epoch, "val_mean_macro_f1": val_res["mean_macro_f1"], "val_band_acc": val_res["band_acc"],
                    "val_under_rate": val_res["under_rate"]})
        print(f"epoch {epoch} val mean macro-F1 {val_res['mean_macro_f1']:.4f}", flush=True)
        if val_res["mean_macro_f1"] > best_f1:
            best_f1, best_epoch = val_res["mean_macro_f1"], epoch
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}

    model.load_state_dict(best_state)
    test_r = test.reset_index(drop=True)
    pred = predict(model, loaders["test"], device, amp_dtype)
    pred.assign(cve_id=test_r["cve_id"], source=test_r["source"]).to_parquet(out_dir / "pred_latent.parquet", index=False)
    results = {"val_log": log, "best_epoch": best_epoch, "val_best_mean_f1": best_f1, "test": evaluate(test_r, pred)}
    (out_dir / "results.json").write_text(json.dumps(results, indent=1, default=float), encoding="utf-8")
    print(f"test mean macro-F1 {results['test']['mean_macro_f1']:.4f}, band accuracy {results['test']['band_acc']:.4f}; "
          f"saved to {out_dir}", flush=True)


if __name__ == "__main__":
    main()
