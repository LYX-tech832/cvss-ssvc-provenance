# CNA-provided CVSS assessments, severity prediction benchmarks and SSVC-based remediation deadlines

Code, derived data and results for the paper *How CNA-Provided CVSS Assessments Shape SSVC-Based Remediation Deadlines and Severity Prediction Benchmarks* (Yuxin Liu, Jikui Wang, Yuxuan Ye). The paper has not been published yet; its reference will be added here once it is.

The study follows CVSS vectors written by CVE Numbering Authorities (CNAs) into two downstream uses:

- **RQ1** How do CNAs implement CVSS v4.0, and how far do their assessments agree with the NVD's?
- **RQ2** How does the composition of label sources change the evaluation of automated CVSS v4.0 assessment?
- **RQ3** Do CISA's SSVC decisions (Vulnrichment) depend on the CNA vector that CISA could see when it decided, and how much would BOD 26-04 remediation tiers change with another assessor's vector?

## Contents

| Path | What it is |
|---|---|
| `src/` | All scripts (Python 3.14). The description at the top of each script states its inputs, method and outputs. |
| `data/asof_versions.jsonl` | For 49,380 CVEs, the Vulnrichment copy of the record that carries CISA's SSVC decision, retrieved from the repository history (written by `src/fetch_asof_versions.py`). |
| `data/vulnrichment_commits.tsv` | All commits of the Vulnrichment repository with their dates (written by `src/vulnrichment_commits.py`). |
| `data/nvd_records.parquet` | The NVD's own (Primary) CVSS vectors extracted from the NVD JSON 2.0 feeds downloaded on 26 October 2026 (written by `src/extract_nvd.py`). The feeds change over time, so this table is provided. |
| `data/encoder_predictions/` | Test-set predictions of two fine-tuned encoders (DeBERTa-v3-base, SecureBERT; five seeds each), taken from the replication package of an earlier study by the same authors (doi:10.5281/zenodo.23276178). |
| `data/*.meta.json`, `data/processed/*.json` | Input hashes and row counts of the extracted tables. |
| `results/rq1/`, `results/rq2/`, `results/rq3/` | All results, as JSON and Markdown. |

The two tables extracted from the CVE List snapshot (`data/processed/cve_records.parquet`, `data/snapshot_records.parquet`) are not included because of their size; the scripts below rebuild them from the public snapshot.

## Inputs not included

- CVE List snapshot of 25 September 2026: release `2026-09-25_all_CVEs_at_midnight` of <https://github.com/CVEProject/cvelistV5> (SHA-256 of the release file in `data/processed/cve_records.provenance.json`).
- NVD JSON 2.0 yearly feeds: <https://nvd.nist.gov/vuln/data-feeds> (`src/fetch_nvd_feeds.py` downloads the current ones; the extracted table of the study is `data/nvd_records.parquet`).
- CISA Vulnrichment: <https://github.com/cisagov/vulnrichment> (read through its public history; no account or token needed).

## Reproduction

Install the dependencies with `pip install -r requirements.txt`, then run from the repository root:

| Step | Command | Writes | Time |
|---|---|---|---|
| 1 | `python src/extract_cve_records.py <path to 2026-09-25_all_CVEs_at_midnight.zip.zip>` | `data/processed/cve_records.parquet` | 1 min |
| 2 | `python src/extract_snapshot.py <zip file with the cves/ directory of the same snapshot>` | `data/snapshot_records.parquet` | a few min |
| 3 (optional) | `python src/fetch_nvd_feeds.py` and `python src/extract_nvd.py` | `data/nvd_records.parquet` (newer NVD data than the study's) | 10 min |
| 4 (optional) | `python src/vulnrichment_commits.py` and `python src/fetch_asof_versions.py --n 49380` | `data/vulnrichment_commits.tsv`, `data/asof_versions.jsonl` | about two days (network) |
| 5 | `python src/rq1_provenance.py` and `python src/rq1_nvd_agreement.py` | `results/rq1/` | 2 min |
| 6 | `python src/rq2_benchmark.py`, `python src/rq2_pairing.py`, `python src/rq2_reversal.py` | `results/rq2/` | 15 min |
| 7 | `python src/rq3_stale_copies.py`, `python src/rq3_disagreement.py`, `python src/rq3_tiers.py`, `python src/rq3_stale_decisions.py` | `results/rq3/` | 10 min |
| 8 | `python src/figures.py` | `paper/figures/` | 1 min |

Steps 3 and 4 are optional: the provided `data/nvd_records.parquet` and `data/asof_versions.jsonl` are the data of the study. Bootstrap intervals use fixed seeds and are reproduced exactly.

## License

Code and results: MIT (see `LICENSE`). Data notices: see `NOTICE.md`.
