# CNA-provided CVSS assessments, SSVC-based remediation deadlines and severity prediction benchmarks

Code, derived data and results for the paper *How CNA-Provided CVSS Assessments Shape SSVC-Based Remediation Deadlines and Severity Prediction Benchmarks* (Yuxin Liu, Jikui Wang, Yuxuan Ye). The paper has not been published yet; its reference will be added here once it is.

Archived version (including the two large tables that are not in this repository): <https://doi.org/10.5281/zenodo.23718895>.

The paper asks three research questions:

- **RQ1** Do CISA's SSVC decisions track the CNA assessment available when CISA decided?
- **RQ2** How much do BOD 26-04 remediation tiers change when another assessor's vector is used, and where does the change come from?
- **RQ3** How does the provenance of CNA-provided labels change the results of severity prediction benchmarks?

## Where each result comes from

The script and result folder names follow the order in which the analyses were written, not the order of the paper. This table maps them:

| Paper | Scripts | Result files |
|---|---|---|
| RQ1 (Section 5, Table S1, Table S2) | `rq3_stale_copies.py`, `rq3_disagreement.py`, `rq3_stale_decisions.py`, `rq3_selection.py` (uses `covariates.py`) | `results/rq3/stale_copies.json`, `disagreement.json`, `stale_decisions.json`, `selection.json` |
| RQ2 (Section 6, Fig. 2, Table S3, Table S4) | `rq3_tiers.py`, `rq1_nvd_agreement.py` | `results/rq3/tiers.json`, `results/rq1/nvd_agreement.json` |
| RQ1 and RQ2 by time of the NVD's assessment (Sections 5 and 6, Tables S11 and S12) | `fetch_nvd_history.py`, `rq3_nvd_timing.py` | `results/rq3/nvd_timing.json` |
| RQ3 (Section 7, Fig. 3, Fig. S1, Tables S5 to S10) | `rq1_provenance.py`, `rq2_benchmark.py`, `rq2_reversal.py`, `rq2_robustness.py`, `rq2_pairing.py` | `results/rq1/provenance.json`, `source_types.json`, `results/rq2/` |

## Contents

| Path | What it is |
|---|---|
| `src/` | All scripts (Python 3.14). The description at the top of each script states its inputs, method and outputs. |
| `data/asof_versions.jsonl` | For 49,380 CVEs, the Vulnrichment copy of the record that carries CISA's SSVC decision, retrieved from the repository history (written by `src/fetch_asof_versions.py`). |
| `data/vulnrichment_commits.tsv` | All commits of the Vulnrichment repository with their dates (written by `src/vulnrichment_commits.py`). |
| `data/nvd_records.parquet` | The NVD's own (Primary) CVSS vectors extracted from the NVD JSON 2.0 feeds downloaded on 26 October 2026 (written by `src/extract_nvd.py`). The feeds change over time, so this table is provided. |
| `data/nvd_cvss_history.parquet` | The NVD's CVSS v3.1 assessment events (Initial Analysis, Reanalysis, Modified Analysis) from 1 June 2022 to 26 October 2026, with their times, from the NVD CVE Change History API (written by `src/fetch_nvd_history.py`). |
| `data/encoder_predictions/` | Test-set predictions of two fine-tuned encoders (DeBERTa-v3-base, SecureBERT; five seeds each), taken from the replication package doi:10.5281/zenodo.23276178. |
| `data/*.meta.json`, `data/processed/*.json` | Input hashes and row counts of the extracted tables. |
| `results/rq1/`, `results/rq2/`, `results/rq3/` | All results, as JSON and Markdown. |

The two tables extracted from the CVE List snapshot (`data/processed/cve_records.parquet`, `data/snapshot_records.parquet`) are not in this repository because of their size. They are included in the Zenodo archive, and steps 1 and 2 below rebuild them from the public snapshot.

## Inputs not included

- CVE List snapshot of 25 September 2026: release `2026-09-25_all_CVEs_at_midnight` of <https://github.com/CVEProject/cvelistV5> (SHA-256 of the release file in `data/processed/cve_records.provenance.json`).
- NVD JSON 2.0 yearly feeds: <https://nvd.nist.gov/vuln/data-feeds> (`src/fetch_nvd_feeds.py` downloads the current ones; the extracted table of the study is `data/nvd_records.parquet`).
- CISA Vulnrichment: <https://github.com/cisagov/vulnrichment> (read through its public history; no account or token needed).

## Reproduction

Install the dependencies with `pip install -r requirements.txt`, then run from the repository root. With the two tables from the Zenodo archive placed at the paths above, steps 1 and 2 can be skipped.

| Step | Command | Writes | Time |
|---|---|---|---|
| 1 | `python src/extract_cve_records.py <path to 2026-09-25_all_CVEs_at_midnight.zip.zip>` | `data/processed/cve_records.parquet` | 1 min |
| 2 | `python src/extract_snapshot.py <zip file with the cves/ directory of the same snapshot>` | `data/snapshot_records.parquet` | a few min |
| 3 (optional) | `python src/fetch_nvd_feeds.py` and `python src/extract_nvd.py` | `data/nvd_records.parquet` (newer NVD data than the study's) | 10 min |
| 4 (optional) | `python src/vulnrichment_commits.py` and `python src/fetch_asof_versions.py --n 49380` | `data/vulnrichment_commits.tsv`, `data/asof_versions.jsonl` | about two days (network) |
| 5 | `python src/rq1_provenance.py` and `python src/rq1_nvd_agreement.py` | `results/rq1/` | 2 min |
| 6 | `python src/rq2_benchmark.py`, `python src/rq2_pairing.py`, `python src/rq2_reversal.py`, `python src/rq2_robustness.py` | `results/rq2/` | 15 min |
| 7 | `python src/rq3_stale_copies.py`, `python src/rq3_disagreement.py`, `python src/rq3_tiers.py`, `python src/rq3_stale_decisions.py`, `python src/rq3_selection.py` | `results/rq3/` | 10 min |
| 7b (optional) | `python src/fetch_nvd_history.py` | `data/nvd_cvss_history.parquet` | about 1 h (network) |
| 7c | `python src/rq3_nvd_timing.py` | `results/rq3/nvd_timing.json` | 1 min |
| 8 | `python src/figures.py` | `paper/figures/` | 1 min |
| 9 | `python src/supplementary_tables.py` | `paper/supplementary_tables.tex` (Tables S1 to S12) | seconds |

Steps 3, 4 and 7b are optional: the provided `data/nvd_records.parquet`, `data/asof_versions.jsonl` and `data/nvd_cvss_history.parquet` are the data of the study. `src/rq2_robustness.py` reuses the cached predictions in `results/rq2/tfidf_sensitivity/` and then takes seconds; delete that folder to refit the 18 TF-IDF models (about one hour). Bootstrap intervals use fixed seeds and are reproduced exactly.

## Notes

- The code was developed with the assistance of an AI tool (Claude Code), as stated in the paper's declaration on generative AI.

## License

Code and results: MIT (see `LICENSE`). Data notices: see `NOTICE.md`.
