# Data notices

## CVE List

The tables written by `src/extract_cve_records.py` and `src/extract_snapshot.py` (included in the Zenodo archive, doi:10.5281/zenodo.23718895), and the CVE identifiers in the result files, are derived from the CVE List (release `2026-09-25_all_CVEs_at_midnight` of <https://github.com/CVEProject/cvelistV5>).

Copyright © 1999-2026, The MITRE Corporation.

CVE Usage: MITRE hereby grants you a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable copyright license to reproduce, prepare derivative works of, publicly display, publicly perform, sublicense, and distribute Common Vulnerabilities and Exposures (CVE™). Any copy you make for such purposes is authorized provided that you reproduce MITRE's copyright designation and this license in any such copy.

(Terms of Use: <https://www.cve.org/Legal/TermsOfUse>.)

## National Vulnerability Database

`data/nvd_records.parquet` is extracted from the NVD JSON 2.0 data feeds (<https://nvd.nist.gov/vuln/data-feeds>), downloaded on 26 October 2026. `data/nvd_cvss_history.parquet` is extracted from the NVD CVE Change History API (<https://services.nvd.nist.gov/rest/json/cvehistory/2.0>). This product uses data from the NVD API but is not endorsed or certified by the NVD.

## CISA Vulnrichment

`data/asof_versions.jsonl` and `data/vulnrichment_commits.tsv` are derived from the public history of <https://github.com/cisagov/vulnrichment>, which is dedicated to the public domain under CC0 1.0 Universal.

## Encoder predictions

`data/encoder_predictions/` is taken from the replication package doi:10.5281/zenodo.23276178 (MIT License).
