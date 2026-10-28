# Pairing provenance (approximate D4: NVD publication 2023-11-01 to 2026-07-12, both v3.1 and v4.0 entries; 25,377 CVEs)

Top sources of the v4.0 labels: cna@vuldb.com 11,254 (44.3%); disclosure@vulncheck.com 4,100 (16.2%); security-advisories@github.com 3,011 (11.9%); ics-cert@hq.dhs.gov 618 (2.4%); productcert@siemens.com 547 (2.2%)

| Setting | n | VulDB share | Rule-R band accuracy | Underestimation | Exact vector |
|---|---|---|---|---|---|
| cross-source: NVD v3.1 with CNA v4.0 | 15,329 | 45.3% | 45.5% | 4.9% | 12.8% |
| same-source: CNA v3.1 with CNA v4.0 | 18,217 | 61.8% | 96.2% | 0.4% | 81.1% |
| same-source, without VulDB | 6,963 | 0.0% | 90.2% | 1.1% | 56.9% |
| strict pairing: NVD v3.1 | 8,310 | 83.6% | 30.0% | 0.9% | 5.0% |
| strict pairing: CNA v3.1 | 8,310 | 83.6% | 98.5% | 0.3% | 87.5% |
| strict pairing without VulDB: NVD v3.1 | 1,360 | 0.0% | 65.1% | 5.3% | 15.4% |
| strict pairing without VulDB: CNA v3.1 | 1,360 | 0.0% | 91.0% | 1.7% | 54.4% |

On the 8,310 strictly paired CVEs, the NVD's and the CNA's v3.1 vectors are identical for 6.2%.
