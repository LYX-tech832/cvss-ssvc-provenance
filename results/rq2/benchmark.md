# RQ2: label sources and the evaluation of automated v4.0 assessment (temporal split)

Training 16,097 CVEs (before 2026); test 21,900; v3.1 pool for the pipeline 110,524.

| Method | Scope | n | Macro-F1 | v4-F1 | Exact | MAE | Band | Under | H+C rec. | kappa |
|---|---|---|---|---|---|---|---|---|---|---|
| majority | all | 21,900 | 0.276 | 0.335 | 0.051 | 1.46 | 0.469 | 0.492 | 0.000 | 0.00 |
| majority | non_derived | 16,749 | 0.258 | 0.327 | 0.002 | 1.49 | 0.365 | 0.593 | 0.000 | 0.00 |
| majority | derived | 5,151 | 0.317 | 0.359 | 0.208 | 1.36 | 0.806 | 0.164 | 0.000 | 0.00 |
| majority | undetected | 7,242 | 0.261 | 0.336 | 0.003 | 1.44 | 0.343 | 0.635 | 0.000 | 0.00 |
| majority | v4_only | 4,264 | 0.259 | 0.323 | 0.001 | 1.47 | 0.401 | 0.554 | 0.000 | 0.00 |
| majority | other | 5,243 | 0.253 | 0.317 | 0.002 | 1.56 | 0.367 | 0.566 | 0.000 | 0.00 |
| tfidf_lr | all | 21,900 | 0.605 | 0.522 | 0.237 | 1.33 | 0.598 | 0.136 | 0.854 | 0.39 |
| tfidf_lr | non_derived | 16,749 | 0.547 | 0.512 | 0.171 | 1.53 | 0.504 | 0.155 | 0.870 | 0.25 |
| tfidf_lr | derived | 5,151 | 0.624 | 0.420 | 0.451 | 0.71 | 0.904 | 0.074 | 0.673 | 0.67 |
| tfidf_lr | undetected | 7,242 | 0.580 | 0.551 | 0.236 | 1.11 | 0.572 | 0.096 | 0.924 | 0.33 |
| tfidf_lr | v4_only | 4,264 | 0.488 | 0.451 | 0.125 | 2.01 | 0.436 | 0.237 | 0.799 | 0.19 |
| tfidf_lr | other | 5,243 | 0.524 | 0.478 | 0.118 | 1.71 | 0.466 | 0.171 | 0.842 | 0.20 |
| pipeline_R | all | 21,900 | 0.565 | 0.480 | 0.167 | 1.39 | 0.541 | 0.127 | 0.858 | 0.29 |
| pipeline_R | non_derived | 16,749 | 0.546 | 0.470 | 0.164 | 1.31 | 0.539 | 0.150 | 0.851 | 0.28 |
| pipeline_R | derived | 5,151 | 0.539 | 0.419 | 0.177 | 1.66 | 0.546 | 0.053 | 0.947 | 0.20 |
| pipeline_R | undetected | 7,242 | 0.579 | 0.514 | 0.226 | 1.03 | 0.594 | 0.121 | 0.879 | 0.35 |
| pipeline_R | v4_only | 4,264 | 0.501 | 0.456 | 0.104 | 1.53 | 0.486 | 0.180 | 0.816 | 0.21 |
| pipeline_R | other | 5,243 | 0.524 | 0.419 | 0.128 | 1.51 | 0.506 | 0.165 | 0.835 | 0.23 |

Base rate (share of the most frequent band among the test labels): all 46.9% (n=21,900); non_derived 45.8% (n=16,749); derived 80.6% (n=5,151); undetected 49.9% (n=7,242); v4_only 41.6% (n=4,264); other 43.4% (n=5,243)

Source profiles (all v4.0 labels): VulDB: 142 distinct vectors, most frequent 24.3% (n=12,882); VulnCheck: 753 distinct vectors, most frequent 8.3% (n=7,429); GitHub: 1,039 distinct vectors, most frequent 4.8% (n=5,129); derived: 142 distinct vectors, most frequent 24.3% (n=12,882); undetected: 1,191 distinct vectors, most frequent 8.0% (n=10,154); v4_only: 1,295 distinct vectors, most frequent 5.1% (n=6,800); other: 2,075 distinct vectors, most frequent 3.2% (n=8,161)

TF-IDF + LR minus pipeline (rule R), paired bootstrap 95% intervals:
- all: band accuracy +0.057 [+0.051, +0.065]; mean macro-F1 +0.040 [+0.036, +0.044]
- non_derived: band accuracy -0.035 [-0.043, -0.027]; mean macro-F1 +0.001 [-0.004, +0.005]
