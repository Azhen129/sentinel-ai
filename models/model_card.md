# Sentinel AI model card

This artifact is a reproducible learning benchmark, not a validated production IDS.

## Provenance

Dataset: [UCI KDD Cup 1999](https://archive.ics.uci.edu/dataset/130/kdd), 10% subset.
Authors: Stolfo, Fan, Lee, Prodromidis and Chan (1999). DOI: 10.24432/C51C7N.
UCI lists the dataset as CC BY 4.0. Source SHA-256: `8045aca0d84e70e622d1148d7df782496f6333bf6eb979a1b0837c42a9fd9561`.
Downloaded/trained at: 2026-10-29T12:18:52.241487+00:00. scikit-learn: 1.6.1. Seed: 42.
Downloaded via the checksum-verified scikit-learn mirror (https://ndownloader.figshare.com/files/5976042); the original UCI
archive returned HTTP 403 in this environment. Expected SHA-256 comes from the official
scikit-learn `sklearn.datasets._kddcup99.ARCHIVE_10_PERCENT` definition.
The benchmark itself contains simulated historical traffic with real published labels; it is separate from our small synthetic demo.

## Method and leakage controls

Exact full-row duplicates were removed. Records sharing all six observable canonical features
are assigned to the same group. A seeded split assigns approximately 60/20/20 percent of
distinct feature groups to training, validation and test; row fractions vary because groups stay intact. There are
zero feature-group overlaps. Only benign training rows fit preprocessing and the 160-tree
Isolation Forest. Numeric features are log1p transformed and robust scaled; categories are
one-hot encoded with unknown categories ignored. IP addresses, timestamps, labels, scenario
names, IDs and post-detection fields never enter inference.

Threshold 0.592961 was fixed at the benign validation 98th score percentile. No test labels
select the threshold or parameters. This is a random group holdout, not a temporal evaluation.
Training attacks are excluded rather than used for tuning. No hyperparameter search was run.

## Actual held-out results

19,887 test records: 17,089 benign, 2,798 attacks.
Precision 0.510426; recall 0.201215; F1 0.288644; benign false-positive rate 0.031599.
ROC-AUC 0.853983; average precision 0.472063.

Confusion matrix (rows actual benign/attack; columns predicted benign/attack):

| Actual / predicted | Benign | Attack |
|---|---:|---:|
| Benign | 16549 | 540 |
| Attack | 2235 | 563 |

## False positives and explanations

540 benign test records were flagged. Frequent false-positive services: `{"private": 397, "urp_i": 123, "ecr_i": 7, "domain_u": 7, "telnet": 3, "finger": 1, "IRC": 1, "other": 1}`.
The model compares individual records. It cannot see scanning sequences or host context;
those require the separately labeled rules. Explanations list outlying feature ranges and
unseen benign categories. These are supporting triage indicators, not exact per-tree attribution.

## Limitations

- KDD Cup 1999 is an old benchmark built from simulated military-network traffic; it is not contemporary production evidence.
- Grouping prevents identical observable feature vectors crossing splits, but there are no usable timestamps or hosts for temporal/host holdout.
- Only duration, directional byte volumes, protocol, service and state are shared with Zeek. Payload and rolling-host features are excluded.
- TLS/HTTPS is mapped to the legacy HTTP service; DNS is mapped to domain/domain_u. These approximations introduce distribution shift.
- The threshold targets a 2% benign validation alert rate, not a guaranteed production false-positive rate.
- Anomalies are unusual traffic, not proof of an attack. Indicator explanations are range/category heuristics, not causal feature attributions.
- Synthetic replay measures the application workflow; these benchmark metrics do not describe the replay or a private network.
- No claim is made about new attack families, encrypted payload inspection, or zero-day detection.

## Reproduce

Use the platform-specific virtual-environment commands in the [training instructions](../README.md#reproduce-training). They use the pinned dependencies and the included preprocessing pipeline.

Or supply the original compressed file with `--data data/raw/kddcup.data_10_percent.gz`.
The download is retained under ignored `data/raw/`; it is not needed to run the application.
Only load trusted model artifacts: joblib/pickle can execute code. Models cannot be uploaded through the API.

The loader requires matching artifact/evaluation SHA-256 fingerprints, model and feature schema,
and the exact pinned scikit-learn version. These checks detect accidental mismatch; they are
not a signature or a substitute for trusted local files. Invalid or missing model files
trigger explicit rule-only fallback.
