"""Reproducible KDD99 benchmark. No synthetic data or test-set threshold tuning.

python scripts/train_model.py --download --output models
python scripts/train_model.py --data data/raw/kddcup.data_10_percent.gz --output models
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path
import sys
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score, confusion_matrix, precision_recall_fscore_support, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.preprocessing import OneHotEncoder, RobustScaler

from detection.features import CATEGORICAL, FEATURES, NUMERIC, feature_frame, feature_group
from detection.ml import ARTIFACT_SCHEMA_VERSION

CANONICAL_URL = "https://kdd.ics.uci.edu/databases/kddcup99/kddcup.data_10_percent.gz"
# Same archive/checksum used by sklearn.datasets.fetch_kddcup99 (1.6.1).
DATA_URL = "https://ndownloader.figshare.com/files/5976042"
EXPECTED_SHA256 = "8045aca0d84e70e622d1148d7df782496f6333bf6eb979a1b0837c42a9fd9561"
SEED = 42
NORMAL_LABEL = "normal."


def load_records(path: Path) -> tuple[list[dict], np.ndarray, dict]:
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8") as handle:
        full = pd.read_csv(handle, header=None, dtype=str)
    if full.shape[1] != 42:
        raise ValueError(f"Expected 42 KDD columns, found {full.shape[1]}")
    original_count = len(full)
    full = full.drop_duplicates().reset_index(drop=True)
    records = [{
        "duration": row[0], "protocol": row[1], "service": row[2], "status": row[3],
        "bytes_sent": row[4], "bytes_received": row[5],
    } for row in full.itertuples(index=False, name=None)]
    labels = (full[41].str.strip() != NORMAL_LABEL).astype(int).to_numpy()
    return records, labels, {
        "original_rows": original_count, "deduplicated_rows": len(full),
        "exact_duplicates_removed": original_count - len(full),
        "benign_rows": int((labels == 0).sum()), "attack_rows": int(labels.sum()),
    }


def grouped_split(records: list[dict], seed: int = SEED) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Group by all inference features, preventing same observable record crossing splits."""
    groups = np.array([feature_group(row) for row in records])
    indices = np.arange(len(records))
    outer = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=seed)
    train_validation, test = next(outer.split(indices, groups=groups))
    inner = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=seed + 1)
    train_local, validation_local = next(inner.split(train_validation, groups=groups[train_validation]))
    train, validation = train_validation[train_local], train_validation[validation_local]
    assert not set(groups[train]) & set(groups[validation])
    assert not set(groups[train]) & set(groups[test])
    assert not set(groups[validation]) & set(groups[test])
    return train, validation, test, groups


def train(path: Path, output: Path) -> dict:
    actual_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual_sha256 != EXPECTED_SHA256:
        raise ValueError("Dataset checksum differs from the documented KDD99 10% archive. Download the original with --download.")
    records, labels, counts = load_records(path)
    frame = feature_frame(records)
    train_indices, validation_indices, test_indices, groups = grouped_split(records)
    benign_train = train_indices[labels[train_indices] == 0]
    benign_validation = validation_indices[labels[validation_indices] == 0]
    if min(len(benign_train), len(benign_validation)) < 20:
        raise ValueError("Need at least 20 benign train and validation records")
    preprocessor = ColumnTransformer([
        ("numeric", RobustScaler(), NUMERIC),
        ("categorical", OneHotEncoder(handle_unknown="ignore", sparse_output=False), CATEGORICAL),
    ], sparse_threshold=0)
    train_matrix = preprocessor.fit_transform(frame.iloc[benign_train])
    estimator = IsolationForest(
        n_estimators=160, max_samples=256, contamination="auto", random_state=SEED,
        n_jobs=1,
    ).fit(train_matrix)
    validation_scores = -estimator.score_samples(preprocessor.transform(frame.iloc[benign_validation]))
    threshold = float(np.quantile(validation_scores, 0.98))
    scores = -estimator.score_samples(preprocessor.transform(frame.iloc[test_indices]))
    predicted = (scores > threshold).astype(int)
    actual = labels[test_indices]
    precision, recall, f1, _ = precision_recall_fscore_support(actual, predicted, average="binary", zero_division=0)
    matrix = confusion_matrix(actual, predicted, labels=[0, 1])
    tn, fp, fn, tp = [int(n) for n in matrix.ravel()]
    benign_ranges = {
        name: {"p01": float(frame.iloc[benign_train][name].quantile(0.01)),
               "median": float(frame.iloc[benign_train][name].median()),
               "p99": float(frame.iloc[benign_train][name].quantile(0.99))}
        for name in NUMERIC
    }
    benign_categories = {name: sorted(frame.iloc[benign_train][name].unique().tolist()) for name in CATEGORICAL}
    false_positive_indices = test_indices[(actual == 0) & (predicted == 1)]
    fp_services = pd.Series([records[index]["service"] for index in false_positive_indices], dtype=str).value_counts().head(8).to_dict()
    limits = [
        "KDD Cup 1999 is an old benchmark built from simulated military-network traffic; it is not contemporary production evidence.",
        "Grouping prevents identical observable feature vectors crossing splits, but there are no usable timestamps or hosts for temporal/host holdout.",
        "Only duration, directional byte volumes, protocol, service and state are shared with Zeek. Payload and rolling-host features are excluded.",
        "TLS/HTTPS is mapped to the legacy HTTP service; DNS is mapped to domain/domain_u. These approximations introduce distribution shift.",
        "The threshold targets a 2% benign validation alert rate, not a guaranteed production false-positive rate.",
        "Anomalies are unusual traffic, not proof of an attack. Indicator explanations are range/category heuristics, not causal feature attributions.",
        "Synthetic replay measures the application workflow; these benchmark metrics do not describe the replay or a private network.",
        "No claim is made about new attack families, encrypted payload inspection, or zero-day detection.",
    ]
    metrics = {
        "name": "Isolation Forest", "version": "1.0.0", "model_version": "1.0.0", "status": "ready", "model_loaded": True,
        "dataset": "UCI KDD Cup 1999 — 10% subset", "dataset_type": "public historical benchmark",
        "source_url": DATA_URL, "canonical_source_url": CANONICAL_URL,
        "download_note": "Original UCI archive returned HTTP 403 in this environment; used the checksum-verified mirror distributed by scikit-learn.",
        "citation_url": "https://doi.org/10.24432/C51C7N",
        "license": "CC BY 4.0 (UCI dataset catalog)",
        "sha256": actual_sha256,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "random_seed": SEED, "sklearn_version": sklearn.__version__,
        "algorithm": "IsolationForest(n_estimators=160, max_samples=256)",
        "features": FEATURES, "feature_count": len(FEATURES), "training_mode": "benign-only unsupervised",
        "training_samples": int(len(benign_train)),
        "threshold": threshold, "threshold_selection": "98th percentile of benign validation anomaly scores; fixed before test evaluation",
        "split_method": "60/20/20 of distinct feature groups, seeded holdout by SHA-256 of all canonical inference features; row fractions vary; exact full-row deduplication before split",
        "counts": {**counts, "feature_groups": int(len(set(groups))),
                   "train_partition": int(len(train_indices)), "train_benign_used": int(len(benign_train)),
                   "validation_partition": int(len(validation_indices)), "validation_benign_used": int(len(benign_validation)),
                   "test": int(len(test_indices)), "test_benign": int((actual == 0).sum()), "test_attacks": int(actual.sum())},
        "split": {"train": int(len(train_indices)), "validation": int(len(validation_indices)), "test": int(len(test_indices)), "feature_group_overlap": 0},
        "metrics": {"precision": float(precision), "recall": float(recall), "f1": float(f1),
                    "false_positive_rate": fp / (fp + tn) if fp + tn else 0,
                    "accuracy": float((predicted == actual).mean()),
                    "roc_auc": float(roc_auc_score(actual, scores)),
                    "average_precision": float(average_precision_score(actual, scores))},
        "confusion_matrix": matrix.tolist(),
        "confusion_matrix_labels": ["benign", "attack"],
        "confusion_matrix_orientation": "rows actual, columns predicted",
        "confusion": {"true_negative": tn, "false_positive": fp, "false_negative": fn, "true_positive": tp},
        "false_positive_analysis": {"count": fp, "top_services": {str(k): int(v) for k, v in fp_services.items()},
                                    "interpretation": "Unusual benign services and traffic volumes can be flagged; triage is required."},
        "benign_ranges_log1p": benign_ranges, "limitations": limits,
        "explanation_method": "Numeric benign percentile and unseen-category heuristics, plus aggregate Isolation Forest score",
    }
    output.mkdir(parents=True, exist_ok=True)
    joblib.dump({"schema_version": ARTIFACT_SCHEMA_VERSION, "model_version": metrics["model_version"],
                 "sklearn_version": sklearn.__version__, "features": FEATURES,
                 "preprocessor": preprocessor, "estimator": estimator, "threshold": threshold,
                 "benign_ranges": benign_ranges, "benign_categories": benign_categories},
                output / "isolation_forest.joblib", compress=3)
    metrics["artifact_schema_version"] = ARTIFACT_SCHEMA_VERSION
    metrics["artifact_sha256"] = hashlib.sha256((output / "isolation_forest.joblib").read_bytes()).hexdigest()
    (output / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    card = f"""# Sentinel AI model card

This artifact is a reproducible learning benchmark, not a validated production IDS.

## Provenance

Dataset: [UCI KDD Cup 1999](https://archive.ics.uci.edu/dataset/130/kdd), 10% subset.
Authors: Stolfo, Fan, Lee, Prodromidis and Chan (1999). DOI: 10.24432/C51C7N.
UCI lists the dataset as CC BY 4.0. Source SHA-256: `{metrics['sha256']}`.
Downloaded/trained at: {metrics['trained_at']}. scikit-learn: {sklearn.__version__}. Seed: 42.
Downloaded via the checksum-verified scikit-learn mirror ({DATA_URL}); the original UCI
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

Threshold {threshold:.6f} was fixed at the benign validation 98th score percentile. No test labels
select the threshold or parameters. This is a random group holdout, not a temporal evaluation.
Training attacks are excluded rather than used for tuning. No hyperparameter search was run.

## Actual held-out results

{len(test_indices):,} test records: {(actual == 0).sum():,} benign, {actual.sum():,} attacks.
Precision {precision:.6f}; recall {recall:.6f}; F1 {f1:.6f}; benign false-positive rate {metrics['metrics']['false_positive_rate']:.6f}.
ROC-AUC {metrics['metrics']['roc_auc']:.6f}; average precision {metrics['metrics']['average_precision']:.6f}.

Confusion matrix (rows actual benign/attack; columns predicted benign/attack):

| Actual / predicted | Benign | Attack |
|---|---:|---:|
| Benign | {tn} | {fp} |
| Attack | {fn} | {tp} |

## False positives and explanations

{fp} benign test records were flagged. Frequent false-positive services: `{json.dumps(metrics['false_positive_analysis']['top_services'])}`.
The model compares individual records. It cannot see scanning sequences or host context;
those require the separately labeled rules. Explanations list outlying feature ranges and
unseen benign categories. These are supporting triage indicators, not exact per-tree attribution.

## Limitations

""" + "\n".join(f"- {item}" for item in limits) + "\n\n## Reproduce\n\n`python scripts/train_model.py --download --output models`\n\nOr supply the original compressed file with `--data data/raw/kddcup.data_10_percent.gz`.\nThe download is retained under ignored `data/raw/`; it is not needed to run the application.\nOnly load trusted model artifacts: joblib/pickle can execute code. Models cannot be uploaded through the API.\n"
    card += "\nThe loader requires matching artifact/evaluation SHA-256 fingerprints, model and feature schema,\n" \
            "and the exact pinned scikit-learn version. These checks detect accidental mismatch; they are\n" \
            "not a signature or a substitute for trusted local files. Invalid or missing model files\n" \
            "trigger explicit rule-only fallback.\n"
    (output / "model_card.md").write_text(card, encoding="utf-8")
    return metrics


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=ROOT / "data/raw/kddcup.data_10_percent.gz")
    parser.add_argument("--output", type=Path, default=ROOT / "models")
    parser.add_argument("--download", action="store_true")
    args = parser.parse_args()
    if args.download and not args.data.exists():
        args.data.parent.mkdir(parents=True, exist_ok=True)
        temporary = args.data.with_suffix(args.data.suffix + ".part")
        with urlopen(DATA_URL, timeout=60) as response, temporary.open("wb") as destination:
            while chunk := response.read(1024 * 1024):
                destination.write(chunk)
        temporary.replace(args.data)
    if not args.data.exists():
        parser.error("Dataset missing: use --download or --data <KDD99 .gz/.csv>")
    metrics = train(args.data, args.output)
    print(json.dumps({"counts": metrics["counts"], "metrics": metrics["metrics"],
                      "confusion_matrix": metrics["confusion_matrix"], "sha256": metrics["sha256"]}, indent=2))


if __name__ == "__main__":
    main()
