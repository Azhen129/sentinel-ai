import math
import hashlib
import json
import shutil
from pathlib import Path

import numpy as np
import pytest

from detection.features import FEATURES, canonical_record, feature_frame, feature_group
from detection.ml import Detector


def test_features_exclude_identifiers_and_labels():
    first = {"duration": 3, "bytes_sent": 100, "bytes_received": 500,
             "protocol": "tcp", "service": "https", "status": "established",
             "src_ip": "192.0.2.1", "label": "attack", "scenario": "scan"}
    second = {**first, "src_ip": "203.0.113.99", "label": "normal", "scenario": "normal", "is_anomaly": True}
    assert feature_frame([first]).equals(feature_frame([second]))
    assert feature_group(first) == feature_group(second)
    assert list(feature_frame([first]).columns) == FEATURES


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -5, "not numeric", None])
def test_numeric_preprocessing_is_finite(value):
    frame = feature_frame([{"duration": value, "bytes_sent": value, "bytes_received": value}])
    assert np.isfinite(frame.iloc[0, :3].to_numpy(dtype=float)).all()
    assert (frame.iloc[0, :3].to_numpy(dtype=float) == 0).all()


def test_zeek_and_benchmark_normalization_align():
    zeek = {"duration": 1, "protocol": "udp", "service": "dns", "status": "established", "bytes_sent": 50, "bytes_received": 70}
    kdd = {**zeek, "service": "domain_u", "status": "SF"}
    assert canonical_record(zeek) == canonical_record(kdd)


def test_missing_model_is_explicit_rule_only(tmp_path):
    detector = Detector(tmp_path / "missing.joblib")
    assert not detector.ready
    assert detector.metadata["status"] == "unavailable"
    assert detector.predict({}) == {"is_anomaly": False, "score": 0.0, "indicators": []}


def test_grouped_split_prevents_engineered_feature_overlap():
    from scripts.train_model import grouped_split
    records = [{"duration": i, "protocol": "tcp", "service": "http", "status": "SF"} for i in range(100)]
    records += [{**records[0], "irrelevant_label": "attack"}] * 8
    train, validation, test, groups = grouped_split(records)
    assert not set(groups[train]) & set(groups[validation])
    assert not set(groups[train]) & set(groups[test])
    assert not set(groups[validation]) & set(groups[test])
    assert len(train) + len(validation) + len(test) == len(records)


def test_shipped_model_inference_and_metadata():
    detector = Detector()
    if not detector.ready:
        pytest.skip("No trained artifact present; run scripts/train_model.py")
    prediction = detector.predict({"duration": 5, "bytes_sent": 10**9, "bytes_received": 0,
                                   "protocol": "tcp", "service": "other", "status": "REJ"})
    assert isinstance(prediction["is_anomaly"], bool)
    assert math.isfinite(prediction["score"])
    assert 0 <= prediction["score"] <= 1
    if prediction["is_anomaly"]:
        assert prediction["indicators"]
    metadata = detector.metadata
    assert metadata["split"]["feature_group_overlap"] == 0
    metrics = metadata["metrics"]
    matrix = np.asarray(metadata["confusion_matrix"])
    assert matrix.sum() == metadata["counts"]["test"]
    tn, fp, fn, tp = matrix.ravel()
    assert metrics["recall"] == pytest.approx(tp / (tp + fn))
    assert metrics["precision"] == pytest.approx(tp / (tp + fp))


def model_copy(tmp_path):
    root = Path(__file__).resolve().parents[1]
    shutil.copy(root / "models/isolation_forest.joblib", tmp_path / "isolation_forest.joblib")
    shutil.copy(root / "models/metrics.json", tmp_path / "metrics.json")
    return tmp_path / "isolation_forest.joblib", tmp_path / "metrics.json"


def test_model_rejects_mismatched_artifact_metadata(tmp_path):
    model, metrics = model_copy(tmp_path)
    metadata = json.loads(metrics.read_text(encoding="utf-8"))
    metadata["artifact_sha256"] = "0" * 64
    metrics.write_text(json.dumps(metadata), encoding="utf-8")
    detector = Detector(model)
    assert not detector.ready
    assert "fingerprints" in detector.metadata["unavailable_reason"]
    assert detector.predict({})["is_anomaly"] is False


def test_model_rejects_missing_evaluation_metadata(tmp_path):
    model, metrics = model_copy(tmp_path)
    metrics.unlink()
    detector = Detector(model)
    assert not detector.ready
    assert detector.metadata["model_loaded"] is False


@pytest.mark.parametrize("invalid", ["wrong_type", "missing_field", "schema", "features", "version", "threshold"])
def test_model_validates_schema_before_ready(tmp_path, invalid):
    import joblib
    model, metrics = model_copy(tmp_path)
    payload = joblib.load(model)
    if invalid == "wrong_type":
        payload = []
    elif invalid == "missing_field":
        del payload["preprocessor"]
    elif invalid == "schema":
        payload["schema_version"] = 999
    elif invalid == "features":
        payload["features"] = ["label"]
    elif invalid == "version":
        payload["sklearn_version"] = "0.0.0"
    elif invalid == "threshold":
        payload["threshold"] = float("nan")
    joblib.dump(payload, model)
    metadata = json.loads(metrics.read_text(encoding="utf-8"))
    metadata["artifact_sha256"] = hashlib.sha256(model.read_bytes()).hexdigest()
    metrics.write_text(json.dumps(metadata), encoding="utf-8")
    detector = Detector(model)
    assert not detector.ready
    assert detector.model is None
    assert detector.metadata["status"] == "unavailable"


def test_model_rejects_installed_library_version_mismatch(tmp_path):
    model, metrics = model_copy(tmp_path)
    metadata = json.loads(metrics.read_text(encoding="utf-8"))
    metadata["sklearn_version"] = "0.0.0"
    metrics.write_text(json.dumps(metadata), encoding="utf-8")
    detector = Detector(model)
    assert not detector.ready
    assert "version" in detector.metadata["unavailable_reason"]
