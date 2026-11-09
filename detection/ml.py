"""Trusted local model loading and passive per-connection inference."""
from __future__ import annotations

import json
import hashlib
import logging
import math
from pathlib import Path

from detection.features import CATEGORICAL, NUMERIC, feature_frame

logger = logging.getLogger(__name__)
DEFAULT_MODEL = Path(__file__).resolve().parents[1] / "models" / "isolation_forest.joblib"
ARTIFACT_SCHEMA_VERSION = 1


class Detector:
    def __init__(self, model_path: str | Path | None = None):
        self.ready = False
        self.model = None
        self.metadata = {
            "status": "unavailable", "name": "Isolation Forest", "model_loaded": False,
            "limitations": ["No trained model is installed. Rule detection remains available."],
        }
        path = Path(model_path) if model_path else DEFAULT_MODEL
        try:
            import sklearn
            # joblib uses pickle. Only load this repository's trusted, locally trained artifact.
            import joblib
            metrics_path = path.parent / "metrics.json"
            metadata = json.loads(metrics_path.read_text(encoding="utf-8"))
            if not isinstance(metadata, dict):
                raise ValueError("Model metadata must be a JSON object")
            fingerprint = hashlib.sha256(path.read_bytes()).hexdigest()
            if metadata.get("artifact_sha256") != fingerprint:
                raise ValueError("Model artifact and evaluation metadata fingerprints do not match")
            if metadata.get("sklearn_version") != sklearn.__version__:
                raise ValueError("Model scikit-learn version differs from installed version; use pinned requirements or retrain")
            model = joblib.load(path)
            if not isinstance(model, dict):
                raise ValueError("Model artifact must contain the Sentinel model dictionary")
            required = {"schema_version", "model_version", "sklearn_version", "features", "preprocessor", "estimator", "threshold", "benign_ranges", "benign_categories"}
            if not required <= model.keys():
                raise ValueError("Model artifact is missing required schema fields")
            if model["schema_version"] != ARTIFACT_SCHEMA_VERSION or metadata.get("artifact_schema_version") != ARTIFACT_SCHEMA_VERSION:
                raise ValueError("Model artifact schema version is unsupported")
            if model["sklearn_version"] != sklearn.__version__:
                raise ValueError("Model artifact scikit-learn version is incompatible")
            if model["model_version"] != metadata.get("model_version"):
                raise ValueError("Model artifact and evaluation versions differ")
            if model["features"] != NUMERIC + CATEGORICAL or model["features"] != metadata.get("features"):
                raise ValueError("Model artifact feature contract is incompatible")
            threshold = float(model["threshold"])
            if not math.isfinite(threshold) or not 0 <= threshold <= 1:
                raise ValueError("Model threshold must be finite and within [0, 1]")
            if not math.isclose(threshold, float(metadata.get("threshold", math.nan)), rel_tol=0, abs_tol=1e-12):
                raise ValueError("Model and evaluation thresholds differ")
            for name in NUMERIC:
                bounds = model["benign_ranges"][name]
                if not all(math.isfinite(float(bounds[key])) for key in ("p01", "median", "p99")):
                    raise ValueError("Model numeric explanation ranges must be finite")
            for name in CATEGORICAL:
                if not isinstance(model["benign_categories"][name], list):
                    raise ValueError("Model category support lists are invalid")
            # A fitted-shape smoke check catches incompatible preprocessing.
            probe = model["preprocessor"].transform(feature_frame([{}]))
            score = float(-model["estimator"].score_samples(probe)[0])
            if not math.isfinite(score) or not 0 <= score <= 1:
                raise ValueError("Model inference smoke check failed")
            self.model = model
            self.metadata = metadata
            self.ready = True
            self.metadata.update({"status": "ready", "model_loaded": True})
        except Exception as exc:
            # Deserialization has multiple error families; invalid local artifacts must
            # not stop the app or silently claim that model inference is healthy.
            self.model = None
            self.ready = False
            reason = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
            self.metadata["unavailable_reason"] = reason
            self.metadata["limitations"] = ["Model validation failed; rule detection remains available.", reason]
            logger.warning("Anomaly model unavailable: %s", type(exc).__name__)

    def predict(self, record: dict) -> dict:
        if not self.ready or self.model is None:
            return {"is_anomaly": False, "score": 0.0, "indicators": []}
        frame = feature_frame([record])
        transformed = self.model["preprocessor"].transform(frame)
        score = float(-self.model["estimator"].score_samples(transformed)[0])
        is_anomaly = score > float(self.model["threshold"])
        indicators = []
        if is_anomaly:
            ranges = self.model["benign_ranges"]
            for feature in NUMERIC:
                value = float(frame.iloc[0][feature])
                bounds = ranges[feature]
                if value > bounds["p99"]:
                    name = feature.removeprefix("log_").replace("_", " ")
                    indicators.append(f"{name.capitalize()} exceeds the training benign 99th percentile")
                elif value < bounds["p01"]:
                    name = feature.removeprefix("log_").replace("_", " ")
                    indicators.append(f"{name.capitalize()} below the training benign 1st percentile")
            for feature in CATEGORICAL:
                value = str(frame.iloc[0][feature])
                if value not in self.model["benign_categories"][feature]:
                    indicators.append(f"{feature.capitalize()} '{value}' absent from benign training records")
            if not indicators:
                indicators.append("Unusual combination of duration, byte volumes, protocol, service and connection state")
            indicators.append(f"Isolation score {score:.3f} exceeds validation threshold {self.model['threshold']:.3f}")
        return {"is_anomaly": bool(is_anomaly), "score": round(score, 6), "indicators": indicators}
