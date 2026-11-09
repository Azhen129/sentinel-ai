"""One feature contract shared by benchmark training and live inference."""
from __future__ import annotations

from collections.abc import Iterable, Mapping
import hashlib
import json
import math

import numpy as np
import pandas as pd

NUMERIC = ["log_duration", "log_bytes_sent", "log_bytes_received"]
CATEGORICAL = ["protocol", "service", "status"]
FEATURES = NUMERIC + CATEGORICAL

STATUS_MAP = {
    "established": "SF", "success": "SF", "closed": "SF", "sf": "SF",
    "failed": "S0", "timeout": "S0", "s0": "S0", "rejected": "REJ",
    "rej": "REJ", "reset": "RSTO", "rsto": "RSTO", "rstr": "RSTR",
    "s1": "S1", "s2": "S2", "s3": "S3", "oth": "OTH",
    "rstrh": "RSTRH", "sh": "SH", "shr": "SHR",
}
SERVICE_MAP = {"https": "http", "tls": "http", "ssl": "http", "dns": "domain_u"}


def finite_nonnegative(value: object) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError):
        return 0.0
    return result if math.isfinite(result) and result >= 0 else 0.0


def canonical_record(record: Mapping) -> dict:
    """Ignore addresses, IDs, labels, timestamps, scenarios and model outputs."""
    protocol = str(record.get("protocol") or "unknown").lower()
    service = str(record.get("service") or "other").lower()
    if service in ("-", "unknown", ""):
        service = "other"
    if service == "dns":
        service = "domain_u" if protocol == "udp" else "domain"
    else:
        service = SERVICE_MAP.get(service, service)
    status = str(record.get("status") or "OTH")
    return {
        "duration": finite_nonnegative(record.get("duration", 0)),
        "bytes_sent": finite_nonnegative(record.get("bytes_sent", 0)),
        "bytes_received": finite_nonnegative(record.get("bytes_received", 0)),
        "protocol": protocol,
        "service": service,
        "status": STATUS_MAP.get(status.lower(), status.upper()),
    }


def feature_frame(records: Iterable[Mapping]) -> pd.DataFrame:
    rows = []
    for record in records:
        row = canonical_record(record)
        rows.append({
            "log_duration": np.log1p(row["duration"]),
            "log_bytes_sent": np.log1p(row["bytes_sent"]),
            "log_bytes_received": np.log1p(row["bytes_received"]),
            **{name: row[name] for name in CATEGORICAL},
        })
    return pd.DataFrame(rows, columns=FEATURES)


def feature_group(record: Mapping) -> str:
    payload = json.dumps(canonical_record(record), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()
