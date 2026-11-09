"""Pure compatibility assessment for an unchanged historical benchmark score.

This helper never loads a model, re-scores a record, changes a threshold or writes
state. Live scores remain diagnostics because their feature semantics and operating
threshold have not been validated on representative live traffic.
"""
from __future__ import annotations

from collections.abc import Collection, Mapping
import math

from detection.features import canonical_record


def _finite_score(value: object) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return number if math.isfinite(number) and 0 <= number <= 1 else None


def baseline_assessment(
    record: Mapping,
    *,
    score: float | None,
    threshold: float | None,
    model_version: str | None = None,
    threshold_source: str = "current_baseline_reference",
    score_source: str = "stored_connection",
    benign_categories: Mapping[str, Collection[str]] | None = None,
) -> dict:
    """Describe live compatibility without treating a baseline exceedance as an alert.

    Existing stored scores can be paired with a *current reference* threshold, but
    must not be presented as a historically persisted threshold. Callers distinguish
    these using threshold_source/score_source; no inference occurs in this helper.
    Range/category explanations are compatibility heuristics, not causal attribution.
    Private addresses, ports, payloads and arbitrary input strings are never echoed.
    """
    score_value, threshold_value = _finite_score(score), _finite_score(threshold)
    comparison_note = ("Any threshold comparison here uses the reported six-decimal score. "
                       "Rounding can change the result near the boundary; the original full-precision model decision has not been recovered.")
    reasons = ["The KDD99 baseline was evaluated on a historical benchmark; its threshold is not calibrated for this live monitoring pipeline."]
    canonical = canonical_record(record)
    provenance = record.get("provenance")
    provenance = provenance if isinstance(provenance, Mapping) else {}
    support = benign_categories if isinstance(benign_categories, Mapping) else None

    if canonical["status"] in {"OBSERVED", "SYN_OBSERVED", "RESET_OBSERVED", "FIN_OBSERVED"}:
        reasons.append("The state is a packet-observation label, not a verified historical benchmark connection outcome.")
    if support is None:
        reasons.append("Benign training-category support was not supplied, so category compatibility cannot be verified here.")
    else:
        for name in ("status", "service", "protocol"):
            categories = support.get(name)
            if categories is not None and canonical[name] not in categories:
                # Do not repeat arbitrary untrusted categorical input in an explanation.
                label = "connection state" if name == "status" else name
                reasons.append(f"The {label} is absent from benign training support and is encoded as an all-zero category block; this is a compatibility limitation, not evidence of malicious behavior.")

    raw_service = str(record.get("service") or "").strip().lower()
    if raw_service in {"", "-", "unknown"}:
        reasons.append("The application service was not identified. Legacy preprocessing maps it to the trained 'other' category; that substitution does not confirm the service or its normality.")
    elif raw_service in {"https", "tls", "ssl"}:
        reasons.append("Legacy preprocessing maps encrypted-service labels to historical HTTP; this is an approximation and does not inspect encrypted content.")

    if any(provenance.get(name) is True for name in ("duration_is_lower_bound", "capture_window_limited", "midstream_start")):
        reasons.append("Duration is a bounded observed span or lower bound and can omit the start or end of a connection.")
    if provenance.get("measurement_semantics") == "transport_payload_bytes":
        reasons.append("Byte totals are header-derived transport payload lengths, not verified content or a reproduction of complete historical benchmark connection measurements.")
    if provenance.get("retransmissions_included") is True:
        reasons.append("Repeated transmissions are included in byte totals; the totals are not unique application-content volumes.")
    if provenance.get("direction_basis") == "local_host":
        if provenance.get("local_role") == "responder":
            reasons.append("The local host was a responder. Local-host byte orientation is not verified to match the benchmark's source/destination orientation.")
        elif provenance.get("local_role") in {None, "unknown"}:
            reasons.append("The stream initiator was not established, so local-host byte direction is not verified to match the benchmark's source/destination orientation.")
    if not provenance:
        reasons.append("Collection provenance is unavailable; duration, byte and direction compatibility cannot be verified.")
    if score_value is None or threshold_value is None:
        reasons.append("A finite baseline score and threshold in [0, 1] are unavailable; no threshold comparison was made.")
    reasons.append(comparison_note)
    reasons.append("This score is informational. Category and range indicators are heuristics, not causal feature attributions or confirmation of an attack.")
    return {
        "name": "KDD99 Isolation Forest baseline",
        "score": score_value,
        "threshold": threshold_value,
        "above_threshold": None if score_value is None or threshold_value is None else score_value > threshold_value,
        "comparison_basis": "reported_rounded_score",
        "comparison_note": comparison_note,
        "alert_eligible": False,
        "compatibility": "not_validated_for_live",
        "threshold_source": threshold_source,
        "score_source": score_source,
        "model_version": model_version,
        "reasons": reasons,
        "explanation_kind": "heuristic_not_causal",
    }
