"""Pure compatibility tests with synthetic documentation-address inputs only."""
import copy
import json

import pytest

from detection.assessment import baseline_assessment

SUPPORT = {"status": ["SF", "REJ"], "service": ["other", "http", "domain_u"], "protocol": ["tcp", "udp", "icmp"]}


def record(**changes):
    value = {"src_ip": "192.0.2.10", "dst_ip": "198.51.100.20", "dst_port": 53,
             "protocol": "udp", "duration": 1, "bytes_sent": 64, "bytes_received": 0,
             "status": "observed", "service": "unknown", "provenance": {
                 "measurement_semantics": "transport_payload_bytes", "local_role": "unknown",
                 "duration_is_lower_bound": True, "capture_window_limited": True,
                 "midstream_start": True, "retransmissions_included": True,
                 "direction_basis": "local_host"}}
    value.update(changes)
    return value


def test_above_threshold_live_score_remains_informational():
    result = baseline_assessment(record(), score=0.62, threshold=0.59, benign_categories=SUPPORT)
    assert result["above_threshold"] is True
    assert result["alert_eligible"] is False
    assert result["compatibility"] == "not_validated_for_live"
    assert result["explanation_kind"] == "heuristic_not_causal"
    reasons = " ".join(result["reasons"])
    assert "all-zero" in reasons and "'other'" in reasons
    assert "lower bound" in reasons and "Repeated transmissions" in reasons
    assert "initiator was not established" in reasons


def test_score_equality_uses_strict_comparison_without_changing_values():
    result = baseline_assessment(record(), score=0.6, threshold=0.6, benign_categories=SUPPORT)
    assert result["above_threshold"] is False
    assert result["score"] == result["threshold"] == 0.6


@pytest.mark.parametrize("score,threshold", [(None, 0.6), (0.6, None), (float("nan"), 0.6), (0.6, float("inf")), (True, 0.6), (-0.1, 0.6), (0.6, 1.1)])
def test_unavailable_or_invalid_values_never_fabricate_a_comparison(score, threshold):
    result = baseline_assessment(record(), score=score, threshold=threshold)
    assert result["above_threshold"] is None
    assert result["alert_eligible"] is False
    json.dumps(result, allow_nan=False)


def test_known_state_does_not_claim_unknown_support_but_stays_uncalibrated():
    result = baseline_assessment(record(status="SF", service="http", protocol="tcp"),
        score=0.4, threshold=0.6, benign_categories=SUPPORT)
    reasons = " ".join(result["reasons"])
    assert "absent from benign training support" not in reasons
    assert result["alert_eligible"] is False


def test_legacy_unknown_service_substitution_is_not_an_unseen_category():
    result = baseline_assessment(record(status="SF"), score=0.4, threshold=0.6, benign_categories=SUPPORT)
    reasons = " ".join(result["reasons"])
    assert "'other'" in reasons
    assert "service is absent" not in reasons


def test_responder_measurement_orientation_is_explicit():
    data = record()
    data["provenance"]["local_role"] = "responder"
    result = baseline_assessment(data, score=0.6, threshold=0.5, benign_categories=SUPPORT)
    assert any("local host was a responder" in reason for reason in result["reasons"])


def test_no_private_values_or_arbitrary_categorical_strings_are_echoed():
    data = record(status="untrusted-status-marker", service="untrusted-service-marker")
    result = baseline_assessment(data, score=0.6, threshold=0.5, benign_categories=SUPPORT)
    output = json.dumps(result)
    assert "192.0.2.10" not in output and "198.51.100.20" not in output
    assert "untrusted-status-marker" not in output and "untrusted-service-marker" not in output


def test_inputs_not_mutated_and_historical_threshold_provenance_not_fabricated():
    data = record()
    before = copy.deepcopy(data)
    result = baseline_assessment(data, score=0.62, threshold=0.59, model_version="baseline-test",
        benign_categories=SUPPORT)
    assert data == before
    assert result["threshold_source"] == "current_baseline_reference"
    assert result["score_source"] == "stored_connection"
    assert result["model_version"] == "baseline-test"
    current = baseline_assessment(data, score=0.62, threshold=0.59, threshold_source="stored_at_ingest",
        score_source="computed_at_ingest", benign_categories=SUPPORT)
    assert current["threshold_source"] == "stored_at_ingest"
    assert current["score_source"] == "computed_at_ingest"


def test_missing_support_and_provenance_are_explicit_without_model_loading():
    result = baseline_assessment(record(provenance=None), score=0.62, threshold=0.59)
    reasons = " ".join(result["reasons"])
    assert "support was not supplied" in reasons
    assert "provenance is unavailable" in reasons


def test_service_alias_approximation_disclosed_without_changing_baseline_mapping():
    result = baseline_assessment(record(service="https"), score=0.62, threshold=0.59, benign_categories=SUPPORT)
    assert any("encrypted-service labels" in reason for reason in result["reasons"])


def test_boundary_comparison_does_not_recover_a_full_precision_decision():
    threshold = 0.5929614023891565
    possible_raw_below, possible_raw_above = 0.59296139, 0.59296149
    assert possible_raw_below < threshold < possible_raw_above
    assert round(possible_raw_below, 6) == round(possible_raw_above, 6) == 0.592961
    result = baseline_assessment(record(), score=0.592961, threshold=threshold, benign_categories=SUPPORT)
    assert result["above_threshold"] is False
    assert result["comparison_basis"] == "reported_rounded_score"
    assert "six-decimal" in result["comparison_note"]
    assert "original full-precision model decision has not been recovered" in result["comparison_note"]
    assert result["comparison_note"] in result["reasons"]
    assert result["alert_eligible"] is False


def test_missing_score_retains_precision_notice_without_a_comparison():
    result = baseline_assessment(record(), score=None, threshold=0.6)
    assert result["above_threshold"] is None
    assert result["comparison_basis"] == "reported_rounded_score"
    assert result["comparison_note"] in result["reasons"]
