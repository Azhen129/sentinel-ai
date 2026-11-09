"""Check evaluation labels, metric arithmetic and constructed-fixture integrity."""
from copy import deepcopy

from backend.app.schemas import PassiveConnection
from detection.evaluation_cases import evaluation_cases
from scripts.evaluate_detection import classification_metrics


def test_metric_arithmetic_and_undefined_denominators():
    rows = [dict(label=a, flagged=b) for a, b in [(1, 1), (1, 0), (0, 1), (0, 0), (0, 0)]]
    result = classification_metrics(rows)
    assert result == dict(true_positives=1, false_positives=1, true_negatives=2, false_negatives=1,
        precision=0.5, recall=0.5, f1=0.5, false_positive_rate=1/3)
    empty = classification_metrics([])
    assert all(empty[key] is None for key in ("precision", "recall", "f1", "false_positive_rate"))


def test_fixtures_are_explicitly_constructed_and_collector_schema_compatible():
    cases = evaluation_cases()
    assert len({c["case_id"] for c in cases}) == len(cases)
    for case in cases:
        assert case["ground_truth"] == "constructed_scenario_intent_not_observed_attack"
        assert sum(r["provenance"]["packet_count"] for r in case["records"]) <= 5000
        for record in case["records"]:
            assert PassiveConnection.model_validate(record).provenance.interface_label == "Constructed fixture"


def test_intent_blind_spot_is_observationally_indistinguishable():
    cases = {c["case_id"]: c for c in evaluation_cases()}
    rows = []
    for name in ("low_volume_intent", "benign_identical_upload"):
        record = deepcopy(cases[name]["records"][0])
        record["provenance"].pop("collection_id")
        record["provenance"].pop("flow_id")
        rows.append(record)
    assert rows[0] == rows[1]
    assert cases["low_volume_intent"]["label"] != cases["benign_identical_upload"]["label"]
