"""Offline regression comparison on constructed metadata; no capture, API or training.

The fixed cases have scenario-intent labels, not independently verified network
ground truth. Results are engineering diagnostics and cannot establish accuracy
on a laptop or production network. No private database is opened by this script.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import statistics
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.app.live_detection import LiveRuleEngine
from backend.app.rules import RuleEngine
from backend.app.schemas import PassiveConnection
from detection.assessment import baseline_assessment
from detection.evaluation_cases import evaluation_cases
from detection.ml import Detector


def classification_metrics(rows):
    counts = Counter()
    for row in rows:
        counts[(bool(row["label"]), bool(row["flagged"]))] += 1
    tp, fp, tn, fn = (counts[k] for k in ((True, True), (False, True), (False, False), (True, False)))
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None
    return dict(true_positives=tp, false_positives=fp, true_negatives=tn, false_negatives=fn,
        precision=precision, recall=recall, f1=f1,
        false_positive_rate=fp / (fp + tn) if fp + tn else None)


def evaluate(detector=None):
    detector = detector if detector is not None else Detector()
    if not detector.ready:
        raise RuntimeError("The trusted baseline model must load for a before/after comparison")
    model = detector.model
    cases = evaluation_cases()
    results = {"before": [], "after": []}
    timings = {"before": [], "after": []}
    for case in cases:
        # Exercise the same strict metadata shape accepted by the local collector API.
        records = [PassiveConnection.model_validate(r).model_dump(mode="json") for r in case["records"]]
        for variant in ("before", "after"):
            engine = RuleEngine() if variant == "before" else LiveRuleEngine()
            rule_ids = set()
            baseline_exceedances = 0
            for record in records:
                started = time.perf_counter()
                prediction = detector.predict(record)
                hits = engine.inspect(record, port_scan_eligible=record["provenance"]["local_role"] == "initiator")
                if variant == "after":
                    baseline_assessment(record, score=prediction["score"], threshold=model["threshold"],
                        model_version=model["model_version"], threshold_source="stored_at_ingest",
                        score_source="computed_at_ingest", benign_categories=model["benign_categories"])
                timings[variant].append((time.perf_counter() - started) * 1000)
                rule_ids.update(hit.rule_id for hit in hits)
                baseline_exceedances += bool(prediction["is_anomaly"])
            flagged = bool(rule_ids) or (variant == "before" and baseline_exceedances > 0)
            results[variant].append(dict(case_id=case["case_id"], label=case["label"], flagged=flagged,
                rule_ids=sorted(rule_ids), baseline_threshold_exceedances=baseline_exceedances,
                observation_records=len(records)))
    output = dict(dataset="constructed_metadata_regression_v1", case_count=len(cases),
        labels="Author-assigned scenario intent; not real-world attack ground truth",
        trained=False, tuned_on_private_records=False, network_access=False, capture=False,
        before_policy="Original rules plus KDD99 threshold-generated incidents",
        after_policy="Live metadata rules; unchanged KDD99 scores informational only",
        baseline_model_sha256=detector.metadata["artifact_sha256"],
        baseline_threshold=model["threshold"], results={})
    for variant in ("before", "after"):
        values = sorted(timings[variant])
        output["results"][variant] = dict(fixture_only_metrics=classification_metrics(results[variant]),
            latency_ms=dict(median=statistics.median(values), p95=values[min(len(values)-1, int(len(values)*0.95))],
                scope="Per-record model and policy computation only; excludes capture, API, storage and browser"),
            cases=results[variant])
    output["limitations"] = [
        "Constructed regression cases are small, intentionally chosen and not an independent operational evaluation.",
        "No new model is fitted or calibrated; no train/validation/test performance claim is made.",
        "Ordinary parallel connections and large legitimate uploads can still trigger review rules.",
        "Slow probing, missing initiator evidence and low-volume malicious intent can be missed.",
        "A collection completes before ingestion; end-to-end detection latency was not measured here.",
        "Removing unsupported benchmark-generated alerts can also remove true positives; live accuracy remains unverified.",
    ]
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Optional new local JSON report; contains only constructed-case results")
    args = parser.parse_args()
    if args.output and args.output.exists():
        parser.error("Output already exists; choose a new filename rather than overwrite evidence")
    result = evaluate()
    value = json.dumps(result, indent=2, allow_nan=False)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8") as stream:
            stream.write(value + "\n")
    print(value)


if __name__ == "__main__":
    main()
