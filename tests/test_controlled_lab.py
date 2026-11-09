"""Owned loopback policy verification; constructed unit fixtures are labelled here."""
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
from pathlib import Path
import socket
import struct
import uuid

import pytest

from backend.app.controlled_lab import (
    LARGE_BYTES, LOOPBACK, LabEvidenceStore, OwnedServices, SOURCE,
    _dns_response, _validate_record, plan, run_controlled_lab,
)


def fixture_record(i=1, scenario="port_probe", *, port=None, sent=18, collection=None):
    """Constructed unit-test evidence, never claimed to be an executed exchange."""
    stamp = datetime(2026, 1, 1, tzinfo=timezone.utc)+timedelta(seconds=i*.25)
    return dict(timestamp=stamp.isoformat(), src_ip=LOOPBACK, dst_ip=LOOPBACK,
        src_port=50000+i, dst_port=port or 30000+i, protocol="tcp", duration=.01,
        bytes_sent=sent, bytes_received=25, status="established", service="tcp_banner_exchange",
        scenario="controlled_localhost_"+scenario,
        provenance=dict(collector="localhost-lab", measurement_semantics="application_bytes",
            observation_scope="owned_loopback_services", flow_semantics="completed_socket_exchange",
            process_scope="owned_lab_processes_only", flow_id=f"{i:040x}",
            collection_id=collection or "00000000-0000-0000-0000-000000000001",
            first_seen=stamp.isoformat(), last_seen=(stamp+timedelta(seconds=.01)).isoformat(),
            local_role="initiator", direction_basis="client_to_owned_service", scenario=scenario,
            protocol_verified="tcp_banner_exchange", source=SOURCE, event_id=uuid.uuid4().hex))


def test_plan_is_disabled_and_never_opens_sockets(monkeypatch):
    monkeypatch.setattr(socket, "socket", lambda *a, **k: pytest.fail("Planning opened a socket"))
    details = plan()
    assert details["execution"] == "disabled" and details["capture"] is False
    assert len(details["scenarios"]) == 7 and details["bind_address"] == LOOPBACK


def test_cli_defaults_to_plan_without_starting_any_service(monkeypatch, capsys):
    path = Path(__file__).parents[1]/"scripts"/"verify_controlled_lab.py"
    spec = importlib.util.spec_from_file_location("controlled_lab_cli_unit", path)
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    monkeypatch.setattr(cli, "run_controlled_lab", lambda *a: pytest.fail("Default CLI performed activity"))
    assert cli.main([]) == 0
    assert '"execution": "disabled"' in capsys.readouterr().out


@pytest.mark.parametrize("change", [
    lambda r: r.update(dst_ip="198.51.100.1"),
    lambda r: r["provenance"].update(collector="dumpcap+tshark"),
    lambda r: r["provenance"].update(measurement_semantics="transport_payload_bytes"),
    lambda r: r["provenance"].update(packet_count=3),
    lambda r: r["provenance"].update(password="must-not-be-stored"),
    lambda r: r["provenance"].update(local_role="unknown"),
    lambda r: r.update(status="syn_observed"),
    lambda r: r.update(bytes_sent=8*1024*1024),
    lambda r: r["provenance"].update(last_seen="2025-01-01T00:00:00+00:00"),
])
def test_unowned_or_capture_shaped_or_inconsistent_records_are_rejected(change):
    record = fixture_record()
    change(record)
    with pytest.raises(ValueError):
        _validate_record(record)


def test_exclusive_database_cannot_overwrite_any_existing_file(tmp_path):
    original = tmp_path/"existing.db"
    original.write_bytes(b"preserved original")
    with pytest.raises(FileExistsError):
        LabEvidenceStore(original)
    assert original.read_bytes() == b"preserved original"


def test_existing_output_directory_is_refused_before_services_start(tmp_path, monkeypatch):
    monkeypatch.setattr(OwnedServices, "__enter__", lambda *a: pytest.fail("Existing output started service"))
    with pytest.raises(FileExistsError):
        run_controlled_lab(tmp_path)


def test_live_rule_findings_have_truthful_lab_bytes_no_model_and_replay_is_noop(tmp_path):
    with LabEvidenceStore(tmp_path/"new.db") as lab:
        records = [fixture_record(i) for i in range(1, 9)]
        assert lab.persist("port_probe", records) == dict(ingested=8, duplicate=False)
        incident = lab.store.incidents()["items"][0]
        saved = lab.store.get_incident(incident["id"])
        assert incident["rule_id"] == "port_scan" and incident["severity"] == "high"
        assert incident["origin"] == "lab" and incident["detection_source"] == "rule"
        assert "controlled localhost endpoint instrumentation" in incident["description"]
        assert lab.persist("port_probe", records) == dict(ingested=0, duplicate=True)
        assert lab.store.get_incident(incident["id"]) == saved
        assert lab.store.connections()["total"] == 8
        assert lab.store.get_meta("database_role") == "controlled_lab"
        assert all(r["anomaly_score"] is None for r in lab.store.connections()["items"])
        changed = [dict(r) for r in records]
        changed[0] = dict(changed[0], bytes_sent=19)
        with pytest.raises(ValueError, match="differs"):
            lab.persist("port_probe", changed)
        assert lab.store.get_incident(incident["id"]) == saved


def test_burst_and_volume_use_current_rules_and_realistic_source_wording(tmp_path):
    with LabEvidenceStore(tmp_path/"new.db") as lab:
        lab.persist("connection_burst", [fixture_record(i, "connection_burst", port=30001) for i in range(1,26)])
        volume = fixture_record(1, "outbound_volume", sent=LARGE_BYTES,
            collection="00000000-0000-0000-0000-000000000002")
        lab.persist("outbound_volume", [volume])
        incidents = lab.store.incidents()["items"]
        assert {i["rule_id"] for i in incidents} == {"connection_frequency", "traffic_spike"}
        assert {i["severity"] for i in incidents} == {"medium"}
        hit = next(i for i in incidents if i["rule_id"] == "traffic_spike")
        assert any("6,291,456 measured outbound application bytes" in s for s in hit["indicators"])
        assert "Measured outbound application byte counters" in hit["description"]
        assert not any("header-derived" in s or "partial capture" in s for s in hit["indicators"])
        assert "does not establish exfiltration" in hit["description"]


def test_bounded_scenario_collection_must_not_mix_or_append_duplicate_flow(tmp_path):
    with LabEvidenceStore(tmp_path/"new.db") as lab:
        first, second = fixture_record(1), fixture_record(2)
        second["provenance"]["collection_id"] = str(uuid.uuid4())
        with pytest.raises(ValueError, match="One isolated collection"):
            lab.persist("port_probe", [first, second])
        assert lab.store.connections()["total"] == 0
        with pytest.raises(ValueError):
            lab.persist("port_probe", [fixture_record(1, "normal_dns")])
        with pytest.raises(ValueError, match="duplicate flow"):
            lab.persist("port_probe", [first, first])
        assert lab.store.connections()["total"] == 0


def test_genuine_dns_format_validation_is_bounded_and_has_no_external_resolver():
    query = struct.pack("!HHHHHH", 123, 0x0100, 1, 0, 0, 0)+b"\x0csentinel-lab\x07invalid\x00\x00\x01\x00\x01"
    reply = _dns_response(query)
    assert reply[:2] == query[:2] and reply[2:4] == b"\x81\x83"  # NXDOMAIN
    assert reply[12:] == query[12:]
    with pytest.raises(ValueError):
        _dns_response(b"unverified-message")


def test_actual_loopback_exchanges_counts_hashes_cleanup_and_expected_rules(tmp_path):
    """Real bounded socket integration; parent requires local loopback permission."""
    directory = tmp_path/"fresh-run"
    report = run_controlled_lab(directory)
    assert report["database_integrity"] == "ok"
    assert report["capture"] is False and report["machine_learning_scored"] is False
    assert report["origins"] == ["lab"]
    assert all(r["status"] in {"passed", "skipped"} for r in report["results"])
    completed = [r for r in report["results"] if r["status"] == "passed"]
    assert len(completed) >= 6
    assert report["client_observations"] == report["server_observations"] == report["counts"]["connections"]
    assert report["counts"]["incidents"] == 3
    assert all(r["unchanged_evidence_replay"] == dict(ingested=0, duplicate=True) for r in completed)
    import json
    clients = [json.loads(line) for line in (directory/"client-observations.jsonl").read_text().splitlines()]
    servers = {row["event_id"]: row for row in (json.loads(line) for line in (directory/"endpoint-observations.jsonl").read_text().splitlines())}
    for record in clients:
        server = servers[record["provenance"]["event_id"]]
        assert record["bytes_sent"] == server["application_bytes_received"]
        assert record["bytes_received"] == server["application_bytes_sent"]
        assert record["dst_port"] in report["owned_destination_ports"]
        assert record["src_ip"] == record["dst_ip"] == LOOPBACK
    large = next(r for r in clients if r["bytes_sent"] == LARGE_BYTES)
    digest = hashlib.sha256(b"L"*LARGE_BYTES).hexdigest()
    assert large["provenance"]["payload_sha256"] == digest
    assert servers[large["provenance"]["event_id"]]["payload_sha256"] == digest
    assert not list(directory.glob("disposable-tls-*"))
    assert report["cleanup_completed"] is True
