"""Synthetic metadata fixtures test opt-in API behavior; these are not capture evidence."""
from datetime import datetime, timedelta, timezone
import hashlib

from fastapi import HTTPException
from fastapi.testclient import TestClient
import pytest

from backend.app.main import ROOT, Runtime, create_app
from backend.app.monitoring import loopback_peer, monitoring_status
from backend.app.schemas import MetadataBatch, PassiveConnection
from backend.app.storage import Store


class RuleOnlyModel:
    ready = False
    metadata = {"status": "unavailable"}

    def predict(self, record):
        return {"is_anomaly": False, "score": 0.0, "indicators": []}


def passive_record(i=1, *, role="initiator", dst_port=443, bytes_sent=120):
    first = datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=i)
    return dict(timestamp=first.isoformat(), src_ip="192.0.2.10", dst_ip="198.51.100.20",
                src_port=50000+i, dst_port=dst_port, protocol="tcp", duration=1,
                bytes_sent=bytes_sent, bytes_received=300, status="syn_observed", service="unknown",
                provenance=dict(collector="dumpcap+tshark", interface_label="Ethernet",
                    measurement_semantics="transport_payload_bytes", observation_scope="selected_interface_passive",
                    flow_semantics="tcp_stream_window", process_scope="interface_only_no_process_attribution",
                    flow_id=f"{i:040x}", collection_id="00000000-0000-0000-0000-000000000001",
                    first_seen=first.isoformat(), last_seen=(first+timedelta(seconds=1)).isoformat(),
                    window_end=(first+timedelta(seconds=30)).isoformat(), packet_count=3,
                    local_role=role, midstream_start=role=="unknown", duration_is_lower_bound=True,
                    capture_window_limited=True, retransmissions_included=True, direction_basis="local_host",
                    transport_flags_observed="SYN,ACK"))


def normalized(i=1, **changes):
    return PassiveConnection.model_validate(passive_record(i, **changes)).model_dump(mode="json", exclude_none=True)


@pytest.fixture
def monitor_client(tmp_path):
    with TestClient(create_app(str(tmp_path / "monitor.db"), monitor_mode=True, api_key="test-monitor-key", detector=RuleOnlyModel()), client=("127.0.0.1", 51000), base_url='http://127.0.0.1') as client:
        yield client


def test_passive_schema_preserves_only_typed_metadata():
    record = normalized()
    assert record["scenario"] == "live_ethernet"
    assert record["provenance"]["collector"] == "dumpcap+tshark"
    for unknown in ("packet_payload", "password", "http_body"):
        candidate = passive_record()
        candidate[unknown] = "never store this"
        with pytest.raises(ValueError):
            PassiveConnection.model_validate(candidate)
    candidate = passive_record()
    candidate["provenance"]["raw_packet"] = "forbidden"
    with pytest.raises(ValueError):
        PassiveConnection.model_validate(candidate)


@pytest.mark.parametrize("state", ["REJ", "failed", "established"])
def test_metadata_cannot_claim_authentication_or_full_transport_states(state):
    record = passive_record()
    record["status"] = state
    with pytest.raises(ValueError):
        PassiveConnection.model_validate(record)


def test_schema_rejects_invalid_capture_window_or_mixed_collection():
    record = passive_record()
    record["provenance"]["window_end"] = "2025-01-01T00:00:00+00:00"
    with pytest.raises(ValueError):
        PassiveConnection.model_validate(record)
    second = passive_record(2)
    second["provenance"]["collection_id"] = "00000000-0000-0000-0000-000000000002"
    with pytest.raises(ValueError):
        MetadataBatch.model_validate({"batch_id": "mixed", "records": [passive_record(), second]})
    with pytest.raises(ValueError):
        MetadataBatch.model_validate({"batch_id": "big", "records": [passive_record()] * 251})


def test_monitor_requires_new_dedicated_unmarked_database_without_modifying_it(tmp_path):
    path = tmp_path / "existing.db"
    store = Store(str(path))
    store.close()
    before = hashlib.sha256(path.read_bytes()).digest()
    with pytest.raises(ValueError, match="new dedicated database"):
        Runtime(str(path), seed=False, monitor_mode=True, detector=RuleOnlyModel())
    assert hashlib.sha256(path.read_bytes()).digest() == before


def test_live_database_is_private_even_when_empty_and_default_modes_refuse_it(tmp_path):
    path = str(tmp_path / "monitor.db")
    rt = Runtime(path, seed=False, monitor_mode=True, detector=RuleOnlyModel())
    rt.store.close()
    for lab in (False, True):
        with pytest.raises(ValueError, match="refuses a database containing live"):
            Runtime(path, seed=False, allow_lab_data=lab, detector=RuleOnlyModel())


def test_batch_is_atomic_idempotent_and_persistent(tmp_path):
    path = str(tmp_path / "monitor.db")
    rt = Runtime(path, seed=False, monitor_mode=True, detector=RuleOnlyModel())
    records = [normalized(1), normalized(2)]
    assert rt.ingest_metadata("batch1", records)["ingested"] == 2
    assert rt.ingest_metadata("batch1", records)["duplicate"] is True
    with pytest.raises(HTTPException) as different:
        rt.ingest_metadata("batch1", [normalized(3)])
    assert different.value.status_code == 409
    # One fresh record followed by an existing flow must roll back both writes.
    with pytest.raises(HTTPException) as duplicate_flow:
        rt.ingest_metadata("batch2", [normalized(3), normalized(1)])
    assert duplicate_flow.value.status_code == 409
    assert rt.store.live_count() == 2
    assert rt.store.monitor_batch("batch2") is None
    rt.store.close()
    rt = Runtime(path, seed=False, monitor_mode=True, detector=RuleOnlyModel())
    assert rt.ingest_metadata("batch1", records)["ingested"] == 0
    assert rt.store.live_count() == 2
    rt.store.close()


def test_row_cap_refuses_whole_batch_and_never_prunes(tmp_path):
    rt = Runtime(str(tmp_path / "monitor.db"), seed=False, monitor_mode=True, monitor_max_rows=2, detector=RuleOnlyModel())
    rt.ingest_metadata("one", [normalized(1)])
    with pytest.raises(HTTPException) as full:
        rt.ingest_metadata("over", [normalized(2), normalized(3)])
    assert full.value.status_code == 507
    assert rt.store.live_count() == 1
    rt.ingest_metadata("two", [normalized(2)])
    assert monitoring_status(rt, True)["capacity_reached"] is True
    assert rt.ingest_metadata("one", [normalized(1)])["duplicate"] is True
    rt.store.close()


def test_runtime_cannot_mix_origins_or_seed_synthetic_monitor_data(tmp_path):
    with pytest.raises(ValueError, match="Synthetic seeding"):
        Runtime(str(tmp_path / "forbidden.db"), monitor_mode=True, detector=RuleOnlyModel())
    demo = Runtime(str(tmp_path / "demo.db"), seed=False, detector=RuleOnlyModel())
    with pytest.raises(ValueError, match="separate runtime databases"):
        demo.ingest(normalized(), "live")
    assert demo.store.overview()["data_sources"] == {"demo": 0, "lab": 0}
    demo.store.close()
    monitor = Runtime(str(tmp_path / "monitor.db"), seed=False, monitor_mode=True, detector=RuleOnlyModel())
    with pytest.raises(ValueError, match="separate runtime databases"):
        monitor.ingest(normalized(), "demo")
    monitor.store.close()


def test_live_responder_and_unknown_ports_never_pollute_initiator_scan_window(tmp_path):
    rt = Runtime(str(tmp_path / "monitor.db"), seed=False, monitor_mode=True, detector=RuleOnlyModel())
    rt.ingest_metadata("responder", [normalized(i, role="responder", dst_port=45000+i) for i in range(1, 9)])
    rt.ingest_metadata("unknown", [normalized(i, role="unknown", dst_port=46000+i) for i in range(9, 17)])
    assert rt.store.incidents()["total"] == 0
    rt.ingest_metadata("first-initiator", [normalized(17, dst_port=3000)])
    assert not any(r["rule_id"] == "port_scan" for r in rt.store.incidents()["items"])
    rt.ingest_metadata("other-initiators", [normalized(i, dst_port=3000+i) for i in range(18, 25)])
    scans = [r for r in rt.store.incidents()["items"] if r["rule_id"] == "port_scan"]
    assert len(scans) == 1 and scans[0]["origin"] == "live"
    assert "8 distinct ports in 60 seconds" in scans[0]["indicators"]
    rt.store.close()


@pytest.mark.parametrize("host,expected", [("127.0.0.1", True), ("::1", True), ("::ffff:127.0.0.1", True), ("192.0.2.1", False), ("testclient", False), (None, False)])
def test_loopback_guard_does_not_trust_hostnames_or_external_addresses(host, expected):
    assert loopback_peer(host) is expected


def test_api_requires_monitor_flag_and_key_and_preserves_origin(monitor_client, tmp_path):
    headers = {"X-Sentinel-Key": "test-monitor-key"}
    body = {"batch_id": "api-1", "records": [passive_record()]}
    assert monitor_client.get("/api/monitor/status").status_code == 401
    status = monitor_client.get("/api/monitor/status", headers=headers).json()
    assert status["database_isolated"] is True and status["ingestion_enabled"] is True
    assert status["monitoring"]["status"] == "waiting"
    assert monitor_client.post("/api/ingest/metadata", json=body).status_code == 401
    result = monitor_client.post("/api/ingest/metadata", json=body, headers=headers)
    assert result.status_code == 200 and result.json()["ingested"] == 1
    assert result.json()["monitoring"]["status"] == "receiving"
    rows = monitor_client.get("/api/connections").json()["items"]
    assert rows[0]["origin"] == "live" and rows[0]["provenance"]["collector"] == "dumpcap+tshark"
    overview = monitor_client.get("/api/overview").json()
    assert overview["mode"] == "monitor" and overview["simulated"] is False
    assert overview["data_sources"] == {"demo": 0, "lab": 0, "live": 1}
    assert monitor_client.get("/api/health").json()["mode"] == "monitor"
    for action in ("start", "pause", "reset"):
        assert monitor_client.post(f"/api/simulation/{action}", json={}).status_code == 403
    assert monitor_client.get("/api/connections").json()["total"] == 1
    with TestClient(create_app(str(tmp_path / "demo.db"), detector=RuleOnlyModel()), client=("127.0.0.1", 50000), base_url='http://127.0.0.1') as demo:
        assert demo.get("/api/monitor/status", headers=headers).status_code == 403
        assert demo.post("/api/ingest/metadata", json=body, headers=headers).status_code == 403
        assert demo.get("/api/overview").json()["total_connections"] == 120


def test_api_monitor_is_loopback_only_and_cannot_use_default_demo_path(tmp_path):
    with TestClient(create_app(str(tmp_path / "monitor.db"), monitor_mode=True, api_key="key", detector=RuleOnlyModel()), client=("203.0.113.5", 50000), base_url='http://127.0.0.1') as remote:
        assert remote.get("/api/overview").status_code == 403
        assert remote.get("/api/health").status_code == 403
    with pytest.raises(ValueError, match="default demo database is forbidden"):
        with TestClient(create_app(str(ROOT / "data" / "sentinel.db"), monitor_mode=True, detector=RuleOnlyModel()), client=("127.0.0.1", 50000), base_url='http://127.0.0.1'):
            pass


def test_api_status_stales_and_missing_key_fails_closed(monitor_client, tmp_path):
    monitor_client.app.state.runtime.store.set_meta("monitoring", {"last_ingest_at": "2020-01-01T00:00:00+00:00"})
    assert monitor_client.get("/api/system").json()["monitoring"]["status"] == "stale"
    with TestClient(create_app(str(tmp_path / "nokey.db"), monitor_mode=True, api_key="", detector=RuleOnlyModel()), client=("127.0.0.1", 50000), base_url='http://127.0.0.1') as missing:
        assert missing.get("/api/monitor/status").status_code == 503
