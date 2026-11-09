from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import threading
import time

from fastapi.testclient import TestClient
import pytest

from backend.app.demo import demo_records
from backend.app.ingestion import aggregate_tshark, parse_zeek
from backend.app.main import create_app
from backend.app.rules import RuleEngine
from backend.app.schemas import Connection
from backend.app.storage import Store


class RuleOnlyModel:
    ready = False
    metadata = {"status": "unavailable", "algorithm": "Isolation Forest"}

    def predict(self, record):
        return {"is_anomaly": False, "score": 0.0, "indicators": []}


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(str(tmp_path / "test.db"), detector=RuleOnlyModel()), base_url='http://127.0.0.1', client=('127.0.0.1',51000)) as client:
        yield client


def connection(**changes):
    result = demo_records(1, datetime(2026, 1, 1, tzinfo=timezone.utc))[0]
    result.update(src_ip="192.0.2.1", dst_ip="198.51.100.1", dst_port=443, protocol="tcp", duration=1, status="SF", bytes_sent=500, bytes_received=2000)
    result.update(changes)
    return result


def zeek_row(**changes):
    row = {"ts": 1767225600, "id.orig_h": "192.0.2.1", "id.resp_h": "198.51.100.1", "id.orig_p": 50100, "id.resp_p": 443, "proto": "tcp", "duration": 1.5, "orig_bytes": 300, "resp_bytes": 1200, "conn_state": "SF", "service": "ssl"}
    row.update(changes)
    return row


def test_seed_and_overview_are_real_aggregates(client):
    overview = client.get("/api/overview").json()
    assert overview["total_connections"] == 120
    assert sum(p["value"] for p in overview["protocols"]) == 120
    assert sum(p["connections"] for p in overview["traffic"]) == 120
    assert overview["active_incidents"] > 0
    assert overview["simulation"]["processed"] == 120
    assert overview["simulated"] is True


def test_connection_pagination_and_filter(client):
    response = client.get("/api/connections?limit=3&offset=2&protocol=udp").json()
    assert len(response["items"]) == 3
    assert all(c["protocol"] == "udp" for c in response["items"])
    assert response["total"] > 3
    assert client.get("/api/connections?limit=501").status_code == 422
    assert client.get("/api/connections?protocol=invalid").status_code == 422


def test_incident_workflow_and_history(client):
    incident = client.get("/api/incidents?source=rule").json()["items"][0]
    identifier = incident["id"]
    update = client.patch(f"/api/incidents/{identifier}", json={"status": "investigating", "note": "Reviewed destination and connection history."})
    assert update.status_code == 200
    result = update.json()
    assert result["status"] == "investigating"
    assert result["notes"][0]["note"] == "Reviewed destination and connection history."
    assert [r["action"] for r in result["history"]] == ["detected", "status_changed", "note"]
    assert client.get("/api/incidents?status=investigating").json()["total"] == 1
    assert client.patch(f"/api/incidents/{identifier}", json={"status": "resolved"}).json()["status"] == "resolved"
    assert client.get("/api/incidents/not-found").status_code == 404
    assert client.patch(f"/api/incidents/{identifier}", json={"status": "deleted"}).status_code == 422
    assert client.patch(f"/api/incidents/{identifier}", json={"note": " "}).status_code == 422


def test_pause_resume_reset_and_validation(client):
    result = client.post("/api/simulation/start", json={"speed": 20})
    assert result.status_code == 200
    time.sleep(0.15)
    paused = client.post("/api/simulation/pause").json()
    assert paused["status"] == "paused"
    assert paused["processed"] > 120
    time.sleep(0.1)
    assert client.get("/api/simulation").json()["processed"] == paused["processed"]
    reset = client.post("/api/simulation/reset").json()
    assert reset["status"] == "idle" and reset["processed"] == 0
    assert client.get("/api/overview").json()["total_connections"] == 0
    assert client.get("/api/incidents").json()["total"] == 0
    assert client.post("/api/simulation/start", json={"speed": 0}).status_code == 422


def test_database_survives_restart_without_duplicate_seed(tmp_path):
    path = str(tmp_path / "persist.db")
    with TestClient(create_app(path, detector=RuleOnlyModel()), base_url='http://127.0.0.1', client=('127.0.0.1',51000)) as client:
        incident = client.get("/api/incidents").json()["items"][0]
        client.patch(f"/api/incidents/{incident['id']}", json={"note": "Persistent note"})
    with TestClient(create_app(path, detector=RuleOnlyModel()), base_url='http://127.0.0.1', client=('127.0.0.1',51000)) as client:
        assert client.get("/api/overview").json()["total_connections"] == 120
        assert client.get(f"/api/incidents/{incident['id']}").json()["notes"][0]["note"] == "Persistent note"


def test_ingestion_is_disabled_by_default(client):
    assert client.post("/api/ingest/zeek", json={"content": json.dumps(zeek_row())}).status_code == 403
    assert client.post("/api/ingest/pcap", content=b"test").status_code == 403


def test_request_limits_reject_large_declared_body_before_parsing(client):
    response = client.post("/api/ingest/zeek", content=b"{}", headers={"Content-Length": "3000001", "Content-Type": "application/json"})
    assert response.status_code == 413
    assert client.post("/api/ingest/pcap", content=b"x", headers={"Content-Length": "20000001"}).status_code == 413


def test_request_limits_reject_chunked_body_before_json_parsing(client):
    chunks = iter([b"x" * 1_500_001, b"x" * 1_500_001])
    response = client.post("/api/ingest/zeek", content=chunks, headers={"Content-Type": "application/json"})
    assert response.status_code == 413


def test_json_content_limit_is_validated_within_outer_body_bound(client):
    response = client.post("/api/ingest/zeek", json={"content": "x" * 2_000_001})
    assert response.status_code == 422


def test_authorized_lab_import_and_reset_preserves_lab(tmp_path):
    with TestClient(create_app(str(tmp_path / "lab.db"), seed=False, lab_mode=True, api_key="test-key", detector=RuleOnlyModel()), base_url='http://127.0.0.1', client=('127.0.0.1',51000)) as client:
        body = {"content": json.dumps(zeek_row())}
        assert client.post("/api/ingest/zeek", json=body).status_code == 401
        imported = client.post("/api/ingest/zeek", json=body, headers={"X-Sentinel-Key": "test-key"})
        assert imported.json()["ingested"] == 1
        client.post("/api/simulation/reset")
        rows = client.get("/api/connections").json()
        assert rows["total"] == 1 and rows["items"][0]["origin"] == "lab"
        assert client.post("/api/ingest/pcap", content=b"test", headers={"X-Sentinel-Key": "test-key"}).status_code == 403


def test_demo_startup_refuses_a_database_with_private_lab_records(tmp_path):
    database = str(tmp_path / "lab.db")
    with TestClient(create_app(database, seed=False, lab_mode=True, api_key="key", detector=RuleOnlyModel()), base_url='http://127.0.0.1', client=('127.0.0.1',51000)) as client:
        assert client.post("/api/ingest/zeek", json={"content": json.dumps(zeek_row())}, headers={"X-Sentinel-Key": "key"}).status_code == 200
    with pytest.raises(ValueError, match="Demo mode refuses a database containing lab"):
        with TestClient(create_app(database, lab_mode=False, detector=RuleOnlyModel()), base_url='http://127.0.0.1', client=('127.0.0.1',51000)):
            pass
    # The guard preserves evidence and permits an authorized local lab to reopen it.
    with TestClient(create_app(database, lab_mode=True, api_key="key", detector=RuleOnlyModel()), base_url='http://127.0.0.1', client=('127.0.0.1',51000)) as client:
        assert client.get("/api/connections").json()["total"] == 1


def test_malformed_batch_is_rejected_before_any_ingestion(tmp_path):
    with TestClient(create_app(str(tmp_path / "lab.db"), seed=False, lab_mode=True, api_key="key", detector=RuleOnlyModel()), base_url='http://127.0.0.1', client=('127.0.0.1',51000)) as client:
        content = json.dumps(zeek_row()) + "\n" + '{"ts": "broken"}'
        response = client.post("/api/ingest/zeek", json={"content": content}, headers={"X-Sentinel-Key": "key"})
        assert response.status_code == 422
        assert client.get("/api/connections").json()["total"] == 0


@pytest.mark.parametrize("protocol", [None, 6, [], {}])
def test_malformed_protocol_is_a_validation_error(tmp_path, protocol):
    with TestClient(create_app(str(tmp_path / "lab.db"), seed=False, lab_mode=True, api_key="key", detector=RuleOnlyModel()), base_url='http://127.0.0.1', client=('127.0.0.1',51000)) as client:
        response = client.post("/api/ingest/zeek", json={"content": json.dumps(zeek_row(proto=protocol))}, headers={"X-Sentinel-Key": "key"})
        assert response.status_code == 422
        assert client.get("/api/connections").json()["total"] == 0


def test_lab_batch_does_not_block_health_requests(tmp_path):
    entered, release = threading.Event(), threading.Event()

    class BlockingModel(RuleOnlyModel):
        def predict(self, record):
            entered.set()
            release.wait(timeout=3)
            return super().predict(record)

    with TestClient(create_app(str(tmp_path / "lab.db"), seed=False, lab_mode=True, api_key="key", detector=BlockingModel()), base_url='http://127.0.0.1', client=('127.0.0.1',51000)) as client, ThreadPoolExecutor(max_workers=1) as pool:
        upload = pool.submit(client.post, "/api/ingest/zeek", json={"content": json.dumps(zeek_row())}, headers={"X-Sentinel-Key": "key"})
        try:
            assert entered.wait(timeout=2)
            start = time.monotonic()
            assert client.get("/api/health").status_code == 200
            assert time.monotonic() - start < 0.5
        finally:
            release.set()
        assert upload.result(timeout=3).status_code == 200


def test_health_model_and_system_explicitly_report_fallback(client):
    assert client.get("/api/health").json()["model_loaded"] is False
    assert client.get("/api/model").json()["ready"] is False
    assert client.get("/api/system").json()["mode"] == "demo"


def test_port_scan_threshold_and_expiry():
    rules = RuleEngine()
    for i in range(7):
        assert "port_scan" not in {h.rule_id for h in rules.inspect(connection(dst_port=1000 + i))}
    assert "port_scan" in {h.rule_id for h in rules.inspect(connection(dst_port=1007))}
    later = (datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=61)).isoformat()
    assert "port_scan" not in {h.rule_id for h in rules.inspect(connection(dst_port=1008, timestamp=later))}


def test_rules_do_not_flag_normal_web_or_quic():
    assert RuleEngine().inspect(connection()) == []
    assert RuleEngine().inspect(connection(protocol="udp", dst_port=443)) == []


def test_failed_connections_frequency_and_spike_rules():
    rules = RuleEngine()
    hits = []
    for _ in range(25):
        hits = rules.inspect(connection(status="REJ"))
    ids = {h.rule_id for h in hits}
    assert {"failed_connections", "connection_frequency"} <= ids
    assert "traffic_spike" in {h.rule_id for h in rules.inspect(connection(bytes_sent=5_000_000))}
    assert "unexpected_port" in {h.rule_id for h in rules.inspect(connection(dst_port=4444))}


def test_rules_keep_sources_separate():
    rules = RuleEngine()
    for i in range(8):
        hits = rules.inspect(connection(src_ip=f"192.0.2.{i + 1}", dst_port=1000 + i))
    assert not any(h.rule_id == "port_scan" for h in hits)


def test_historical_rewind_starts_a_new_rule_window():
    rules = RuleEngine()
    future = "2026-01-02T00:00:00+00:00"
    rules.inspect(connection(timestamp=future))
    for i in range(8):
        hits = rules.inspect(connection(dst_port=1000 + i))
    assert "port_scan" in {h.rule_id for h in hits}


def test_zeek_json_parser_handles_missing_values():
    rows = parse_zeek(json.dumps(zeek_row(duration="-", orig_bytes="-")))
    assert rows[0]["duration"] == 0
    assert rows[0]["bytes_sent"] == 0
    assert rows[0]["src_ip"] == "192.0.2.1"
    assert rows[0]["scenario"] == "lab"


def test_zeek_tsv_parser_uses_header():
    row = zeek_row()
    text = "#separator \\x09\n#fields\t" + "\t".join(row) + "\n" + "\t".join(map(str, row.values()))
    parsed = parse_zeek(text, "tsv")
    assert parsed[0]["dst_port"] == 443


def test_committed_zeek_examples_have_equivalent_content():
    root = Path(__file__).resolve().parents[1] / "data" / "examples"
    json_records = parse_zeek((root / "conn.json").read_text(), "json")
    tsv_records = parse_zeek((root / "conn.log").read_text(), "tsv")
    assert len(json_records) == 3
    assert json_records == tsv_records


@pytest.mark.parametrize("content,format", [("{}", "json"), ("[]", "json"), ("broken", "json"), ("#fields\tts\n1\t2", "tsv"), ("", "json")])
def test_zeek_rejects_invalid_inputs(content, format):
    with pytest.raises(ValueError):
        parse_zeek(content, format)


def test_offline_flow_aggregation_tracks_bidirectional_bytes():
    output = '"1767225600","192.0.2.1","","198.51.100.1","","50000","","443","","100","0","1","0"\n"1767225602","198.51.100.1","","192.0.2.1","","443","","50000","","200","0","0","1"\n'
    flows = aggregate_tshark(output)
    assert len(flows) == 1
    assert flows[0]["bytes_sent"] == 100
    assert flows[0]["bytes_received"] == 200
    assert flows[0]["duration"] == 2


def test_connection_validates_addresses_and_normalizes_timezone():
    item = Connection.model_validate(connection(timestamp="2026-01-01T03:00:00+03:00"))
    assert item.timestamp == "2026-01-01T00:00:00+00:00"
    with pytest.raises(ValueError):
        Connection.model_validate(connection(src_ip="not-an-ip"))


def test_demo_uses_documentation_ranges_and_deterministic_features():
    a = demo_records(anchor=datetime(2026, 1, 1, tzinfo=timezone.utc))
    b = demo_records(anchor=datetime(2026, 1, 1, tzinfo=timezone.utc))
    assert a == b
    assert all(r["src_ip"].startswith("192.0.2.") for r in a)
    assert all(r["dst_ip"].startswith(("198.51.100.", "203.0.113.")) for r in a)
