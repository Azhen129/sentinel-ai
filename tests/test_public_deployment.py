"""Public hosting boundaries exercised through the actual API and SQLite state."""
import hashlib
import json
from pathlib import Path
import sqlite3
import tomllib

from fastapi.testclient import TestClient
import pytest

from deployment.public_snapshot import generate_snapshot, public_app_from_snapshot


@pytest.fixture(scope="module")
def snapshot(tmp_path_factory):
    path = tmp_path_factory.mktemp("synthetic-public-bundle") / "public-demo.sqlite"
    generate_snapshot(path)
    return path


def test_public_deployment_survives_fresh_instances_and_ignores_private_environment(snapshot, tmp_path, monkeypatch):
    private_path = tmp_path / "must-never-open.db"
    for key, value in {
        "SENTINEL_MONITOR_MODE": "true", "SENTINEL_LAB_MODE": "true",
        "SENTINEL_PCAP_ENABLED": "true", "SENTINEL_PUBLIC_DEMO": "false",
        "SENTINEL_DB_PATH": str(private_path), "SENTINEL_API_KEY": "inert-test-fixture",
    }.items():
        monkeypatch.setenv(key, value)
    original_hash = hashlib.sha256(snapshot.read_bytes()).hexdigest()
    previous = None
    databases = []
    for _ in range(2):
        app = public_app_from_snapshot(snapshot, tmp_path)
        databases.append(app.state.public_snapshot_database)
        with TestClient(app, base_url="https://public.example.invalid") as client:
            health = client.get("/api/health").json()
            assert health["public_demo"] and health["mode"] == "demo" and health["model_loaded"]
            assert health["monitoring_status"] == "disabled"
            assert health["capabilities"] == {"incident_write": False, "simulation_control": False}
            overview = client.get("/api/overview").json()
            assert overview["total_connections"] == 360
            assert overview["data_sources"] == {"demo": 360, "lab": 0}
            rows = client.get("/api/connections?limit=500").json()
            assert rows["total"] == 360 and len(rows["items"]) == 360
            assert all(row["origin"] == "demo" for row in rows["items"])
            incidents = client.get("/api/incidents?limit=500").json()["items"]
            saved = (rows["items"], incidents)
            if previous:
                assert saved == previous
            previous = saved
            assert client.get("/api/incidents/" + incidents[0]["id"]).status_code == 200
            assert client.get("/api/model").status_code == 200
            assert client.get("/api/system").status_code == 200
            assert client.get("/api/monitor/status").status_code == 403
            for method, path in (
                ("POST", "/api/ingest/metadata"), ("POST", "/api/ingest/zeek"),
                ("POST", "/api/ingest/pcap"), ("POST", "/api/simulation/start"),
                ("POST", "/api/simulation/reset"), ("PATCH", "/api/incidents/" + incidents[0]["id"]),
                ("DELETE", "/api/connections"), ("PUT", "/unknown"),
            ):
                assert client.request(method, path, json={}).status_code == 403
            assert client.get("/api/overview").json()["total_connections"] == 360
    assert databases[0] != databases[1]
    assert not private_path.exists()
    assert hashlib.sha256(snapshot.read_bytes()).hexdigest() == original_hash


@pytest.mark.parametrize("change", ["hash", "live", "lab", "role", "incomplete", "monitor_table"])
def test_public_deployment_rejects_corrupted_or_nonpublic_snapshots(snapshot, tmp_path, change):
    altered = tmp_path / "altered.sqlite"
    altered.write_bytes(snapshot.read_bytes())
    manifest = json.loads(snapshot.with_suffix(".sqlite.json").read_text())
    if change == "hash":
        altered.write_bytes(altered.read_bytes() + b"tampered")
    else:
        with sqlite3.connect(altered) as db:
            if change == "live":
                db.execute("UPDATE connections SET origin='live' WHERE id=1")
            elif change == "lab":
                db.execute("UPDATE incidents SET origin='lab'")
            elif change == "role":
                db.execute("DELETE FROM metadata WHERE key='database_role'")
            elif change == "incomplete":
                db.execute("DELETE FROM connections WHERE id=1")
            elif change == "monitor_table":
                db.execute("CREATE TABLE monitor_batches (batch_id TEXT)")
            db.commit()
            db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        db.close()
        manifest["sha256"] = hashlib.sha256(altered.read_bytes()).hexdigest()
    altered.with_suffix(".sqlite.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError):
        public_app_from_snapshot(altered, tmp_path)


def test_public_builder_refuses_existing_input_database(snapshot):
    with pytest.raises(ValueError, match="overwrite"):
        generate_snapshot(snapshot)


@pytest.mark.parametrize("model_ready", [False, True])
def test_public_deployment_requires_matching_loaded_model(snapshot, tmp_path, monkeypatch, model_ready):
    class UnavailableModel:
        ready = model_ready
        metadata = {"artifact_sha256": "0" * 64}
    monkeypatch.setattr("deployment.public_snapshot.Detector", UnavailableModel)
    with pytest.raises(ValueError, match="matching model"):
        public_app_from_snapshot(snapshot, tmp_path)


def test_deployment_runtime_pins_match_local_requirements():
    root = Path(__file__).resolve().parents[1]
    config = tomllib.loads((root / "pyproject.toml").read_text())
    requirements = set((root / "requirements.txt").read_text().splitlines())
    assert set(config["project"]["dependencies"]) <= requirements
    assert config["tool"]["vercel"]["entrypoint"] == "deployment.public_app:app"
