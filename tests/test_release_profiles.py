"""Public snapshot isolation and private browser-boundary integration checks."""
import hashlib
import json

from fastapi.testclient import TestClient
import pytest

from backend.app.main import Runtime, create_app
from backend.app.storage import Store


class NoModel:
    ready = False
    metadata = {"status": "unavailable"}
    def predict(self, record):
        return {"is_anomaly": False, "score": 0.0, "indicators": []}


def local_client(app, **kwargs):
    return TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 51000), **kwargs)


def table_fingerprint(store):
    return hashlib.sha256(json.dumps({t:[tuple(r) for r in store.db.execute(f'SELECT * FROM {t} ORDER BY rowid')]
        for t in ("connections", "incidents", "history", "metadata")}, sort_keys=True).encode()).hexdigest()


def test_public_demo_is_complete_synthetic_snapshot_and_all_writes_fail(tmp_path):
    app = create_app(str(tmp_path/"public.db"), public_demo=True, lab_mode=False,
                     monitor_mode=False, pcap_enabled=False, detector=NoModel())
    with local_client(app) as client:
        overview = client.get("/api/overview").json()
        assert overview["public_demo"] is True and overview["mode"] == "demo"
        assert overview["data_sources"] == {"demo": 360, "lab": 0}
        assert overview["simulation"]["status"] == "completed"
        assert overview["capabilities"] == {"incident_write": False, "simulation_control": False}
        assert client.get("/api/system").json()["public_demo"] is True
        before = table_fingerprint(app.state.runtime.store)
        incident = client.get("/api/incidents").json()["items"][0]
        for route in ("simulation/start", "simulation/pause", "simulation/reset", "ingest/zeek", "ingest/pcap", "ingest/metadata"):
            assert client.post("/api/"+route, json={}).status_code == 403
        assert client.patch("/api/incidents/"+incident["id"], json={"note":"Rejected public mutation"}).status_code == 403
        assert client.post("/an-unknown-route", json={}).status_code == 403
        assert table_fingerprint(app.state.runtime.store) == before
        assert app.state.runtime.store.get_meta("database_role") == "public_demo"
    # Reopening does not append another replay or create new history.
    with local_client(create_app(str(tmp_path/"public.db"), public_demo=True, detector=NoModel())) as client:
        assert client.get("/api/overview").json()["total_connections"] == 360


@pytest.mark.parametrize("flags", [{"monitor_mode":True}, {"lab_mode":True}, {"pcap_enabled":True}])
def test_public_demo_cannot_enable_private_ingestion_modes(tmp_path, flags):
    with pytest.raises(ValueError, match="forbids"):
        with local_client(create_app(str(tmp_path/"public.db"), public_demo=True, detector=NoModel(), **flags)):
            pass
    assert not (tmp_path/"public.db").exists()


@pytest.mark.parametrize("role", ["monitor", "controlled_lab", None])
def test_public_demo_refuses_existing_private_or_unmarked_database_before_write(tmp_path, role):
    path=tmp_path/"private.db"
    store=Store(str(path))
    if role:store.set_meta("database_role", role)
    store.close()
    before=path.read_bytes()
    with pytest.raises(ValueError, match="Public demonstration"):
        Runtime(str(path), detector=NoModel(), public_demo=True)
    assert path.read_bytes()==before


def test_public_and_controlled_empty_roles_cannot_be_repurposed_as_demo(tmp_path):
    for role in ("public_demo", "controlled_lab"):
        path=tmp_path/(role+".db");store=Store(str(path));store.set_meta("database_role",role);store.close()
        before=path.read_bytes()
        with pytest.raises(ValueError):Runtime(str(path), detector=NoModel())
        assert path.read_bytes()==before


def test_default_private_demo_retains_replay_and_note_workflow(tmp_path):
    with local_client(create_app(str(tmp_path/"demo.db"), detector=NoModel())) as client:
        overview=client.get("/api/overview").json()
        assert overview["public_demo"] is False and overview["total_connections"]==120
        assert overview["capabilities"]["simulation_control"] is True
        assert client.post("/api/simulation/pause").status_code==200
        assert client.post("/api/simulation/reset").status_code==200


@pytest.mark.parametrize("lab", [False,True])
def test_private_profiles_reject_rebinding_hosts_and_untrusted_browser_origins(tmp_path, lab):
    app=create_app(str(tmp_path/"private.db"), monitor_mode=not lab, lab_mode=lab,
                   api_key="test-key", detector=NoModel())
    with local_client(app) as client:
        assert client.get("/api/health").status_code==200
        assert client.get("/api/connections", headers={"Host":"attacker.invalid"}).status_code==403
        assert client.get("/api/connections", headers=[("Host","127.0.0.1"),("Host","attacker.invalid")]).status_code==403
        assert client.patch("/api/incidents/missing", json={"note":"x"},headers={"Origin":"https://attacker.invalid"}).status_code==403
        assert client.patch("/api/incidents/missing", json={"note":"x"},headers={"Origin":"null"}).status_code==403
        # Local browser is allowed through to normal route semantics; a missing ID remains404.
        assert client.patch("/api/incidents/missing", json={"note":"x"},headers={"Origin":"http://127.0.0.1:5173"}).status_code==404
        assert client.patch("/api/incidents/missing", json={"note":"x"}).status_code==404
        assert client.get("/api/health").headers["x-frame-options"]=="DENY"
