"""Deployment-only synthetic snapshot preparation; never accepts a private DB."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import tempfile

from backend.app.main import Runtime, create_app
from detection.ml import Detector


def _snapshot_contents(database: Path) -> dict:
    connection = sqlite3.connect(database.resolve().as_uri()+"?mode=ro&immutable=1", uri=True)
    try:
        if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ValueError("Public snapshot failed SQLite integrity validation")
        metadata = {key: json.loads(value) for key, value in connection.execute("SELECT key,value FROM metadata")}
        origins = {row[0] for table in ("connections", "incidents")
                   for row in connection.execute(f"SELECT DISTINCT origin FROM {table}")}
        counts = {table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                  for table in ("connections", "incidents", "history")}
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        connection.close()
    if (metadata.get("database_role") != "public_demo" or origins != {"demo"}
            or counts["connections"] != 360 or "monitor_batches" in tables
            or metadata.get("simulation", {}).get("status") != "completed"
            or metadata.get("simulation", {}).get("processed") != 360):
        raise ValueError("Only a complete 360-row synthetic public-demo snapshot is deployable")
    return dict(counts=counts, origins=sorted(origins), role="public_demo")


def generate_snapshot(destination: Path) -> dict:
    """Build the frozen snapshot from the existing real synthetic/model pipeline."""
    destination = Path(destination).resolve()
    manifest = destination.with_suffix(destination.suffix+".json")
    if destination.exists() or manifest.exists():
        raise ValueError("Refuse to overwrite an existing database or snapshot manifest")
    destination.parent.mkdir(parents=True, exist_ok=True)
    detector = Detector()
    if not detector.ready:
        raise ValueError("The approved historical model must load to prepare the public snapshot")
    with tempfile.TemporaryDirectory(prefix="sentinel-synthetic-build-", dir=destination.parent) as folder:
        fresh = Path(folder)/"public-demo.sqlite"
        runtime = Runtime(str(fresh), seed=True, detector=detector, public_demo=True)
        try:
            runtime.store.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            runtime.store.close()
        contents = _snapshot_contents(fresh)
        with destination.open("xb") as output, fresh.open("rb") as source:
            shutil.copyfileobj(source, output)
    result = dict(schema=1, source="existing_synthetic_demo_pipeline", **contents,
                  model_artifact_sha256=detector.metadata["artifact_sha256"],
                  sha256=hashlib.sha256(destination.read_bytes()).hexdigest())
    with manifest.open("x", encoding="utf-8") as output:
        json.dump(result, output, indent=2)
    return result


def public_app_from_snapshot(snapshot: Path, temporary_parent: Path):
    """A fixed safe profile, with a unique writable copy of a bundled snapshot.

    FastAPI's normal lifespan remains responsible for Runtime startup/shutdown.
    The deployment platform must support ASGI lifespan; no fallback is invented.
    """
    snapshot = Path(snapshot).resolve()
    manifest = json.loads(snapshot.with_suffix(snapshot.suffix+".json").read_text(encoding="utf-8"))
    if (manifest.get("schema") != 1 or manifest.get("source") != "existing_synthetic_demo_pipeline"
            or manifest.get("sha256") != hashlib.sha256(snapshot.read_bytes()).hexdigest()):
        raise ValueError("Public snapshot manifest/hash mismatch")
    _snapshot_contents(snapshot)
    detector = Detector()
    if (not detector.ready or detector.metadata.get("artifact_sha256")
            != manifest.get("model_artifact_sha256")):
        raise ValueError("The public snapshot requires its approved, matching model artifact")
    temporary_parent = Path(temporary_parent).resolve()
    temporary_parent.mkdir(parents=True, exist_ok=True)
    folder = Path(tempfile.mkdtemp(prefix="sentinel-public-", dir=temporary_parent))
    database = folder/"public-demo.sqlite"
    shutil.copyfile(snapshot, database)
    app = create_app(str(database), public_demo=True, monitor_mode=False, lab_mode=False,
                     pcap_enabled=False, api_key="", seed=False, detector=detector)
    app.state.public_snapshot_hash = manifest["sha256"]
    app.state.public_snapshot_database = database
    return app
