"""Opt-in local metadata ingestion. No capture process or interface access is provided."""
from datetime import datetime, timezone
from ipaddress import ip_address
import json
from pathlib import Path
import sqlite3


LIMITATIONS = [
    "Receiving means recent API metadata, not proof that a capture process is running.",
    "Rows are capture-window flow observations, not guaranteed complete TCP/UDP sessions.",
    "Header-derived transport payload lengths include retransmissions and exclude headers; payload contents are not verified or accepted by this API.",
    "Bounded snapshots and dropped/truncated packets can undercount metadata; no API status proves gap-free collection.",
    "Source/destination and bytes are oriented to the selected local host, including responder traffic.",
    "Port-scan rules require an observed local initiator; responder/unknown flows do not contribute destination-port evidence.",
    "Burst rules count unique observed TCP initiator flows to one peer inside a collection; partial/unknown-role activity can be missed.",
    "The historical Isolation Forest is an informational live reference, not an alert-eligible validated detector. Unknown service/state and local byte orientation differ from its benchmark.",
    "No process attribution, authentication outcomes, packet capture control, or active response is implemented in this API.",
    "The row cap stops new ingestion; existing records and incidents are not automatically deleted. A row cap is not secure erasure.",
]


def loopback_peer(host):
    try:
        address = ip_address(host)
        return address.is_loopback or bool(getattr(address, "ipv4_mapped", None) and address.ipv4_mapped.is_loopback)
    except (ValueError, TypeError):
        return False


def validate_database_role(path, mode):
    """Inspect before opening writable storage; refuse private or unmarked reuse."""
    existing = path != ":memory:" and Path(path).is_file() and Path(path).stat().st_size > 0
    if not existing:
        return
    db = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True)
    try:
        tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        role = None
        if "metadata" in tables:
            row = db.execute("SELECT value FROM metadata WHERE key='database_role'").fetchone()
            role = json.loads(row[0]) if row else None
        origins = set()
        for table in ("connections", "incidents"):
            if table in tables:
                origins.update(row[0] for row in db.execute(f"SELECT DISTINCT origin FROM {table}"))
    finally:
        db.close()
    if mode == "public_demo" and (role != "public_demo" or origins - {"demo"}):
        raise ValueError("Public demonstration requires a new dedicated database or its existing public_demo database containing only synthetic records. Private or unmarked databases are never reused.")
    if mode != "public_demo" and role == "public_demo":
        raise ValueError("The frozen public-demo database cannot be reused by another profile. Select a separate database; no records were deleted.")
    if mode == "demo" and role == "controlled_lab":
        raise ValueError("Demo mode refuses a controlled-lab database even when empty. Select a separate demo database.")
    if mode == "monitor" and (role != "monitor" or origins - {"live"}):
        raise ValueError("Monitoring requires a new dedicated database or an existing marked monitor database. Existing unmarked/demo/lab databases are never reused or cleared.")
    if mode != "monitor" and (role == "monitor" or "live" in origins):
        raise ValueError("Demo/lab mode refuses a database containing live monitoring data or a monitor role. Select its separate database path; no records were deleted.")
    if mode == "demo" and "lab" in origins:
        raise ValueError("Demo mode refuses a database containing lab traffic or incidents. Use a separate demo path or enable the authorized local lab mode.")


def monitoring_status(runtime, enabled):
    stats = runtime.store.get_meta("monitoring", {}) if enabled else {}
    retained = runtime.store.live_count() if enabled else 0
    last = stats.get("last_ingest_at")
    status = "disabled" if not enabled else "waiting"
    if enabled and last:
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(last)).total_seconds()
        status = "receiving" if 0 <= age <= 30 else "stale"
    return dict(enabled=enabled, status=status, last_ingest_at=last,
                ingested_records=stats.get("ingested_records", 0), retained_records=retained,
                max_rows=runtime.monitor_max_rows, capacity_reached=enabled and retained >= runtime.monitor_max_rows,
                collector=stats.get("collector"), interface_label=stats.get("interface_label"),
                measurement_semantics=stats.get("measurement_semantics"), observation_scope=stats.get("observation_scope"),
                limitations=LIMITATIONS)
