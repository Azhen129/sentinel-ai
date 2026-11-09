from contextlib import contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import threading
import uuid


def utcnow():
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, path: str):
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self._transaction_depth = 0
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS connections (
          id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, src_ip TEXT NOT NULL,
          dst_ip TEXT NOT NULL, protocol TEXT NOT NULL, origin TEXT NOT NULL,
          is_anomaly INTEGER NOT NULL, bytes INTEGER NOT NULL, payload TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS ix_connections_time ON connections(timestamp);
        CREATE INDEX IF NOT EXISTS ix_connections_src ON connections(src_ip);
        CREATE TABLE IF NOT EXISTS incidents (
          id TEXT PRIMARY KEY, rule_id TEXT NOT NULL, src_ip TEXT NOT NULL, dst_ip TEXT NOT NULL,
          timestamp TEXT NOT NULL, last_seen TEXT NOT NULL, severity TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'open', detection_source TEXT NOT NULL,
          origin TEXT NOT NULL, count INTEGER NOT NULL DEFAULT 1, connection_id INTEGER,
          title TEXT NOT NULL, description TEXT NOT NULL, indicators TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS ix_incidents_correlation ON incidents(rule_id,src_ip,last_seen);
        CREATE TABLE IF NOT EXISTS history (
          id INTEGER PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
          timestamp TEXT NOT NULL, action TEXT NOT NULL, note TEXT NOT NULL DEFAULT '');
        CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY,value TEXT NOT NULL);
        """)
        self.db.commit()

    @contextmanager
    def transaction(self):
        with self.lock:
            outer = self._transaction_depth == 0
            self._transaction_depth += 1
            try:
                if outer:
                    with self.db:
                        yield self.db
                else:
                    yield self.db
            finally:
                self._transaction_depth -= 1

    def close(self):
        with self.lock:
            self.db.close()

    def has_lab_data(self):
        with self.lock:
            return self.db.execute("SELECT EXISTS(SELECT 1 FROM connections WHERE origin='lab') OR EXISTS(SELECT 1 FROM incidents WHERE origin='lab')").fetchone()[0] == 1

    def enable_monitor_storage(self):
        with self.transaction() as db:
            db.execute("CREATE TABLE IF NOT EXISTS monitor_batches (batch_id TEXT PRIMARY KEY,fingerprint TEXT NOT NULL,records INTEGER NOT NULL,timestamp TEXT NOT NULL)")
            db.execute("CREATE UNIQUE INDEX IF NOT EXISTS ix_live_flow_identity ON connections(json_extract(payload,'$.provenance.collection_id'),json_extract(payload,'$.provenance.flow_id')) WHERE origin='live'")
            db.execute("INSERT OR REPLACE INTO metadata VALUES ('database_role','\"monitor\"')")

    def live_count(self):
        with self.lock:
            return self.db.execute("SELECT COUNT(*) FROM connections WHERE origin='live'").fetchone()[0]

    def monitor_batch(self, batch_id):
        with self.lock:
            row = self.db.execute("SELECT * FROM monitor_batches WHERE batch_id=?", (batch_id,)).fetchone()
            return dict(row) if row else None

    def save_monitor_batch(self, batch_id, fingerprint, count, timestamp, stats):
        # Called within the same outer transaction as its connection/incident inserts.
        self.db.execute("INSERT INTO monitor_batches VALUES (?,?,?,?)", (batch_id, fingerprint, count, timestamp))
        self.db.execute("INSERT OR REPLACE INTO metadata VALUES ('monitoring',?)", (json.dumps(stats),))

    def get_meta(self, key, default=None):
        with self.lock:
            row = self.db.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()
            return json.loads(row[0]) if row else default

    def set_meta(self, key, value):
        with self.transaction() as db:
            db.execute("INSERT OR REPLACE INTO metadata VALUES (?,?)", (key, json.dumps(value)))

    def insert(self, record, origin, hits):
        with self.transaction() as db:
            cursor = db.execute("INSERT INTO connections(timestamp,src_ip,dst_ip,protocol,origin,is_anomaly,bytes,payload) VALUES (?,?,?,?,?,?,?,?)", (record["timestamp"], record["src_ip"], record["dst_ip"], record["protocol"], origin, int(record["is_anomaly"]), record["bytes_sent"] + record["bytes_received"], json.dumps(record)))
            connection_id = cursor.lastrowid
            for hit in hits:
                # Correlate repeated evidence into a single open investigation in a 5-minute window.
                ts = datetime.fromisoformat(record["timestamp"])
                cutoff = datetime.fromtimestamp(ts.timestamp() - 300, timezone.utc).isoformat()
                previous = db.execute("SELECT id FROM incidents WHERE rule_id=? AND src_ip=? AND dst_ip=? AND origin=? AND status!='resolved' AND last_seen>=? AND last_seen<=? ORDER BY last_seen DESC LIMIT 1", (hit["rule_id"], record["src_ip"], record["dst_ip"], origin, cutoff, record["timestamp"])).fetchone()
                if previous:
                    incident_id = previous["id"]
                    db.execute("UPDATE incidents SET last_seen=?,count=count+1,indicators=? WHERE id=?", (record["timestamp"], json.dumps(hit["indicators"]), incident_id))
                else:
                    incident_id = "INC-" + uuid.uuid4().hex[:10].upper()
                    db.execute("INSERT INTO incidents (id,rule_id,src_ip,dst_ip,timestamp,last_seen,severity,detection_source,origin,connection_id,title,description,indicators) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", (incident_id, hit["rule_id"], record["src_ip"], record["dst_ip"], record["timestamp"], record["timestamp"], hit["severity"], hit["detection_source"], origin, connection_id, hit["title"], hit["description"], json.dumps(hit["indicators"])))
                    db.execute("INSERT INTO history (incident_id,timestamp,action,note) VALUES (?,?,?,?)", (incident_id, utcnow(), "detected", hit["description"]))
            return connection_id

    @staticmethod
    def incident(row):
        result = dict(row)
        result["indicators"] = json.loads(result["indicators"])
        return result

    def get_incident(self, incident_id):
        with self.lock:
            row = self.db.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
            if row is None:
                return None
            result = self.incident(row)
            history = [dict(r) for r in self.db.execute("SELECT * FROM history WHERE incident_id=? ORDER BY id", (incident_id,))]
            result["history"] = history
            result["notes"] = [r for r in history if r["action"] == "note"]
            return result

    def patch_incident(self, incident_id, status=None, note=None):
        with self.transaction() as db:
            row = db.execute("SELECT status FROM incidents WHERE id=?", (incident_id,)).fetchone()
            if row is None:
                return None
            if status and status != row["status"]:
                db.execute("UPDATE incidents SET status=? WHERE id=?", (status, incident_id))
                db.execute("INSERT INTO history(incident_id,timestamp,action,note) VALUES (?,?,?,?)", (incident_id, utcnow(), "status_changed", f"{row['status']} → {status}"))
            if note:
                db.execute("INSERT INTO history(incident_id,timestamp,action,note) VALUES (?,?,?,?)", (incident_id, utcnow(), "note", note))
        return self.get_incident(incident_id)

    def connections(self, q="", protocol="", limit=100, offset=0):
        clauses, params = ["1=1"], []
        if q:
            clauses.append("(src_ip LIKE ? OR dst_ip LIKE ? OR payload LIKE ?)")
            params += [f"%{q}%"] * 3
        if protocol:
            clauses.append("protocol=?")
            params.append(protocol)
        where = " AND ".join(clauses)
        with self.lock:
            total = self.db.execute(f"SELECT COUNT(*) FROM connections WHERE {where}", params).fetchone()[0]
            rows = self.db.execute(f"SELECT id,payload,origin FROM connections WHERE {where} ORDER BY timestamp DESC,id DESC LIMIT ? OFFSET ?", params + [limit, offset]).fetchall()
            return {"items": [dict(json.loads(r["payload"]), id=r["id"], origin=r["origin"]) for r in rows], "total": total}

    def get_connection(self, connection_id):
        """Read the actual incident anchor without altering its saved payload."""
        with self.lock:
            row = self.db.execute("SELECT id,payload,origin FROM connections WHERE id=?", (connection_id,)).fetchone()
            return dict(json.loads(row["payload"]), id=row["id"], origin=row["origin"]) if row else None

    def incidents(self, severity="", status="", source="", q="", limit=100, offset=0):
        clauses, params = ["1=1"], []
        for name, value in [("severity", severity), ("status", status), ("detection_source", source)]:
            if value:
                clauses.append(f"{name}=?")
                params.append(value)
        if q:
            clauses.append("(title LIKE ? OR src_ip LIKE ? OR dst_ip LIKE ? OR id LIKE ?)")
            params += [f"%{q}%"] * 4
        where = " AND ".join(clauses)
        with self.lock:
            total = self.db.execute(f"SELECT COUNT(*) FROM incidents WHERE {where}", params).fetchone()[0]
            rows = self.db.execute(f"SELECT * FROM incidents WHERE {where} ORDER BY last_seen DESC LIMIT ? OFFSET ?", params + [limit, offset]).fetchall()
            return {"items": [self.incident(r) for r in rows], "total": total}

    def overview(self):
        with self.lock:
            totals = self.db.execute("SELECT COUNT(*),COALESCE(SUM(bytes),0),COALESCE(SUM(is_anomaly),0) FROM connections").fetchone()
            active = self.db.execute("SELECT COUNT(*) FROM incidents WHERE status!='resolved'").fetchone()[0]
            traffic = [dict(r) for r in self.db.execute("SELECT substr(timestamp,1,16)||':00+00:00' AS timestamp,COUNT(*) AS connections,SUM(bytes) AS bytes,SUM(is_anomaly) AS anomalies FROM connections GROUP BY substr(timestamp,1,16) ORDER BY timestamp DESC LIMIT 30")][::-1]
            protocols = [dict(r) for r in self.db.execute("SELECT UPPER(protocol) AS name,COUNT(*) AS value FROM connections GROUP BY protocol ORDER BY value DESC")]
            devices = [dict(r) for r in self.db.execute("SELECT src_ip AS ip,COUNT(*) AS connections,SUM(bytes) AS bytes FROM connections GROUP BY src_ip ORDER BY bytes DESC LIMIT 6")]
            stats = [dict(r) for r in self.db.execute("SELECT detection_source AS name,COUNT(*) AS value FROM incidents GROUP BY detection_source")]
            sources = {"demo": 0, "lab": 0}
            sources.update({r["origin"]: r["count"] for r in self.db.execute("SELECT origin,COUNT(*) AS count FROM connections GROUP BY origin")})
            return dict(total_connections=totals[0], total_bytes=totals[1], active_incidents=active, anomaly_rate=round(totals[2] / totals[0] * 100, 2) if totals[0] else 0, traffic=traffic, protocols=protocols, top_devices=devices, detection_stats=stats, recent_connections=self.connections(limit=8)["items"], recent_incidents=self.incidents(limit=5)["items"], data_sources=sources, simulated=sources["lab"] == 0 and sources.get("live", 0) == 0)

    def reset_demo(self):
        with self.transaction() as db:
            db.execute("DELETE FROM incidents WHERE origin='demo'")
            db.execute("DELETE FROM connections WHERE origin='demo'")
