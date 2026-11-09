"""FastAPI application. Basic startup is entirely passive and requires no privileges."""
import asyncio
import copy
from contextlib import asynccontextmanager
from dataclasses import asdict
from datetime import datetime
import logging
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import threading
import time

from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from detection.assessment import baseline_assessment

from .demo import demo_records
from .ingestion import parse_pcap, parse_zeek
from .limits import BodyLimitMiddleware
from .live_detection import LIVE_POLICY, LiveRuleEngine, evaluate_context
from .monitoring import loopback_peer, monitoring_status, validate_database_role
from .rules import RuleEngine
from .schemas import IncidentPatch, MetadataBatch, SimulationStart, ZeekUpload
from .security import monitor_host_allowed, monitor_origin_allowed
from .storage import Store, utcnow

ROOT = Path(__file__).resolve().parents[2]
logger = logging.getLogger("sentinel")


class NoModel:
    ready = False
    metadata = {"algorithm": "Isolation Forest", "status": "unavailable", "limitations": ["Model artifact unavailable; rule detection remains active."]}

    def predict(self, record):
        return {"is_anomaly": False, "score": 0.0, "indicators": []}


class Runtime:
    def __init__(self, db_path: str, seed=True, detector=None, *, allow_lab_data=False, monitor_mode=False, monitor_max_rows=5000, public_demo=False):
        if monitor_mode and seed:
            raise ValueError("Synthetic seeding is forbidden in monitor mode")
        if public_demo and (monitor_mode or allow_lab_data):
            raise ValueError("The public demonstration cannot enable private monitoring or lab imports")
        mode = "public_demo" if public_demo else "monitor" if monitor_mode else "lab" if allow_lab_data else "demo"
        validate_database_role(db_path, mode)
        self.store = Store(db_path)
        self.monitor_mode = monitor_mode
        self.public_demo = public_demo
        self.monitor_max_rows = monitor_max_rows
        if monitor_mode:
            self.store.enable_monitor_storage()
        if public_demo:
            self.store.set_meta("database_role", "public_demo")
        if not allow_lab_data and self.store.has_lab_data():
            self.store.close()
            raise ValueError("Demo mode refuses a database containing lab traffic or incidents. Set SENTINEL_DB_PATH to a separate empty demo database, or enable SENTINEL_LAB_MODE=true for your authorized local lab. Never expose lab data in a public demo.")
        self.rules = {origin: RuleEngine() for origin in ("demo", "lab", "live")}
        self.rules["live"] = LiveRuleEngine()
        self.started = time.monotonic()
        self.task = None
        # Demo and lab windows remain independent; each batch is ordered within its origin.
        self.ingestion_locks = {origin: threading.RLock() for origin in ("demo", "lab", "live")}
        self.detector = detector
        if detector is None:
            try:
                from detection.ml import Detector
                self.detector = Detector()
            except (ImportError, OSError, ValueError, RuntimeError):
                logger.warning("ML artifact unavailable. Running rule-based detection only.")
                self.detector = NoModel()
        anchor = self.store.get_meta("demo_anchor")
        self.records = demo_records(anchor=datetime.fromisoformat(anchor) if anchor else None)
        self.store.set_meta("demo_anchor", self.records[0]["timestamp"])
        stored = self.store.get_meta("simulation")
        self.simulation = stored or dict(status="idle", processed=0, total=len(self.records), speed=4)
        if self.simulation["status"] == "running":
            self.simulation["status"] = "paused"
        if not stored and seed:
            initial_count = len(self.records) if public_demo else 120
            for record in self.records[:initial_count]:
                self.ingest(record, "demo")
            self.simulation["processed"] = initial_count
            if public_demo:
                self.simulation["status"] = "completed"
        elif self.simulation["processed"]:
            # Rebuild only the recent rule window without duplicating persisted records.
            for record in self.records[max(0, self.simulation["processed"] - 25):self.simulation["processed"]]:
                self.rules["demo"].inspect(record)
        if monitor_mode:
            for record in sorted(self.store.connections(limit=monitor_max_rows)["items"], key=lambda item: item["timestamp"]):
                self.rules["live"].inspect(record, port_scan_eligible=record.get("provenance", {}).get("local_role") == "initiator")
        self.save_state()

    def save_state(self):
        self.store.set_meta("simulation", self.simulation)

    def ingest(self, record, origin="demo"):
        if (origin == "live") != self.monitor_mode:
            raise ValueError("Live monitoring and demo/lab records must use separate runtime databases")
        with self.ingestion_locks[origin]:
            payload, hits = self.prepare_record(record, origin)
            return self.store.insert(payload, origin, hits)

    def prepare_record(self, record, origin):
        if self.public_demo and origin != "demo":
            raise ValueError("Only synthetic demo records belong in the public demonstration")
        eligible = origin != "live" or record.get("provenance", {}).get("local_role") == "initiator"
        hits = [dict(asdict(hit), detection_source="rule") for hit in self.rules[origin].inspect(record, port_scan_eligible=eligible)]
        prediction = self.detector.predict(record)
        if origin != "live" and prediction.get("is_anomaly"):
            hits.append(dict(rule_id="ml_anomaly", title="Machine-learning anomaly", severity="medium", description="Isolation Forest flagged an unusual traffic feature combination. This is a statistical anomaly, not proof of an attack.", indicators=list(prediction.get("indicators", [])), detection_source="ml"))
        if origin == "live":
            for hit in hits:
                hit["indicators"] += ["Passive interface flow-window metadata; no authentication or process attribution", f"Observed local role: {record['provenance']['local_role']}"]
        score = float(prediction.get("score", 0))
        payload = dict(record, is_anomaly=bool(hits), anomaly_score=score)
        if origin == "live":
            assessment = self.assess_baseline(record, score if self.detector.ready else None,
                                              threshold_source="stored_at_ingest", score_source="computed_at_ingest")
            payload.update(model_assessment=assessment, live_policy=LIVE_POLICY["version"],
                           anomaly_score=assessment["score"])
        return payload, hits

    def assess_baseline(self, record, score, *, threshold_source="current_baseline_reference", score_source="stored_connection"):
        artifact = getattr(self.detector, "model", None)
        artifact = artifact if isinstance(artifact, dict) else {}
        metadata = self.detector.metadata
        return baseline_assessment(record, score=score,
            threshold=artifact.get("threshold", metadata.get("threshold")),
            model_version=metadata.get("model_version"), threshold_source=threshold_source,
            score_source=score_source, benign_categories=artifact.get("benign_categories"))

    def connection_view(self, record):
        if record is None:
            return record
        if record.get("origin") == "lab" and record.get("provenance", {}).get("collector") == "localhost-lab":
            context = evaluate_context(record)
            context["observation_limits"] = [
                "Measurements came from owned loopback application sockets, not Ethernet packets or a packet decoder.",
                "Application bytes and successful exchanges are verified only for this controlled local exercise.",
                "DNS/discovery and router-role simulations do not verify a home router, multicast network or Internet application.",
            ]
            return dict(record, analysis=context)
        if record.get("origin") != "live":
            return record
        assessment = record.get("model_assessment")
        if not isinstance(assessment, dict):
            # Legacy scores are read, never recalculated or backfilled in SQLite.
            assessment = self.assess_baseline(record, record.get("anomaly_score"))
        return dict(record, analysis=dict(evaluate_context(record), model_assessment=assessment))

    def incident_view(self, incident):
        if incident is None:
            return None
        connection = self.connection_view(self.store.get_connection(incident.get("connection_id")))
        result = dict(incident, connection=connection)
        if incident.get("origin") == "live":
            historical = incident.get("detection_source") == "ml" and not (connection and connection.get("live_policy"))
            assessment = (connection or {}).get("analysis", {})
            notice = ("Historical benchmark anomaly retained unchanged. Its score and category/range hints are not validated live threat evidence; review compatibility and independent context."
                      if incident.get("detection_source") == "ml" else
                      "A live rule's observed conditions were met. This is evidence of that pattern, not confirmation of an attack; consider legitimate causes and collection limits.")
            result["analysis"] = dict(assessment, historical_alert=historical,
                explanation_kind="benchmark_heuristic" if incident.get("detection_source") == "ml" else "rule_trigger", notice=notice)
        elif connection and connection.get("provenance", {}).get("collector") == "localhost-lab":
            result["analysis"] = dict(connection["analysis"], historical_alert=False,
                explanation_kind="rule_trigger", notice="This controlled-lab finding uses genuine events from owned loopback services and application byte counters. It does not establish detection accuracy on physical Ethernet traffic.")
        return result

    def ingest_metadata(self, batch_id, records):
        if not self.monitor_mode:
            raise HTTPException(403, "Metadata ingestion requires the separate monitor runtime")
        fingerprint = hashlib.sha256(json.dumps(records, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        with self.ingestion_locks["live"]:
            previous = self.store.monitor_batch(batch_id)
            if previous:
                if previous["fingerprint"] != fingerprint:
                    raise HTTPException(409, "Batch ID already exists with different metadata")
                return dict(batch_id=batch_id, origin="live", ingested=0, duplicate=True, retained_records=self.store.live_count())
            count = self.store.live_count()
            if count + len(records) > self.monitor_max_rows:
                raise HTTPException(507, "Monitoring row cap reached or batch would exceed it. No records were deleted or added. Stop collection and explicitly select a new dedicated monitor database.")
            old_rules = copy.deepcopy(self.rules["live"])
            try:
                # Inference runs in this worker thread before the short atomic SQLite write.
                prepared = [self.prepare_record(record, "live") for record in sorted(records, key=lambda r: r["timestamp"])]
                last = utcnow()
                stats = self.store.get_meta("monitoring", {})
                first = records[0]["provenance"]
                stats.update(last_ingest_at=last, ingested_records=stats.get("ingested_records", 0) + len(records),
                             collector=first["collector"], interface_label=first["interface_label"],
                             measurement_semantics=first["measurement_semantics"], observation_scope=first["observation_scope"])
                with self.store.transaction():
                    # Recheck under the SQLite writer lock so even overlapping local
                    # senders cannot exceed the cap or commit a repeated batch.
                    self.store.db.execute("BEGIN IMMEDIATE")
                    concurrent = self.store.monitor_batch(batch_id)
                    if concurrent:
                        self.rules["live"] = old_rules
                        if concurrent["fingerprint"] != fingerprint:
                            raise HTTPException(409, "Batch ID already exists with different metadata")
                        return dict(batch_id=batch_id, origin="live", ingested=0, duplicate=True, retained_records=self.store.live_count())
                    count = self.store.live_count()
                    if count + len(records) > self.monitor_max_rows:
                        raise HTTPException(507, "Monitoring row cap reached; no records were deleted or added")
                    stats["ingested_records"] = count + len(records)
                    for payload, hits in prepared:
                        self.store.insert(payload, "live", hits)
                    self.store.save_monitor_batch(batch_id, fingerprint, len(records), last, stats)
            except sqlite3.IntegrityError as exc:
                self.rules["live"] = old_rules
                raise HTTPException(409, "A flow from this collection was already ingested. Retry only the original unchanged batch ID.") from exc
            except Exception:
                self.rules["live"] = old_rules
                raise
            return dict(batch_id=batch_id, origin="live", ingested=len(records), duplicate=False, retained_records=count + len(records))

    def ingest_batch(self, records, origin="lab"):
        with self.ingestion_locks[origin]:
            for record in records:
                self.ingest(record, origin)

    async def replay(self):
        try:
            while self.simulation["status"] == "running" and self.simulation["processed"] < len(self.records):
                index = self.simulation["processed"]
                self.ingest(self.records[index])
                self.simulation["processed"] += 1
                self.save_state()
                await asyncio.sleep(1 / self.simulation["speed"])
            if self.simulation["processed"] >= len(self.records):
                self.simulation["status"] = "completed"
                self.save_state()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Replay stopped after an internal processing failure")
            self.simulation["status"] = "paused"
            self.save_state()

    async def stop(self):
        if self.task and not self.task.done():
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass
        self.task = None


def create_app(db_path: str | None = None, *, seed: bool | None = None, lab_mode: bool | None = None, pcap_enabled: bool | None = None, api_key: str | None = None, detector=None, monitor_mode: bool | None = None, monitor_max_rows=5000, public_demo: bool | None = None):
    configured_lab = lab_mode if lab_mode is not None else os.getenv("SENTINEL_LAB_MODE", "false").lower() == "true"
    configured_pcap = pcap_enabled if pcap_enabled is not None else os.getenv("SENTINEL_PCAP_ENABLED", "false").lower() == "true"
    configured_key = api_key if api_key is not None else os.getenv("SENTINEL_API_KEY", "")
    configured_monitor = monitor_mode if monitor_mode is not None else os.getenv("SENTINEL_MONITOR_MODE", "false").lower() == "true"
    configured_public = public_demo if public_demo is not None else os.getenv("SENTINEL_PUBLIC_DEMO", "false").lower() == "true"
    database = db_path or os.getenv("SENTINEL_DB_PATH", str(ROOT / "data" / "sentinel.db"))
    mode = "monitor" if configured_monitor else "lab" if configured_lab else "demo"
    capabilities = dict(incident_write=not configured_public, simulation_control=not configured_public and not configured_monitor)

    @asynccontextmanager
    async def lifespan(app):
        if configured_public:
            if configured_monitor or configured_lab or configured_pcap:
                raise ValueError("Public demo mode forbids monitoring, lab imports and PCAP processing")
            if not (db_path or os.getenv("SENTINEL_DB_PATH")) or (database != ":memory:" and Path(database).resolve() == (ROOT / "data" / "sentinel.db").resolve()):
                raise ValueError("Public demo mode requires its own explicitly selected database, separate from the existing demo and private evidence")
        if configured_monitor:
            if configured_lab:
                raise ValueError("Choose monitor mode or lab mode separately; they cannot be enabled together")
            if not (db_path or os.getenv("SENTINEL_DB_PATH")) or (database != ":memory:" and Path(database).resolve() == (ROOT / "data" / "sentinel.db").resolve()):
                raise ValueError("Monitor mode requires an explicitly selected separate SENTINEL_DB_PATH; the default demo database is forbidden")
            if seed:
                raise ValueError("Synthetic seeding is forbidden in monitor mode")
        if not 1 <= monitor_max_rows <= 5000:
            raise ValueError("Monitor row cap must be between 1 and 5000")
        app.state.runtime = Runtime(database, seed=(not configured_lab and not configured_monitor) if seed is None else seed,
                                    detector=detector, allow_lab_data=configured_lab,
                                    monitor_mode=configured_monitor, monitor_max_rows=monitor_max_rows, public_demo=configured_public)
        yield
        runtime = app.state.runtime
        await runtime.stop()
        if runtime.simulation["status"] == "running":
            runtime.simulation["status"] = "paused"
            runtime.save_state()
        runtime.store.close()

    app = FastAPI(title="Sentinel AI", description="Passive security analytics with an explicitly synthetic demonstration replay.", version="1.0.0", lifespan=lifespan)
    app.add_middleware(BodyLimitMiddleware)
    origins = [item.strip() for item in os.getenv("SENTINEL_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173,http://localhost:8080,http://127.0.0.1:8080").split(",") if item.strip()]
    app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=False, allow_methods=["GET", "POST", "PATCH"], allow_headers=["Content-Type", "X-Sentinel-Key"])

    @app.middleware("http")
    async def safety_headers(request, call_next):
        if configured_monitor or configured_lab:
            if not loopback_peer(request.client.host if request.client else None):
                return JSONResponse(status_code=403, content={"detail": "Private monitoring and lab APIs are restricted to loopback clients"})
            host_headers = [value for name, value in request.scope.get("headers", []) if name.lower() == b"host"]
            if len(host_headers) != 1 or not monitor_host_allowed(request.headers.get("host")):
                return JSONResponse(status_code=403, content={"detail": "Private API requires a literal loopback Host"})
            if request.method not in {"GET", "HEAD", "OPTIONS"} and not monitor_origin_allowed(request.headers.get("origin"), origins):
                return JSONResponse(status_code=403, content={"detail": "Private API rejected an untrusted browser Origin"})
            if request.method not in {"GET", "HEAD", "OPTIONS"} and sum(name.lower() == b"origin" for name, _ in request.scope.get("headers", [])) > 1:
                return JSONResponse(status_code=403, content={"detail": "Private API requires at most one browser Origin"})
        if configured_public and request.method not in {"GET", "HEAD", "OPTIONS"}:
            return JSONResponse(status_code=403, content={"detail": "The public demonstration is a read-only synthetic snapshot"})
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    @app.exception_handler(Exception)
    async def unhandled_error(request, exc):
        logger.error("Request failed: %s", type(exc).__name__)
        return JSONResponse(status_code=500, content={"detail": "Internal service error. See local service logs."})

    def runtime(request: Request) -> Runtime:
        return request.app.state.runtime

    def authorize_lab(key):
        if not configured_lab:
            raise HTTPException(403, "Lab ingestion is disabled. Synthetic demo mode is active.")
        if not configured_key:
            raise HTTPException(503, "Set SENTINEL_API_KEY before enabling lab imports.")
        if not key or not secrets.compare_digest(key, configured_key):
            raise HTTPException(401, "A valid X-Sentinel-Key header is required for lab ingestion.")

    def authorize_monitor(key):
        if not configured_monitor:
            raise HTTPException(403, "Passive metadata ingestion is disabled; enable only a separate local monitor instance")
        if not configured_key:
            raise HTTPException(503, "Set SENTINEL_API_KEY before sending private monitoring metadata")
        if not key or not secrets.compare_digest(key, configured_key):
            raise HTTPException(401, "A valid X-Sentinel-Key header is required for monitoring metadata")

    @app.get("/api/health")
    async def health(request: Request):
        rt = runtime(request)
        return {"status": "ok", "mode": mode, "public_demo": configured_public, "capabilities": capabilities, "simulated": mode == "demo", "model_loaded": bool(rt.detector.ready), "version": "1.0.0", "monitoring_status": monitoring_status(rt, configured_monitor)["status"]}

    @app.get("/api/overview")
    async def overview(request: Request):
        rt = runtime(request)
        result = dict(rt.store.overview(), simulation=dict(rt.simulation), mode=mode, public_demo=configured_public, capabilities=capabilities, monitoring=monitoring_status(rt, configured_monitor))
        if configured_lab:
            result["recent_connections"] = [rt.connection_view(record) for record in result["recent_connections"]]
        if configured_monitor:
            result["simulated"] = False
            result["data_sources"].setdefault("live", 0)
            result["recent_connections"] = [rt.connection_view(record) for record in result["recent_connections"]]
            result["live_detection_policy"] = LIVE_POLICY
        return result

    @app.get("/api/connections")
    async def connections(request: Request, q: str = Query("", max_length=150), protocol: str = Query("", pattern="^(tcp|udp|icmp)?$"), limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
        rt = runtime(request)
        result = rt.store.connections(q, protocol, limit, offset)
        if configured_monitor or configured_lab:
            result["items"] = [rt.connection_view(record) for record in result["items"]]
        return result

    @app.get("/api/incidents")
    async def incidents(request: Request, severity: str = Query("", pattern="^(critical|high|medium|low)?$"), status: str = Query("", pattern="^(open|investigating|resolved)?$"), source: str = Query("", pattern="^(rule|ml)?$"), q: str = Query("", max_length=150), limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
        return runtime(request).store.incidents(severity, status, source, q, limit, offset)

    @app.get("/api/incidents/{incident_id}")
    async def incident(request: Request, incident_id: str):
        rt = runtime(request)
        result = rt.incident_view(rt.store.get_incident(incident_id))
        if result is None:
            raise HTTPException(404, "Incident not found")
        return result

    @app.patch("/api/incidents/{incident_id}")
    async def update_incident(request: Request, incident_id: str, patch: IncidentPatch):
        if patch.status is None and (patch.note is None or not patch.note.strip()):
            raise HTTPException(422, "Provide a status or nonempty investigation note")
        rt = runtime(request)
        result = rt.incident_view(rt.store.patch_incident(incident_id, patch.status, patch.note.strip() if patch.note else None))
        if result is None:
            raise HTTPException(404, "Incident not found")
        return result

    @app.get("/api/model")
    async def model(request: Request):
        rt = runtime(request)
        return dict(rt.detector.metadata, ready=bool(rt.detector.ready), loaded=bool(rt.detector.ready),
                    operating_mode=mode, live_detection_policy=LIVE_POLICY if configured_monitor else None,
                    demo_notice="Replay traffic is synthetic. Dataset evaluation does not establish live-network performance.")

    @app.get("/api/system")
    async def system(request: Request):
        rt = runtime(request)
        return {"mode": mode, "public_demo": configured_public, "capabilities": capabilities, "uptime_seconds": round(time.monotonic() - rt.started), "model_loaded": bool(rt.detector.ready), "database": "SQLite / WAL", "ingestion": "passive metadata API" if configured_monitor else "passive file import" if configured_lab else "synthetic replay", "pcap_enabled": configured_lab and configured_pcap, "services": [{"name": "API service", "status": "healthy"}, {"name": "SQLite storage", "status": "healthy"}, {"name": "Rule engine", "status": "healthy"}, {"name": "Isolation Forest baseline reference" if configured_monitor else "Isolation Forest", "status": "healthy" if rt.detector.ready else "unavailable"}], "live_detection_policy": LIVE_POLICY if configured_monitor else None, "monitoring": monitoring_status(rt, configured_monitor), "safety": "This API never starts capture, scans, responds actively, or blocks traffic. An independently authorized local collector can submit bounded metadata in monitor mode."}

    @app.get("/api/monitor/status")
    async def monitor_status(request: Request, x_sentinel_key: str | None = Header(None)):
        authorize_monitor(x_sentinel_key)
        state = monitoring_status(runtime(request), True)
        return dict(mode="monitor", enabled=True, ingestion_enabled=not state["capacity_reached"], database_isolated=True, monitoring=state)

    @app.post("/api/ingest/metadata")
    async def ingest_metadata(request: Request, batch: MetadataBatch, x_sentinel_key: str | None = Header(None)):
        authorize_monitor(x_sentinel_key)
        rt = runtime(request)
        records = [record.model_dump(mode="json", exclude_none=True) for record in batch.records]
        result = await asyncio.to_thread(rt.ingest_metadata, batch.batch_id, records)
        return dict(result, monitoring=monitoring_status(rt, True))

    @app.get("/api/simulation")
    async def simulation(request: Request):
        return dict(runtime(request).simulation)

    @app.post("/api/simulation/start")
    async def start(request: Request, settings: SimulationStart = SimulationStart()):
        if configured_monitor:
            raise HTTPException(403, "Synthetic replay is disabled in the separate live monitor instance")
        rt = runtime(request)
        rt.simulation["speed"] = settings.speed
        if rt.simulation["status"] != "running" and rt.simulation["processed"] < len(rt.records):
            rt.simulation["status"] = "running"
            rt.task = asyncio.create_task(rt.replay())
        rt.save_state()
        return dict(rt.simulation)

    @app.post("/api/simulation/pause")
    async def pause(request: Request):
        if configured_monitor:
            raise HTTPException(403, "Replay controls cannot stop an external collector; stop that explicitly authorized local process separately")
        rt = runtime(request)
        await rt.stop()
        if rt.simulation["status"] == "running":
            rt.simulation["status"] = "paused"
        rt.save_state()
        return dict(rt.simulation)

    @app.post("/api/simulation/reset")
    async def reset(request: Request):
        if configured_monitor:
            raise HTTPException(403, "Monitor data cannot be reset through replay controls; no evidence was deleted")
        rt = runtime(request)
        await rt.stop()
        rt.store.reset_demo()
        rt.rules["demo"].reset()
        rt.simulation.update(status="idle", processed=0)
        rt.save_state()
        return dict(rt.simulation)

    @app.post("/api/ingest/zeek")
    async def ingest_zeek(request: Request, upload: ZeekUpload, x_sentinel_key: str | None = Header(None)):
        authorize_lab(x_sentinel_key)
        try:
            records = await asyncio.to_thread(parse_zeek, upload.content, upload.format)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        rt = runtime(request)
        await asyncio.to_thread(rt.ingest_batch, records, "lab")
        return {"ingested": len(records), "origin": "lab", "source": "zeek"}

    @app.post("/api/ingest/pcap")
    async def ingest_pcap(request: Request, x_sentinel_key: str | None = Header(None)):
        authorize_lab(x_sentinel_key)
        if not configured_pcap:
            raise HTTPException(403, "Offline PCAP import is disabled; set SENTINEL_PCAP_ENABLED=true")
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 20_000_000:
                raise HTTPException(413, "PCAP maximum size is 20 MB")
        try:
            records = await asyncio.to_thread(parse_pcap, bytes(body))
        except RuntimeError as exc:
            raise HTTPException(503, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        await asyncio.to_thread(runtime(request).ingest_batch, records, "lab")
        return {"ingested": len(records), "origin": "lab", "source": "pcap", "limitations": "First 50,000 packets; TCP/UDP only; coarse bidirectional five-tuple aggregates can merge reused sessions; frame lengths rather than application payload bytes; inferred flow state."}

    return app


app = create_app()
