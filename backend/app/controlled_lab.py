"""Opt-in owned-loopback experiments; application instrumentation, never capture.

Importing this module performs no network, model or database activity. Only a fresh
run directory is accepted. No caller-supplied destination, capture tool or API key
is used. The unchanged live rules are evaluated against measured application
bytes; this verifies that policy, not the Ethernet packet-decoding pipeline.
"""
from __future__ import annotations

from collections import Counter
from contextlib import AbstractContextManager
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import socket
import socketserver
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import uuid

from .live_detection import LIVE_POLICY, LiveRuleEngine
from .schemas import Connection
from .storage import Store

LOOPBACK = "127.0.0.1"
LARGE_BYTES = 6 * 1024 * 1024
MAX_BODY = 7 * 1024 * 1024
PACE = .25  # At most four initiated exchanges/second; not a stress/load test.
SOURCE = "actual_owned_loopback_endpoint_instrumentation"
SCENARIOS = {
    "port_probe": (8, "Eight retained TCP banner ports", "port_scan", "high"),
    "connection_burst": (25, "25 separate TCP exchanges to one owned port", "connection_frequency", "medium"),
    "outbound_volume": (4, "Three 2 KiB uploads and one verified 6 MiB upload", "traffic_spike", "medium"),
    "normal_https": (3, "Small HTTPS requests with local certificate verification", None, None),
    "normal_dns": (3, "Valid DNS question/NXDOMAIN responses on owned loopback UDP", None, None),
    "local_discovery": (3, "SSDP-format unicast request/responses on loopback", None, None),
    "router_like": (3, "Small HTTP status requests to an owned router-role simulator", None, None),
}
LIMITATIONS = [
    "This is endpoint application/socket instrumentation, not TShark, Zeek or packet capture.",
    "Application byte counts exclude TCP/IP, TLS/HTTP headers and retransmissions; the Ethernet decoder/API path is not exercised.",
    "All destinations are retained 127.0.0.1 listeners. Ephemeral ports do not verify conventional port-443/53/1900 context labels.",
    "Unicast discovery and a router-role simulator do not test actual multicast, a home router or other devices.",
    "Each scenario has a separate collection UUID, preventing cross-scenario evidence contamination; real cross-collection behavior remains a documented blind spot.",
    "Authorized port discovery, legitimate connection bursts and legitimate large uploads can trigger the same review rules.",
    "Slow probes, unknown/responder TCP roles, UDP scans and low-volume malicious intent can be missed; these experiments do not estimate real-world accuracy.",
    "The historical Isolation Forest is neither loaded nor scored by this runner. No thresholds are changed.",
]


def utc(epoch=None):
    return datetime.fromtimestamp(time.time() if epoch is None else epoch, timezone.utc).isoformat()


def plan():
    return dict(execution="disabled", bind_address=LOOPBACK, capture=False,
        source=SOURCE, database="New exclusive controlled-lab.db; origin=lab; role=controlled_lab",
        scenarios={name: dict(expected_exchanges=spec[0], activity=spec[1], expected_rule=spec[2], expected_severity=spec[3])
                   for name, spec in SCENARIOS.items()}, limitations=LIMITATIONS)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _validate_record(record):
    """Reject capture-shaped/mislabelled or unowned evidence before persistence."""
    base = Connection.model_validate(record).model_dump(mode="json")
    p = record.get("provenance", {})
    fields = {"collector", "measurement_semantics", "observation_scope", "flow_semantics", "process_scope",
              "flow_id", "collection_id", "first_seen", "last_seen", "local_role", "direction_basis",
              "protocol_verified", "scenario", "source", "event_id", "verified_payload_bytes", "payload_sha256"}
    if set(p)-fields:
        raise ValueError("Only approved endpoint provenance fields are accepted")
    if base["src_ip"] != LOOPBACK or base["dst_ip"] != LOOPBACK:
        raise ValueError("Controlled evidence must have literal owned IPv4 loopback endpoints")
    if base["protocol"] not in {"tcp", "udp"} or base["status"] != "established":
        raise ValueError("Only completed bidirectional socket exchanges are accepted")
    if not (0 < base["src_port"] <= 65535 and 0 < base["dst_port"] <= 65535):
        raise ValueError("Actual assigned socket ports are required")
    if max(base["bytes_sent"], base["bytes_received"]) > MAX_BODY:
        raise ValueError("Lab application byte count exceeds its bound")
    if p.get("collector") != "localhost-lab" or p.get("measurement_semantics") != "application_bytes" or p.get("observation_scope") != "owned_loopback_services":
        raise ValueError("Truthful owned endpoint provenance is required")
    if any(key in p for key in ("packet_count", "transport_flags_observed", "interface_id")):
        raise ValueError("Endpoint instrumentation must not claim packet/interface evidence")
    if p.get("local_role") != "initiator" or p.get("direction_basis") != "client_to_owned_service":
        raise ValueError("The client must have initiated the measured owned exchange")
    if p.get("flow_semantics") != "completed_socket_exchange" or p.get("process_scope") != "owned_lab_processes_only" or p.get("source") != SOURCE:
        raise ValueError("Owned application instrumentation semantics are required")
    if p.get("protocol_verified") not in {"tcp_banner_exchange", "http", "https_tls_verified", "dns_request_response", "ssdp_format_unicast"}:
        raise ValueError("An explicitly verified owned protocol exchange is required")
    event_id = p.get("event_id", "")
    if len(event_id) != 32 or any(c not in "0123456789abcdef" for c in event_id):
        raise ValueError("A bounded event identity is required")
    if "verified_payload_bytes" in p or "payload_sha256" in p:
        digest = p.get("payload_sha256", "")
        if p.get("verified_payload_bytes") != base["bytes_sent"] or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("Verified upload count and SHA256 must agree with the observation")
    uuid.UUID(p["collection_id"])
    if len(p.get("flow_id", "")) != 40 or any(c not in "0123456789abcdef" for c in p["flow_id"]):
        raise ValueError("A bounded flow identity is required")
    first, last = (datetime.fromisoformat(p[key]) for key in ("first_seen", "last_seen"))
    if first.tzinfo is None or last.tzinfo is None or last < first or base["timestamp"] != p["first_seen"]:
        raise ValueError("Actual ordered UTC observation times are required")
    if base["scenario"] != "controlled_localhost_" + p.get("scenario", "") or p.get("scenario") not in SCENARIOS:
        raise ValueError("A declared controlled scenario is required")
    return dict(base, provenance=p)


def _lab_hit(hit):
    """Keep the rule/threshold, describe the actual measurement source accurately."""
    item = dict(asdict(hit), detection_source="rule")
    replacements = {
        "header-derived outbound transport length bytes": "measured outbound application bytes",
        "Observed outbound transport length counters": "Measured outbound application byte counters",
        "Retransmissions may be counted; payload/content and intent were not inspected.":
            "Application bytes were verified at both endpoints; network retransmissions/headers were not measured and malicious intent is not established.",
        "A legitimate upload or retransmissions can trigger it": "A legitimate upload can trigger it",
        "Unique flow IDs within one collection; partial capture can miss activity.":
            "Unique completed owned socket exchanges in one scenario; no packet capture was performed.",
    }
    for key in ("description", "indicators"):
        values = [item[key]] if key == "description" else item[key]
        for old, new in replacements.items():
            values = [text.replace(old, new) for text in values]
        item[key] = values[0] if key == "description" else values
    item["description"] += " Source: controlled localhost endpoint instrumentation; this is a review condition, not a confirmed attack."
    return item


class LabEvidenceStore(AbstractContextManager):
    """Fresh database only; unchanged-evidence replay is atomic and idempotent."""
    def __init__(self, path):
        self.path = Path(path)
        # Exclusive creation occurs before SQLite opens; existing databases are refused.
        with self.path.open("xb"):
            pass
        self.store = Store(str(self.path))
        self.store.set_meta("database_role", "controlled_lab")
        self.store.set_meta("controlled_lab_policy", LIVE_POLICY)
        with self.store.transaction() as db:
            db.execute("CREATE TABLE controlled_lab_batches (batch_id TEXT PRIMARY KEY,fingerprint TEXT NOT NULL)")
            db.execute("CREATE UNIQUE INDEX ix_controlled_lab_flow ON connections(json_extract(payload,'$.provenance.collection_id'),json_extract(payload,'$.provenance.flow_id')) WHERE origin='lab'")

    def persist(self, batch_id, records):
        if batch_id not in SCENARIOS or not 0 < len(records) <= 250:
            raise ValueError("Only bounded declared scenario batches are accepted")
        records = [_validate_record(record) for record in records]
        if any(r["provenance"]["scenario"] != batch_id for r in records):
            raise ValueError("Scenario batch and records disagree")
        if len({r["provenance"]["collection_id"] for r in records}) != 1:
            raise ValueError("One isolated collection per scenario is required")
        if len({r["provenance"]["flow_id"] for r in records}) != len(records):
            raise ValueError("A scenario batch must not contain duplicate flow identities")
        fingerprint = hashlib.sha256(_canonical(records).encode()).hexdigest()
        with self.store.transaction() as db:
            previous = db.execute("SELECT fingerprint FROM controlled_lab_batches WHERE batch_id=?", (batch_id,)).fetchone()
            if previous:
                if previous[0] != fingerprint:
                    raise ValueError("Existing evidence batch differs; never replace or append to it")
                return dict(ingested=0, duplicate=True)
            engine = LiveRuleEngine()
            for record in sorted(records, key=lambda r: r["timestamp"]):
                hits = [_lab_hit(hit) for hit in engine.inspect(record)]
                payload = dict(record, is_anomaly=bool(hits), anomaly_score=None, live_policy=LIVE_POLICY["version"])
                self.store.insert(payload, "lab", hits)
            db.execute("INSERT INTO controlled_lab_batches VALUES (?,?)", (batch_id, fingerprint))
        return dict(ingested=len(records), duplicate=False)

    def __exit__(self, *_):
        self.store.close()


class _TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = False
    daemon_threads = False
    block_on_close = True

    def handle_error(self, *_):
        pass  # Bounded failures are reported through missing verified evidence.


class _UDPServer(socketserver.UDPServer):
    max_packet_size = 2048

    def handle_error(self, *_):
        pass


class _HTTPServer(ThreadingHTTPServer):
    allow_reuse_address = False
    daemon_threads = False
    block_on_close = True

    def handle_error(self, *_):
        pass

    def get_request(self):
        sock, address = super().get_request()
        sock.settimeout(5)
        if getattr(self, "tls_context", None):
            try:
                sock = self.tls_context.wrap_socket(sock, server_side=True)
            except BaseException:
                sock.close()
                raise
        return sock, address


def _dns_response(query):
    # One actual IN/A question for a reserved .invalid name, no upstream resolver.
    question = b"\x0csentinel-lab\x07invalid\x00\x00\x01\x00\x01"
    if len(query) < 12 or query[2:] != b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + question:
        raise ValueError("Unexpected bounded lab DNS question")
    return query[:2] + b"\x81\x83\x00\x01\x00\x00\x00\x00\x00\x00" + question


class OwnedServices(AbstractContextManager):
    def __init__(self, directory):
        self.directory = Path(directory)
        self._servers, self._threads = [], []
        self._condition = threading.Condition()
        self._pending, self._server_events = {}, {}
        self.client_events = []
        self._active = False
        self.tls_error = None
        self._tls_temp = None

    def _server_event(self, peer, port, sent, received, verified, **extras):
        with self._condition:
            pending = self._pending.get((peer[1], port))
            if peer[0] != LOOPBACK or pending is None:
                raise ValueError("Unowned loopback exchange")
            event = dict(event_id=pending["event_id"], scenario=pending["scenario"],
                timestamp=utc(), src_ip=peer[0], src_port=peer[1], dst_ip=LOOPBACK, dst_port=port,
                application_bytes_received=sent, application_bytes_sent=received,
                protocol_verified=verified, source=SOURCE, **extras)
            self._server_events[pending["event_id"]] = event
            self._condition.notify_all()

    def _tls(self):
        if os.name == "nt":
            # Never search the working directory/PATH for an executable on Windows.
            program_files = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
            # Native MinGW executables avoid the MSYS shared-object requirement
            # that can prevent Git's POSIX executable starting in a sandbox.
            candidates = [Path(r"C:\msys64\mingw64\bin\openssl.exe"),
                          program_files/"Git"/"mingw64"/"bin"/"openssl.exe",
                          program_files/"Git"/"usr"/"bin"/"openssl.exe"]
            binary = next((str(path) for path in candidates if path.is_file()), None)
        else:
            binary = shutil.which("openssl")
        if not binary:
            self.tls_error = "Existing local OpenSSL not found; no install or OS trust changes attempted"
            return None
        self._tls_temp = tempfile.TemporaryDirectory(prefix="disposable-tls-", dir=self.directory)
        folder = Path(self._tls_temp.name)
        key, cert = folder / "key.pem", folder / "cert.pem"
        # Fixed local certificate command; inherited API credentials are not passed.
        env = {k: v for k, v in os.environ.items() if k.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP"}}
        try:
            subprocess.run([binary, "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-days", "1", "-nodes",
                "-keyout", str(key), "-out", str(cert), "-subj", "/CN=sentinel-localhost-lab",
                "-addext", "subjectAltName=IP:127.0.0.1"], check=True, timeout=15,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env)
            server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server.minimum_version = ssl.TLSVersion.TLSv1_2
            server.load_cert_chain(cert, key)
            self.client_tls = ssl.create_default_context(cafile=str(cert))
            self.client_tls.minimum_version = ssl.TLSVersion.TLSv1_2
            return server
        except (OSError, subprocess.SubprocessError, ssl.SSLError):
            self.tls_error = "Disposable local TLS certificate setup failed; HTTPS was not generated"
            return None

    def __enter__(self):
        owner = self

        class Banner(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(5)
                data = bytearray()
                while not data.endswith(b"\n") and len(data) < 64:
                    chunk = self.request.recv(64 - len(data))
                    if not chunk:
                        return
                    data.extend(chunk)
                if bytes(data) != b"SENTINEL-LAB-PING\n":
                    return
                response = b"SENTINEL-OWNED-LOOPBACK\n"
                self.request.sendall(response)
                owner._server_event(self.client_address, self.server.server_address[1], len(data), len(response), "tcp_banner_exchange")

        class HTTP(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_):
                pass

            def _respond(self, details):
                body = _canonical(details).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Content-Type", "application/json")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
                self.wfile.flush()
                self.close_connection = True
                return len(body)

            def do_GET(self):
                if self.path not in {"/normal", "/router-simulator/status"}:
                    self.send_error(404)
                    return
                verified = "https_tls_verified" if isinstance(self.connection, ssl.SSLSocket) else "http"
                size = self._respond(dict(owned_loopback=True, router_role_simulated=self.path.startswith("/router")))
                owner._server_event(self.client_address, self.server.server_address[1], 0, size, verified)

            def do_POST(self):
                try:
                    length = int(self.headers.get("Content-Length", "-1"))
                    if self.path != "/upload" or not 0 < length <= MAX_BODY:
                        self.send_error(400)
                        return
                    count, digest = 0, hashlib.sha256()
                    while count < length:
                        chunk = self.rfile.read(min(65536, length-count))
                        if not chunk or chunk != b"L" * len(chunk):
                            raise ValueError("Only the bounded generated lab body is accepted")
                        count += len(chunk)
                        digest.update(chunk)
                    size = self._respond(dict(received_bytes=count, sha256=digest.hexdigest()))
                    owner._server_event(self.client_address, self.server.server_address[1], count, size, "http",
                                        verified_payload_bytes=count, payload_sha256=digest.hexdigest())
                except (OSError, ValueError):
                    self.close_connection = True

        class UDP(socketserver.BaseRequestHandler):
            def handle(self):
                data, sock = self.request
                if self.server.kind == "dns":
                    response, verified = _dns_response(data), "dns_request_response"
                elif data == b'M-SEARCH * HTTP/1.1\r\nHOST: 127.0.0.1\r\nMAN: "ssdp:discover"\r\nST: sentinel-localhost-lab\r\n\r\n':
                    response, verified = b"HTTP/1.1 200 OK\r\nST: sentinel-localhost-lab\r\nUSN: uuid:owned-loopback\r\n\r\n", "ssdp_format_unicast"
                else:
                    return
                sock.sendto(response, self.client_address)
                owner._server_event(self.client_address, self.server.server_address[1], len(data), len(response), verified)

        try:
            self.banner_ports = []
            for _ in range(8):
                service = _TCPServer((LOOPBACK, 0), Banner)
                self._servers.append(service)
                self.banner_ports.append(service.server_address[1])
            self.http = _HTTPServer((LOOPBACK, 0), HTTP)
            self._servers.append(self.http)
            self.https = None
            tls = self._tls()
            if tls:
                self.https = _HTTPServer((LOOPBACK, 0), HTTP)
                self.https.tls_context = tls
                self._servers.append(self.https)
            self.udp_ports = {}
            for kind in ("dns", "discovery"):
                service = _UDPServer((LOOPBACK, 0), UDP)
                service.kind = kind
                self._servers.append(service)
                self.udp_ports[kind] = service.server_address[1]
            for service in self._servers:
                thread = threading.Thread(target=service.serve_forever, kwargs={"poll_interval": .05}, daemon=True)
                thread.start()
                self._threads.append(thread)
            self._active = True
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    @property
    def owned_ports(self):
        return [service.server_address[1] for service in self._servers]

    def __exit__(self, *_):
        for service, thread in zip(self._servers, self._threads):
            if thread.is_alive():
                service.shutdown()
        for service in self._servers:
            service.server_close()
        for thread in self._threads:
            thread.join(timeout=6)
        if self._tls_temp:
            self._tls_temp.cleanup()
        self._active = False
        self.cleanup_completed = all(not thread.is_alive() for thread in self._threads) and all(service.socket.fileno() == -1 for service in self._servers)

    def _begin(self, sock, scenario, collection):
        if not self._active:
            raise RuntimeError("Owned services must be active")
        local, peer = sock.getsockname(), sock.getpeername()
        if local[0] != LOOPBACK or peer[0] != LOOPBACK or peer[1] not in self.owned_ports:
            raise RuntimeError("Destination must be a retained owned loopback listener")
        event = dict(event_id=uuid.uuid4().hex, scenario=scenario, collection=collection,
                     local=local, peer=peer, wall=time.time(), clock=time.monotonic())
        with self._condition:
            if (local[1], peer[1]) in self._pending:
                raise RuntimeError("A socket tuple was unexpectedly reused in this bounded run")
            self._pending[(local[1], peer[1])] = event
        return event

    def _complete(self, event, sent, received, protocol, **extras):
        ended, elapsed = time.time(), time.monotonic()-event["clock"]
        with self._condition:
            ready = self._condition.wait_for(lambda: event["event_id"] in self._server_events, timeout=5)
            if not ready:
                raise RuntimeError("Owned server confirmation missing; no unverified record accepted")
            server = self._server_events[event["event_id"]]
        if (server["application_bytes_received"], server["application_bytes_sent"]) != (sent, received):
            raise RuntimeError("Independent client/server application-byte counts disagree")
        first, last = utc(event["wall"]), utc(ended)
        if ended < event["wall"]:
            raise RuntimeError("Wall clock moved backwards during an observation")
        record = dict(timestamp=first, src_ip=LOOPBACK, dst_ip=LOOPBACK,
            src_port=event["local"][1], dst_port=event["peer"][1], protocol=protocol,
            duration=elapsed, bytes_sent=sent, bytes_received=received, status="established",
            service=server["protocol_verified"], scenario="controlled_localhost_"+event["scenario"],
            provenance=dict(collector="localhost-lab", measurement_semantics="application_bytes",
                observation_scope="owned_loopback_services", flow_semantics="completed_socket_exchange",
                process_scope="owned_lab_processes_only", flow_id=hashlib.sha1(event["event_id"].encode()).hexdigest(),
                collection_id=event["collection"], first_seen=first, last_seen=last, local_role="initiator",
                direction_basis="client_to_owned_service", protocol_verified=server["protocol_verified"],
                scenario=event["scenario"], source=SOURCE, event_id=event["event_id"], **extras))
        record = _validate_record(record)
        self.client_events.append(record)
        return record

    def _banner(self, port, scenario, collection):
        if port not in self.banner_ports:
            raise ValueError("Only owned banner listeners may be contacted")
        with socket.create_connection((LOOPBACK, port), timeout=5) as sock:
            event = self._begin(sock, scenario, collection)
            data = b"SENTINEL-LAB-PING\n"
            sock.sendall(data)
            reply = bytearray()
            while not reply.endswith(b"\n") and len(reply) < 128:
                chunk = sock.recv(128-len(reply))
                if not chunk:
                    break
                reply.extend(chunk)
            if bytes(reply) != b"SENTINEL-OWNED-LOOPBACK\n":
                raise RuntimeError("Owned listener response did not verify")
            return self._complete(event, len(data), len(reply), "tcp")

    def _http(self, scenario, collection, *, upload=None, tls=False):
        service = self.https if tls else self.http
        if service is None or service.server_address[1] not in self.owned_ports:
            raise RuntimeError("The owned HTTPS service is unavailable")
        cls = http.client.HTTPSConnection if tls else http.client.HTTPConnection
        kwargs = dict(timeout=5)
        if tls:
            kwargs["context"] = self.client_tls
        connection = cls(LOOPBACK, service.server_address[1], **kwargs)
        try:
            connection.connect()  # HTTPConnection ignores environment proxy settings.
            event = self._begin(connection.sock, scenario, collection)
            digest = hashlib.sha256()
            if upload is None:
                path = "/router-simulator/status" if scenario == "router_like" else "/normal"
                connection.request("GET", path, headers={"Connection": "close"})
                sent = 0
            else:
                if upload not in {2048, LARGE_BYTES}:
                    raise ValueError("Only fixed harmless lab payload sizes are supported")
                connection.putrequest("POST", "/upload")
                connection.putheader("Content-Length", str(upload))
                connection.putheader("Connection", "close")
                connection.endheaders()
                sent, pace = 0, time.monotonic()
                while sent < upload:
                    chunk = b"L" * min(65536, upload-sent)
                    sent += len(chunk)
                    time.sleep(max(0, pace+sent/(2*1024*1024)-time.monotonic()))
                    connection.send(chunk)
                    digest.update(chunk)
            response = connection.getresponse()
            body = response.read(4097)
            if response.status != 200 or len(body) > 4096:
                raise RuntimeError("Owned HTTP response did not verify")
            details = json.loads(body)
            if upload is not None and (details.get("received_bytes") != upload or details.get("sha256") != digest.hexdigest()):
                raise RuntimeError("Actual uploaded byte count/hash did not agree at both endpoints")
            extras = dict(verified_payload_bytes=upload, payload_sha256=digest.hexdigest()) if upload else {}
            return self._complete(event, sent, len(body), "tcp", **extras)
        finally:
            connection.close()

    def _udp(self, kind, scenario, collection):
        port = self.udp_ports[kind]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(5)
            sock.connect((LOOPBACK, port))
            event = self._begin(sock, scenario, collection)
            if kind == "dns":
                query = struct.pack("!HHHHHH", int(event["event_id"][:4], 16), 0x0100, 1, 0, 0, 0)+b"\x0csentinel-lab\x07invalid\x00\x00\x01\x00\x01"
                expected = _dns_response(query)
            else:
                query = b'M-SEARCH * HTTP/1.1\r\nHOST: 127.0.0.1\r\nMAN: "ssdp:discover"\r\nST: sentinel-localhost-lab\r\n\r\n'
                expected = b"HTTP/1.1 200 OK\r\nST: sentinel-localhost-lab\r\nUSN: uuid:owned-loopback\r\n\r\n"
            sock.send(query)
            reply = sock.recv(2048)
            if reply != expected:
                raise RuntimeError("Owned UDP protocol response did not verify")
            return self._complete(event, len(query), len(reply), "udp")

    def scenario(self, name):
        if name not in SCENARIOS:
            raise ValueError("Unknown fixed lab scenario")
        collection, records = str(uuid.uuid4()), []
        for i in range(SCENARIOS[name][0]):
            started = time.monotonic()
            if name in {"port_probe", "connection_burst"}:
                record = self._banner(self.banner_ports[i] if name == "port_probe" else self.banner_ports[0], name, collection)
            elif name == "outbound_volume":
                record = self._http(name, collection, upload=2048 if i<3 else LARGE_BYTES)
            elif name == "normal_https":
                record = self._http(name, collection, tls=True)
            elif name in {"normal_dns", "local_discovery"}:
                record = self._udp("dns" if name == "normal_dns" else "discovery", name, collection)
            else:
                record = self._http(name, collection)
            records.append(record)
            time.sleep(max(0, PACE-(time.monotonic()-started)))
        return records


def run_controlled_lab(directory):
    """Explicit authorized execution; no private/original database is opened."""
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=False)
    started, results = utc(), []
    with LabEvidenceStore(directory/"controlled-lab.db") as evidence:
        with OwnedServices(directory) as lab:
            owned_ports = lab.owned_ports
            for name, spec in SCENARIOS.items():
                if name == "normal_https" and lab.https is None:
                    results.append(dict(scenario=name, activity=spec[1], status="skipped", reason=lab.tls_error,
                                        source=SOURCE, exchanges=0, incidents=[], severities=[]))
                    continue
                before = len(lab.client_events)
                try:
                    records = lab.scenario(name)
                    evidence.persist(name, records)
                    replay = evidence.persist(name, records)
                    connection_ids = {row[0] for row in evidence.store.db.execute("SELECT id FROM connections WHERE json_extract(payload,'$.provenance.scenario')=?", (name,))}
                    incidents = [i for i in evidence.store.incidents()["items"] if i["connection_id"] in connection_ids]
                    rules = sorted({i["rule_id"] for i in incidents})
                    expected = [spec[2]] if spec[2] else []
                    severities = sorted({i["severity"] for i in incidents})
                    expected_severities = [spec[3]] if spec[3] else []
                    results.append(dict(scenario=name, activity=spec[1], status="passed" if rules==expected and severities==expected_severities else "unexpected_result",
                        source=SOURCE, exchanges=len(records), collection_id=records[0]["provenance"]["collection_id"],
                        application_bytes_sent=sum(r["bytes_sent"] for r in records),
                        actual_span_seconds=(datetime.fromisoformat(records[-1]["provenance"]["last_seen"])-datetime.fromisoformat(records[0]["timestamp"])).total_seconds(),
                        expected_rules=expected, rules=rules, incidents=[i["id"] for i in incidents],
                        expected_severities=expected_severities, severities=severities, unchanged_evidence_replay=replay,
                        concern="Authorized/legitimate activity intentionally triggers review thresholds; no malicious intent is asserted" if expected else
                                "Small isolated routine activity is unflagged; this is not a benignness guarantee or a network false-positive-rate measurement"))
                except (OSError, ValueError, RuntimeError, ssl.SSLError, http.client.HTTPException) as exc:
                    results.append(dict(scenario=name, activity=spec[1], status="error", source=SOURCE,
                        error_type=type(exc).__name__, reason="Owned exchange/evidence validation failed; inspect private run evidence",
                        exchanges=len(lab.client_events)-before, evidence_persisted=False, incidents=[], severities=[]))
                    break  # Fail safely rather than continue after uncertain ownership/measurement.
            client_events = list(lab.client_events)
            server_events = list(lab._server_events.values())
        cleanup_completed = lab.cleanup_completed
        integrity = evidence.store.db.execute("PRAGMA integrity_check").fetchone()[0]
        counts = dict(connections=evidence.store.connections()["total"], incidents=evidence.store.incidents()["total"],
                      history=evidence.store.db.execute("SELECT COUNT(*) FROM history").fetchone()[0])
        roles = [r[0] for r in evidence.store.db.execute("SELECT DISTINCT origin FROM connections")]
    for filename, rows in (("client-observations.jsonl", client_events), ("endpoint-observations.jsonl", server_events)):
        with (directory/filename).open("x", encoding="utf-8") as stream:
            for row in rows:
                stream.write(_canonical(row)+"\n")
    report = dict(schema_version=1, started_at=started, ended_at=utc(), source=SOURCE,
        database_role="controlled_lab", origin="lab", policy=LIVE_POLICY, capture=False,
        machine_learning_scored=False, bound_address=LOOPBACK, owned_destination_ports=owned_ports,
        cleanup_completed=cleanup_completed,
        results=results, counts=counts, origins=roles, database_integrity=integrity,
        client_observations=len(client_events), server_observations=len(server_events),
        outcome_counts=dict(Counter(r["status"] for r in results)), limitations=LIMITATIONS)
    with (directory/"report.json").open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, allow_nan=False)
    return report
