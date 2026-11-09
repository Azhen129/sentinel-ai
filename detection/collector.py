"""Bounded passive TShark metadata collection; importing this module captures nothing.

No raw packet file, application payload, HTTP/DNS field or credential is exported.
Records use the selected laptop's perspective, including when the first observed
packet came from a peer. They are partial observation windows, not complete sessions.
"""
from __future__ import annotations

import csv
from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import ip_address
import math
import os
from pathlib import Path
import queue
import re
import shutil
import subprocess
import threading
import time
from uuid import UUID, uuid4


# Deliberately immutable and restricted to connection metadata. No packet output
# filename, -V/-x, export-objects or DNS/HTTP/TLS application fields are used.
TSHARK_FIELDS = (
    "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst",
    "tcp.srcport", "udp.srcport", "tcp.dstport", "udp.dstport", "tcp.len",
    "udp.length", "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.reset",
    "tcp.flags.fin", "tcp.stream", "udp.stream",
)
MAX_LINE_CHARS = 4096
INTERFACE_PATTERN = re.compile(r"^\\Device\\NPF_\{([0-9A-Fa-f-]{36})\}$", re.IGNORECASE)


class CollectorError(ValueError):
    """A safe diagnostic that contains no packet contents or credentials."""


class PacketError(ValueError):
    def __init__(self, counter: str):
        self.counter = counter
        super().__init__(counter)


def utc_timestamp(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat()


@dataclass(frozen=True)
class CaptureConfig:
    interface: str
    local_addresses: tuple[str, ...]
    interface_label: str = "Ethernet"
    duration: int = 20
    max_packets: int = 5000
    max_flows: int = 1000

    def __post_init__(self):
        match = INTERFACE_PATTERN.fullmatch(self.interface)
        if not match:
            raise CollectorError("Select the exact Windows Ethernet \\Device\\NPF_{UUID} interface; names, indexes and loopback are not accepted")
        try:
            identifier = UUID(match.group(1))
        except ValueError as exc:
            raise CollectorError("Invalid capture interface UUID") from exc
        object.__setattr__(self, "interface", "\\Device\\NPF_{" + str(identifier).upper() + "}")
        if not isinstance(self.interface_label, str) or not 1 <= len(self.interface_label) <= 80 or any(ord(c) < 32 for c in self.interface_label):
            raise CollectorError("Interface label must contain 1–80 printable characters")
        for name, maximum in (("duration", 120), ("max_packets", 5000), ("max_flows", 1000)):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
                raise CollectorError(f"{name} must be an integer from 1 to {maximum}")
        if not self.local_addresses or len(self.local_addresses) > 8:
            raise CollectorError("Supply 1–8 explicit local addresses assigned to the selected Ethernet adapter")
        addresses = []
        for raw in self.local_addresses:
            try:
                # IPv6 scope belongs to the selected interface, not a BPF host literal.
                if not isinstance(raw, str) or raw.count("%") > 1:
                    raise ValueError
                address = ip_address(raw.split("%", 1)[0])
            except ValueError as exc:
                raise CollectorError("Local addresses must be numeric IPv4/IPv6 literals") from exc
            if address.is_loopback or address.is_unspecified or address.is_multicast:
                raise CollectorError("Ethernet monitoring requires assigned non-loopback unicast local addresses")
            if str(address) not in addresses:
                addresses.append(str(address))
        object.__setattr__(self, "local_addresses", tuple(addresses))

    @property
    def capture_filter(self) -> str:
        return "(" + " or ".join("host " + address for address in self.local_addresses) + ") and (tcp or udp)"


def resolve_tshark(path: str | None = None) -> str:
    candidate = path or shutil.which("tshark")
    if not candidate:
        raise CollectorError("TShark is unavailable on PATH; select the existing tshark executable explicitly")
    executable = Path(candidate).resolve()
    if not executable.is_file() or executable.name.lower() not in {"tshark", "tshark.exe"}:
        raise CollectorError("Select an existing trusted tshark executable")
    return str(executable)


def resolve_dumpcap(path: str | None = None, tshark: str | None = None) -> str:
    candidate = path or shutil.which("dumpcap")
    if not candidate and tshark:
        candidate = str(Path(tshark).with_name("dumpcap.exe" if Path(tshark).suffix.lower() == ".exe" else "dumpcap"))
    if not candidate or not Path(candidate).is_file() or Path(candidate).name.lower() not in {"dumpcap", "dumpcap.exe"}:
        raise CollectorError("Select the existing trusted dumpcap executable beside TShark")
    return str(Path(candidate).resolve())


def capture_command(config: CaptureConfig, executable: str) -> list[str]:
    # Direct live TShark can create temporary capture files. Explicit stdout piping
    # avoids filenames: raw 128-byte prefixes exist only in the process pipe.
    return [executable, "-i", config.interface, "-p", "-f", config.capture_filter,
            "-s", "128", "-a", f"duration:{config.duration}", "-c", str(config.max_packets), "-w", "-"]


def decoder_command(executable: str) -> list[str]:
    command = [executable, "-n", "-r", "-", "-l", "-T", "fields", "-E", "header=n",
               "-E", "separator=,", "-E", "quote=d", "-E", "occurrence=a", "-E", "aggregator=;"]
    for name in TSHARK_FIELDS:
        command.extend(("-e", name))
    return command


def integer(value: str, maximum: int, *, empty: bool = False) -> int | None:
    if not value and empty:
        return None
    if not re.fullmatch(r"[0-9]+", value):
        raise PacketError("skipped_malformed")
    result = int(value)
    if result > maximum:
        raise PacketError("skipped_malformed")
    return result


def flag(value: str) -> bool:
    if value in {"", "0", "False", "false"}:
        return False
    if value in {"1", "True", "true"}:
        return True
    raise PacketError("skipped_malformed")


@dataclass(frozen=True)
class PacketMetadata:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    payload_bytes: int
    stream: int | None
    flags: frozenset[str]


def parse_metadata_line(line: str) -> PacketMetadata:
    if not line or len(line) > MAX_LINE_CHARS:
        raise PacketError("skipped_malformed")
    try:
        values = next(csv.reader([line], strict=True))
    except (csv.Error, StopIteration) as exc:
        raise PacketError("skipped_malformed") from exc
    if len(values) != len(TSHARK_FIELDS):
        raise PacketError("skipped_malformed")
    values = [value.strip() for value in values]
    if any(";" in value for value in values):
        raise PacketError("skipped_ambiguous")
    epoch, v4s, v6s, v4d, v6d, tcps, udps, tcpd, udpd, tcplen, udplen, syn, ack, rst, fin, tcpstream, udpstream = values
    if (v4s and v6s) or (v4d and v6d) or (tcps and udps) or (tcpd and udpd):
        raise PacketError("skipped_ambiguous")
    try:
        when = float(epoch)
        if not math.isfinite(when) or when < 0:
            raise ValueError
        utc_timestamp(when)
        source, destination = ip_address(v4s or v6s), ip_address(v4d or v6d)
        if source.version != destination.version:
            raise ValueError
    except (ValueError, OverflowError, OSError) as exc:
        raise PacketError("skipped_malformed") from exc
    if tcps and tcpd:
        protocol, source_port, destination_port = "tcp", integer(tcps, 65535), integer(tcpd, 65535)
        payload = integer(tcplen, 2**32 - 1)
        stream = integer(tcpstream, 2**32 - 1, empty=True)
        if stream is None:
            raise PacketError("skipped_missing_stream")
        flags = frozenset(name for name, present in (("SYN", flag(syn)), ("ACK", flag(ack)), ("RST", flag(rst)), ("FIN", flag(fin))) if present)
    elif udps and udpd:
        protocol, source_port, destination_port = "udp", integer(udps, 65535), integer(udpd, 65535)
        length = integer(udplen, 65535)
        if length < 8:
            # UDP jumbograms with length=0 need extra evidence; do not invent a size.
            raise PacketError("skipped_malformed")
        payload, stream, flags = length - 8, integer(udpstream, 2**32 - 1, empty=True), frozenset()
    else:
        raise PacketError("skipped_unsupported")
    return PacketMetadata(when, str(source), str(destination), source_port, destination_port,
                          protocol, payload, stream, flags)


@dataclass
class _Flow:
    key: tuple
    first: float
    last: float
    local_ip: str
    peer_ip: str
    local_port: int
    peer_port: int
    protocol: str
    flow_semantics: str
    midstream_start: bool
    bytes_sent: int = 0
    bytes_received: int = 0
    packets: int = 0
    local_role: str = "unknown"
    role_ambiguous: bool = False
    flags: set[str] = field(default_factory=set)


class FlowCollector:
    """At most max_flows aggregates and no packet list; finalized exactly once.

    A collection's lifetime is its bounded capture window. We do not expire and
    re-emit partial copies of the same stream, which would inflate connection/rule
    counts. All state expires when this one-shot collector is discarded.
    """
    def __init__(self, config: CaptureConfig, collection_id: str | None = None):
        self.config = config
        self.collection_id = str(UUID(collection_id)) if collection_id else str(uuid4())
        self.flows: dict[tuple, _Flow] = {}
        self.finished = False
        self.stats = {name: 0 for name in ("metadata_rows_read", "packets_accepted", "skipped_malformed",
            "skipped_ambiguous", "skipped_missing_stream", "skipped_nonlocal", "skipped_local_to_local",
            "skipped_unsupported", "skipped_flow_limit", "skipped_packet_limit")}

    def consume(self, line: str) -> None:
        if self.finished:
            raise CollectorError("A finalized collector cannot ingest more metadata")
        self.stats["metadata_rows_read"] += 1
        if self.stats["metadata_rows_read"] > self.config.max_packets:
            self.stats["skipped_packet_limit"] += 1
            return
        try:
            packet = parse_metadata_line(line)
        except PacketError as exc:
            self.stats[exc.counter] += 1
            return
        src_local = packet.src_ip in self.config.local_addresses
        dst_local = packet.dst_ip in self.config.local_addresses
        if src_local and dst_local:
            self.stats["skipped_local_to_local"] += 1
            return
        if not src_local and not dst_local:
            self.stats["skipped_nonlocal"] += 1
            return
        local_ip, peer_ip = (packet.src_ip, packet.dst_ip) if src_local else (packet.dst_ip, packet.src_ip)
        local_port, peer_port = (packet.src_port, packet.dst_port) if src_local else (packet.dst_port, packet.src_port)
        key = (packet.protocol, packet.stream, local_ip, peer_ip, local_port, peer_port)
        if key not in self.flows:
            if len(self.flows) >= self.config.max_flows:
                self.stats["skipped_flow_limit"] += 1
                return
            semantics = "tcp_stream_window" if packet.protocol == "tcp" else "udp_stream_window" if packet.stream is not None else "udp_5tuple_window"
            self.flows[key] = _Flow(key, packet.timestamp, packet.timestamp, local_ip, peer_ip, local_port,
                peer_port, packet.protocol, semantics, not ("SYN" in packet.flags and "ACK" not in packet.flags))
        flow = self.flows[key]
        flow.first, flow.last = min(flow.first, packet.timestamp), max(flow.last, packet.timestamp)
        flow.packets += 1
        if src_local:
            flow.bytes_sent += packet.payload_bytes
        else:
            flow.bytes_received += packet.payload_bytes
        flow.flags.update(packet.flags)
        if "SYN" in packet.flags and "ACK" not in packet.flags:
            inferred_role = "initiator" if src_local else "responder"
            if flow.local_role == "unknown" and not flow.role_ambiguous:
                flow.local_role = inferred_role
            elif flow.local_role != inferred_role:
                # Simultaneous open or ambiguous handshake is not safely attributable.
                flow.local_role = "unknown"
                flow.role_ambiguous = True
        self.stats["packets_accepted"] += 1

    def finalize(self, window_end: str) -> list[dict]:
        if self.finished:
            raise CollectorError("Flow records can only be finalized once")
        self.finished = True
        records = []
        for flow in sorted(self.flows.values(), key=lambda value: value.first):
            status = "reset_observed" if "RST" in flow.flags else "fin_observed" if "FIN" in flow.flags else "syn_observed" if "SYN" in flow.flags else "observed"
            # UUID5-like stable identifier with no raw address text in the identifier.
            import hashlib
            flow_id = hashlib.sha256((self.collection_id + repr(flow.key)).encode()).hexdigest()[:40]
            records.append({"timestamp": utc_timestamp(flow.first), "src_ip": flow.local_ip,
                "dst_ip": flow.peer_ip, "src_port": flow.local_port, "dst_port": flow.peer_port,
                "protocol": flow.protocol, "duration": flow.last - flow.first,
                "bytes_sent": flow.bytes_sent, "bytes_received": flow.bytes_received,
                "status": status, "service": "unknown", "scenario": "live_ethernet",
                "provenance": {"collector": "dumpcap+tshark", "interface_label": self.config.interface_label,
                    "measurement_semantics": "transport_payload_bytes",
                    "observation_scope": "selected_interface_passive", "flow_semantics": flow.flow_semantics,
                    "process_scope": "interface_only_no_process_attribution", "flow_id": flow_id,
                    "collection_id": self.collection_id, "first_seen": utc_timestamp(flow.first),
                    "last_seen": utc_timestamp(flow.last), "window_end": window_end,
                    "packet_count": flow.packets, "local_role": flow.local_role,
                    "midstream_start": flow.midstream_start, "duration_is_lower_bound": True,
                    "capture_window_limited": True, "retransmissions_included": True,
                    "direction_basis": "local_host",
                    "transport_flags_observed": ",".join(name for name in ("SYN", "ACK", "RST", "FIN") if name in flow.flags)}})
        return records


def metadata_batches(records: list[dict], collection_id: str, size: int = 50):
    if not 1 <= size <= 50:
        raise CollectorError("Metadata batches must contain at most 50 finalized flows")
    for index in range(0, len(records), size):
        yield {"batch_id": f"{collection_id}:{index // size}", "records": records[index:index + size]}


def _stop_process(process):
    if process.poll() is not None:
        return
    if hasattr(subprocess, "CREATE_NO_WINDOW"):
        try:
            # Stop only this owned process tree; never elevate or change Npcap settings.
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=5, creationflags=subprocess.CREATE_NO_WINDOW, check=False)
        except (OSError, subprocess.TimeoutExpired):
            pass
    if process.poll() is None:
        process.kill()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        pass


def collect_window(config: CaptureConfig, tshark: str, dumpcap: str) -> dict:
    """Capture only when explicitly called by an opted-in caller; no API requests."""
    collector = FlowCollector(config)
    started = datetime.now(timezone.utc).isoformat()
    output_queue: queue.Queue = queue.Queue(maxsize=64)
    stopped = threading.Event()
    metadata_read_failed = threading.Event()
    capture, decoder = None, None
    readers = []

    def offer(value):
        while not stopped.is_set():
            try:
                output_queue.put(value, timeout=0.1)
                return
            except queue.Full:
                pass

    def read_metadata():
        try:
            while not stopped.is_set():
                line = decoder.stdout.readline(MAX_LINE_CHARS + 1)
                if not line:
                    break
                if len(line) > MAX_LINE_CHARS:
                    # Discard the rest of this oversized metadata row without storing it.
                    while line and not line.endswith("\n"):
                        line = decoder.stdout.readline(MAX_LINE_CHARS + 1)
                    offer("")
                else:
                    offer(line.rstrip("\r\n"))
        except (OSError, ValueError):
            metadata_read_failed.set()
        finally:
            offer(None)

    def discard_diagnostics(stream):
        # Drain without retaining or printing diagnostics that can contain local paths.
        try:
            while not stopped.is_set() and stream.read(1024):
                pass
        except (OSError, ValueError):
            pass

    deadline = time.monotonic() + config.duration + 10
    try:
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        child_environment = os.environ.copy()
        child_environment.pop("SENTINEL_API_KEY", None)
        capture = subprocess.Popen(capture_command(config, dumpcap), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, creationflags=creationflags,
            env=child_environment)
        decoder = subprocess.Popen(decoder_command(tshark), stdin=capture.stdout,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace",
            bufsize=1, shell=False, creationflags=creationflags, env=child_environment)
        # Decoder owns the read end now; the parent must never read or store PCAP bytes.
        capture.stdout.close()
        readers = [threading.Thread(target=read_metadata, daemon=True),
            threading.Thread(target=discard_diagnostics, args=(capture.stderr,), daemon=True),
            threading.Thread(target=discard_diagnostics, args=(decoder.stderr,), daemon=True)]
        for reader in readers:
            reader.start()
        while True:
            if time.monotonic() >= deadline:
                raise CollectorError("Capture exceeded its bounded shutdown deadline; the owned capture process is being stopped")
            try:
                line = output_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            if line is None:
                break
            collector.consume(line)
        if metadata_read_failed.is_set():
            raise CollectorError("Decoder metadata pipe failed; no partial collection was accepted")
        try:
            decoder_returncode = decoder.wait(timeout=3)
            capture_returncode = capture.wait(timeout=3)
        except subprocess.TimeoutExpired as exc:
            raise CollectorError("Capture did not stop after its bounded window") from exc
        if decoder_returncode or capture_returncode:
            raise CollectorError("Capture unavailable in this process context. Review local TShark/Npcap access; no elevation or permission changes were attempted")
        ended = datetime.now(timezone.utc).isoformat()
        records = collector.finalize(ended)
        return {"collection_id": collector.collection_id, "started_at": started, "ended_at": ended,
                "capture_window_seconds": config.duration, "packet_limit": config.max_packets,
                "flow_limit": config.max_flows, "promiscuous": False, "name_resolution": False,
                "raw_pcap_persisted": False, "application_payload_fields_persisted": False,
                "snapshot_length_bytes": 128,
                "flow_record_count": len(records), "counters": collector.stats, "records": records,
                "limitations": ["Header-derived transport payload lengths include retransmissions and exclude TCP/UDP/IP headers; truncated payload contents are not verified.",
                    "Records are bounded-window observations; duration is a lower bound, not complete session lifetime.",
                    "All records use the local laptop's perspective; responder flows differ from KDD initiator-oriented training.",
                    "No HTTP/authentication outcome, process attribution or maliciousness is inferred.",
                    "Unseen/midstream transport states and unknown service introduce model distribution shift.",
                    "128-byte packet prefixes can contain application fragments in memory; no payload fields or raw packet files are persisted.",
                    "The 128-byte prefix can truncate IPv6 extension/transport headers; ambiguous or unavailable metadata is skipped and counted."]}
    finally:
        stopped.set()
        for process in (decoder, capture):
            if process is not None:
                _stop_process(process)
        for reader in readers:
            reader.join(timeout=1)
        for process in (decoder, capture):
            if process is not None:
                for stream in (process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()
