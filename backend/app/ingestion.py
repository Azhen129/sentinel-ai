"""Read exported logs/files only. This module never captures packets or scans hosts."""
import csv
from datetime import datetime, timezone
import io
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from .schemas import Connection


def from_zeek(row: dict) -> dict:
    def number(key, default=0):
        value = row.get(key, default)
        return default if value in ("-", "(empty)", None, "") else value
    raw_protocol = row.get("proto", "tcp")
    if not isinstance(raw_protocol, str):
        raise ValueError("Protocol must be a string: tcp, udp, or icmp")
    protocol = raw_protocol.lower()
    if protocol not in {"tcp", "udp", "icmp"}:
        raise ValueError("Supported protocols: tcp, udp, icmp")
    result = dict(timestamp=datetime.fromtimestamp(float(row["ts"]), timezone.utc).isoformat(), src_ip=row["id.orig_h"], dst_ip=row["id.resp_h"], src_port=int(number("id.orig_p")), dst_port=int(number("id.resp_p")), protocol=protocol, duration=float(number("duration")), bytes_sent=int(number("orig_bytes")), bytes_received=int(number("resp_bytes")), status=str(row.get("conn_state", "unknown")), service=str(row.get("service", "unknown")), scenario="lab")
    return Connection.model_validate(result).model_dump()


def parse_zeek(content: str, format: str = "json") -> list[dict]:
    records = []
    fields = None
    separator = "\t"
    for line_number, raw in enumerate(content.splitlines(), 1):
        if not raw.strip():
            continue
        if raw.startswith("#separator "):
            token = raw.split(" ", 1)[1]
            separator = bytes(token, "utf-8").decode("unicode_escape")
            if len(separator) != 1:
                raise ValueError("Invalid Zeek separator")
            continue
        if raw.startswith("#fields"):
            fields = raw.split(separator)[1:]
            continue
        if raw.startswith("#"):
            continue
        try:
            if format == "json":
                row = json.loads(raw)
                if not isinstance(row, dict):
                    raise ValueError("Expected one JSON object per line")
            else:
                if not fields:
                    raise ValueError("TSV logs require a #fields header")
                values = raw.split(separator)
                if len(values) != len(fields):
                    raise ValueError("Field count does not match header")
                row = dict(zip(fields, values))
            records.append(from_zeek(row))
            if len(records) > 10000:
                raise ValueError("Maximum 10,000 connections per import")
        except (ValueError, KeyError, TypeError, OverflowError, OSError) as exc:
            raise ValueError(f"Invalid Zeek record at line {line_number}: {str(exc)[:180]}") from exc
    if not records:
        raise ValueError("No connection records found")
    return records


def parse_pcap(data: bytes) -> list[dict]:
    executable = shutil.which("tshark")
    if not executable:
        raise RuntimeError("Install tshark to enable offline PCAP import")
    if data[:4] not in {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"}:
        raise ValueError("Expected a PCAP or PCAPNG file")
    with tempfile.TemporaryDirectory(prefix="sentinel-pcap-") as temp:
        path = Path(temp) / "upload.pcap"
        path.write_bytes(data)
        args = [executable, "-n", "-r", str(path), "-c", "50000", "-T", "fields", "-E", "separator=,", "-E", "quote=d", "-E", "occurrence=f"]
        for field in ["frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "tcp.srcport", "udp.srcport", "tcp.dstport", "udp.dstport", "frame.len", "tcp.flags.reset", "tcp.flags.syn", "tcp.flags.ack"]:
            args += ["-e", field]
        try:
            output = subprocess.run(args, capture_output=True, text=True, timeout=30, check=False)
        except subprocess.TimeoutExpired as exc:
            raise ValueError("PCAP processing exceeded 30 seconds") from exc
        if output.returncode:
            raise ValueError("tshark could not parse this capture")
    return aggregate_tshark(output.stdout)


def aggregate_tshark(output: str) -> list[dict]:
    flows = {}
    for row in csv.reader(io.StringIO(output)):
        if len(row) != 13:
            continue
        ts, ipv4s, ipv6s, ipv4d, ipv6d, tcps, udps, tcpd, udpd, length, rst, syn, ack = row
        src, dst = ipv4s or ipv6s, ipv4d or ipv6d
        if not src or not dst or not (tcps or udps):
            continue
        protocol = "tcp" if tcps else "udp"
        sp, dp = int(tcps or udps), int(tcpd or udpd)
        key = (src, dst, sp, dp, protocol)
        reverse = (dst, src, dp, sp, protocol)
        when = float(ts)
        if reverse in flows:
            flow = flows[reverse]
            flow["bytes_received"] += int(length)
            flow["_last"] = max(flow["_last"], when)
        elif key in flows:
            flow = flows[key]
            flow["bytes_sent"] += int(length)
            flow["_last"] = max(flow["_last"], when)
        else:
            flow = dict(timestamp=datetime.fromtimestamp(when, timezone.utc).isoformat(), src_ip=src, dst_ip=dst, src_port=sp, dst_port=dp, protocol=protocol, duration=0, bytes_sent=int(length), bytes_received=0, status="observed", service="unknown", scenario="lab", _first=when, _last=when)
            flows[key] = flow
        if rst in {"1", "True"}:
            flow["status"] = "RSTR"
        if len(flows) > 10000:
            raise ValueError("Maximum 10,000 flows per import")
    result = []
    for flow in flows.values():
        flow["duration"] = flow.pop("_last") - flow.pop("_first")
        result.append(Connection.model_validate(flow).model_dump())
    if not result:
        raise ValueError("No supported TCP/UDP IP flows found")
    return result
