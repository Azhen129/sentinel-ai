"""Opt-in, bounded Windows Ethernet metadata collection. Default: no capture.

Use --interface with the exact selected NPF UUID and repeat --local-address for
assigned laptop addresses. Review the dry-run preview first. --enable-capture
collects one bounded window; --ingest separately permits loopback API requests.
No elevation, installation, capture-file creation or permission change is attempted.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from detection.collector import (CaptureConfig, CollectorError, capture_command,
    collect_window, decoder_command, metadata_batches, resolve_dumpcap, resolve_tshark)


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Never forward an API key or metadata through a redirect, even locally.
        return None


def loopback_api(value: str) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise CollectorError("Invalid loopback API URL") from exc
    if (parsed.scheme not in {"http", "https"} or parsed.hostname not in {"127.0.0.1", "::1"}
        or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment
        or parsed.path not in {"", "/"} or (port is not None and not 1 <= port <= 65535)):
        raise CollectorError("API must be a literal http(s)://127.0.0.1[:port] or http(s)://[::1][:port], without credentials, paths or redirects")
    return value.rstrip("/")


def api_request(base: str, path: str, key: str, payload: dict | None = None) -> dict:
    base = loopback_api(base)
    if path not in {"/api/monitor/status", "/api/ingest/metadata"}:
        raise CollectorError("Only the explicit monitoring profile and metadata endpoints are permitted")
    if any(ord(character) < 33 or ord(character) > 126 for character in key):
        raise CollectorError("API keys must not contain whitespace or control characters")
    body = json.dumps(payload, allow_nan=False).encode("utf-8") if payload is not None else None
    request = Request(base + path, body,
        {"Content-Type": "application/json", "X-Sentinel-Key": key},
        method="POST" if payload is not None else "GET")
    # trust_env=False equivalent: never route loopback metadata/key through proxies.
    opener = build_opener(ProxyHandler({}), NoRedirects())
    try:
        with opener.open(request, timeout=15) as response:
            content = response.read(2_000_001)
        if len(content) > 2_000_000:
            raise CollectorError("Loopback API response exceeds the bounded limit")
        result = json.loads(content)
        if not isinstance(result, dict):
            raise CollectorError("Loopback API returned an unexpected response")
        return result
    except HTTPError as exc:
        raise CollectorError(f"Loopback API rejected the request (HTTP {exc.code}); no redirect, retry or credential logging was performed") from None
    except (URLError, OSError, json.JSONDecodeError):
        raise CollectorError("Loopback API request failed; verify the isolated monitor backend and key locally") from None


def preflight(base: str, key: str) -> dict:
    profile = api_request(base, "/api/monitor/status", key)
    if (profile.get("mode") != "monitor" or profile.get("enabled") is not True
        or profile.get("ingestion_enabled") is not True or profile.get("database_isolated") is not True):
        raise CollectorError("The loopback API is not an enabled isolated monitoring profile with available capacity")
    return profile


def private_output(path: Path, project: Path = ROOT) -> Path:
    result = path.resolve()
    private_root = (project / "data" / "monitoring").resolve()
    if not private_root.is_relative_to(project.resolve()) or not result.is_relative_to(private_root) or result.suffix.lower() != ".json":
        raise CollectorError("Optional metadata output must be an ignored data/monitoring/*.json path inside this project")
    if result.exists():
        raise CollectorError("Optional metadata output already exists; choose a new private filename")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", help="Exact selected Windows \\Device\\NPF_{UUID}; never an index or auto-selected device")
    parser.add_argument("--interface-label", default="Ethernet", help="Display label only; never inserted into a command")
    parser.add_argument("--local-address", action="append", default=[], help="Assigned numeric laptop address; repeat for IPv4/IPv6")
    parser.add_argument("--duration", type=int, default=20, help="Seconds, 1–120; default20")
    parser.add_argument("--max-packets", type=int, default=5000, help="1–5000")
    parser.add_argument("--max-flows", type=int, default=1000, help="1–1000 finalized aggregates in memory")
    parser.add_argument("--tshark", help="Existing trusted tshark.exe")
    parser.add_argument("--dumpcap", help="Existing trusted dumpcap.exe, normally beside TShark")
    parser.add_argument("--enable-capture", action="store_true", help="Explicitly permit one passive bounded capture window")
    parser.add_argument("--ingest", action="store_true", help="Separately permit keyed loopback monitoring API requests")
    parser.add_argument("--api", default="http://127.0.0.1:8000")
    parser.add_argument("--ask-key", action="store_true", help="Prompt privately rather than reading SENTINEL_API_KEY; requires --ingest")
    parser.add_argument("--output", type=Path, help="Optional private metadata-only JSON under data/monitoring/; no packet files")
    args = parser.parse_args(argv)
    key = ""
    try:
        if args.ingest and not args.enable_capture:
            raise CollectorError("--ingest requires explicit --enable-capture; no requests were sent")
        if args.ask_key and not args.ingest:
            raise CollectorError("--ask-key is only used with --ingest")
        if not args.interface and not args.enable_capture:
            print(json.dumps({"capture_enabled": False, "requests_sent": False,
                "message": "Monitoring is disabled. Supply the selected interface and assigned local addresses to preview a bounded capture plan."}))
            return 0
        if not args.interface or not args.local_address:
            raise CollectorError("Select the exact Ethernet --interface and at least one assigned --local-address")
        config = CaptureConfig(args.interface, tuple(args.local_address), args.interface_label,
            args.duration, args.max_packets, args.max_flows)
        base = loopback_api(args.api)
        output = private_output(args.output) if args.output else None
        if not args.enable_capture:
            # A true dry run: no executable launch, interface open, key prompt or API request.
            print(json.dumps({"capture_enabled": False, "requests_sent": False,
                "capture_argv_preview": capture_command(config, args.dumpcap or "dumpcap.exe"),
                "decoder_argv_preview": decoder_command(args.tshark or "tshark.exe"),
                "pipe": "capture binary stdout -> decoder stdin; no packet filename or temporary capture file",
                "flow_limit": config.max_flows, "batch_size": 50,
                "configuration_note": "Confirm these addresses belong to this exact selected Ethernet adapter before opting in."}, indent=2))
            return 0
        if os.name != "nt":
            raise CollectorError("This CLI requires Windows and the explicitly selected Npcap Ethernet interface")
        tshark = resolve_tshark(args.tshark)
        dumpcap = resolve_dumpcap(args.dumpcap, tshark)
        if args.ingest:
            if args.ask_key and not sys.stdin.isatty():
                raise CollectorError("A private key prompt requires an interactive terminal; use SENTINEL_API_KEY for noninteractive execution")
            key = getpass.getpass("Sentinel monitor API key: ") if args.ask_key else os.environ.get("SENTINEL_API_KEY", "")
            if len(key) < 32:
                raise CollectorError("Set a monitor key of at least32 characters via SENTINEL_API_KEY or --ask-key; capture was not started")
            preflight(base, key)  # Verify profile/key/capacity before opening the adapter.
        result = collect_window(config, tshark, dumpcap)
        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            with output.open("x", encoding="utf-8") as destination:
                json.dump(result, destination, indent=2, allow_nan=False)
        ingested, duplicate_batches = 0, 0
        if args.ingest:
            for batch in metadata_batches(result["records"], result["collection_id"]):
                try:
                    response = api_request(base, "/api/ingest/metadata", key, batch)
                except CollectorError as exc:
                    raise CollectorError(f"Metadata ingestion stopped after {ingested} newly accepted flows. {exc}") from None
                if response.get("duplicate") is True:
                    duplicate_batches += 1
                elif response.get("origin") == "live" and response.get("ingested") == len(batch["records"]):
                    ingested += response["ingested"]
                else:
                    raise CollectorError(f"Unexpected ingestion acknowledgment after {ingested} accepted flows; do not retry blindly")
        # Raw addresses, metadata rows and credentials are intentionally absent from stdout.
        print(json.dumps({"collection_id": result["collection_id"], "capture_completed": True,
            "started_at": result["started_at"], "ended_at": result["ended_at"],
            "flow_record_count": result["flow_record_count"], "counters": result["counters"],
            "raw_pcap_persisted": False, "application_payload_fields_persisted": False,
            "metadata_file_saved": output is not None, "ingested_flows": ingested,
            "duplicate_batches": duplicate_batches, "continuous_capture": False,
            "limitations": result["limitations"]}, indent=2))
        return 0
    except (CollectorError, OSError) as exc:
        print(f"Monitoring stopped: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Monitoring interrupted; owned capture processes were stopped.", file=sys.stderr)
        return 130
    finally:
        key = ""


if __name__ == "__main__":
    raise SystemExit(main())
