"""Import an existing, authorized lab log or capture into a local Sentinel API."""
from __future__ import annotations

import argparse
from http.client import HTTPException
import json
import os
from pathlib import Path
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


MAX_RESPONSE_BYTES = 65_536


class ImportErrorSafe(Exception):
    """A diagnostic that never includes an input body, API key or response body."""


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Custom authentication headers must never follow even a local redirect.
        return None


def loopback_api(value: str) -> str:
    """Validate a literal loopback origin before reading private input or secrets."""
    try:
        parsed = urlsplit(value)
        if (parsed.scheme not in {"http", "https"} or parsed.hostname not in {"127.0.0.1", "::1"}
                or parsed.username is not None or parsed.password is not None
                or parsed.path or parsed.query or parsed.fragment
                or value != parsed.scheme + "://" + parsed.netloc
                or not value.isascii() or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value)
                or parsed.netloc.endswith(":") or "," in parsed.netloc or "\\" in parsed.netloc):
            raise ValueError
        if parsed.hostname == "::1" and not parsed.netloc.startswith("["):
            raise ValueError
        port = parsed.port
        if port is not None and not 1 <= port <= 65535:
            raise ValueError
        suffix = parsed.netloc.partition("]")[2] if parsed.netloc.startswith("[") else parsed.netloc.partition(":")[2]
        if suffix and not (suffix[1:].isdigit() if suffix.startswith(":") else suffix.isdigit()):
            raise ValueError
    except (ValueError, TypeError, UnicodeError):
        raise ImportErrorSafe("API must be a literal HTTP(S) loopback origin using 127.0.0.1 or [::1], with an optional valid port and no credentials, path, query or fragment") from None
    return value


def request_import(api: str, endpoint: str, body: bytes, mime: str, key: str) -> dict:
    api = loopback_api(api)
    if endpoint not in {"/api/ingest/zeek", "/api/ingest/pcap"}:
        raise ImportErrorSafe("Unsupported local import endpoint")
    if not key or any(ord(c) < 32 or ord(c) > 126 for c in key):
        raise ImportErrorSafe("Set a valid SENTINEL_API_KEY in this terminal; no import was sent")
    request = Request(api + endpoint, body,
        {"Content-Type": mime, "X-Sentinel-Key": key}, method="POST")
    opener = build_opener(ProxyHandler({}), NoRedirects())
    try:
        with opener.open(request, timeout=30) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ImportErrorSafe("Import acknowledgment exceeds the response size limit; verify local state before retrying")
        result = json.loads(raw)
        if (not isinstance(result, dict) or type(result.get("ingested")) is not int
                or not 0 <= result["ingested"] <= 10000 or result.get("origin") != "lab"
                or result.get("source") not in {"zeek", "pcap"}):
            raise ImportErrorSafe("Unexpected import acknowledgment; verify local state before retrying")
        # Print only typed acknowledgment fields, never arbitrary returned content.
        return {name: result[name] for name in ("ingested", "origin", "source")}
    except HTTPError as exc:
        exc.close()
        raise ImportErrorSafe(f"Local import rejected (HTTP {exc.code}); redirects are disabled and response content was not displayed") from None
    except (OSError, URLError, HTTPException, ValueError, UnicodeError):
        raise ImportErrorSafe("Local import or acknowledgment failed; verify the API and stored state before retrying") from None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    parser.add_argument("--format", choices=("json", "tsv", "pcap"), default="json")
    parser.add_argument("--api", default="http://127.0.0.1:8000")
    args = parser.parse_args()
    try:
        api = loopback_api(args.api)
    except ImportErrorSafe as exc:
        parser.error(str(exc))
    key = os.environ.get("SENTINEL_API_KEY", "")
    if not key:
        parser.error("Set SENTINEL_API_KEY in this terminal to the backend's lab key.")
    try:
        maximum = 20_000_000 if args.format == "pcap" else 2_000_000
        with args.path.open("rb") as source:
            raw = source.read(maximum + 1)
        if len(raw) > maximum:
            raise ImportErrorSafe(f"Input exceeds the {maximum:,}-byte limit; split the file first")
        if args.format == "pcap":
            body, endpoint, mime = raw, "/api/ingest/pcap", "application/octet-stream"
        else:
            body = json.dumps({"content": raw.decode("utf-8"), "format": args.format}, ensure_ascii=False).encode("utf-8")
            if len(body) > 3_000_000:
                raise ImportErrorSafe("Encoded import exceeds the API's 3 MB request limit; split the file first")
            endpoint, mime = "/api/ingest/zeek", "application/json"
        print(json.dumps(request_import(api, endpoint, body, mime, key), indent=2))
        return 0
    except ImportErrorSafe as exc:
        print(f"Import stopped: {exc}", file=sys.stderr)
    except (OSError, UnicodeError):
        print("Import failed: input could not be read as the selected format; no file content was displayed", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
