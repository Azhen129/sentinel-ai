"""Verify private lab transport without making network requests or real imports."""
import io
import json
from http.client import BadStatusLine
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler

import pytest

from scripts import import_lab


@pytest.mark.parametrize("api", ["http://127.0.0.1:8000", "http://[::1]:8000", "https://127.0.0.1", "https://[::1]"])
def test_literal_loopback_origins(api):
    assert import_lab.loopback_api(api) == api


@pytest.mark.parametrize("api", [
    "http://localhost:8000", "http://example.test", "http://127.0.0.2", "http://127.1",
    "http://2130706433", "http://user:secret@127.0.0.1", "http://127.0.0.1/path",
    "http://127.0.0.1/", "http://127.0.0.1?q=1", "http://127.0.0.1#x", "file://127.0.0.1",
    "http://127.0.0.1:0", "http://127.0.0.1:65536", "http://127.0.0.1:",
    "http://127.0.0.1:+80", "http://127.0.0.1:80,example.test", "http://127.0.0.1\r\n",
    "http://[::1]extra", "http://::1", "http://[::1]:+80",
])
def test_reject_remote_or_ambiguous_api_before_transport(api, monkeypatch):
    monkeypatch.setattr(import_lab, "build_opener", lambda *args: pytest.fail("Transport must not be created"))
    with pytest.raises(import_lab.ImportErrorSafe):
        import_lab.request_import(api, "/api/ingest/zeek", b"private-input", "application/json", "test-key")


class Response(io.BytesIO):
    pass


def test_proxy_environment_ignored_and_redirects_disabled(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://example.test:3128")
    monkeypatch.setenv("HTTPS_PROXY", "http://example.test:3128")
    observed = {}

    class Opener:
        def open(self, request, timeout):
            observed.update(url=request.full_url, timeout=timeout, key=request.get_header("X-sentinel-key"), data=request.data)
            return Response(json.dumps({"ingested": 2, "origin": "lab", "source": "zeek", "untrusted_extra": "not printed"}).encode())

    def build(*handlers):
        assert any(isinstance(h, ProxyHandler) and h.proxies == {} for h in handlers)
        redirect = next(h for h in handlers if isinstance(h, import_lab.NoRedirects))
        assert redirect.redirect_request(None, None, 302, "redirect", {}, "https://example.test") is None
        return Opener()

    monkeypatch.setattr(import_lab, "build_opener", build)
    result = import_lab.request_import("http://127.0.0.1:8000", "/api/ingest/zeek", b"test-body", "application/json", "test-key")
    assert result == {"ingested": 2, "origin": "lab", "source": "zeek"}
    assert observed == {"url": "http://127.0.0.1:8000/api/ingest/zeek", "timeout": 30, "key": "test-key", "data": b"test-body"}


@pytest.mark.parametrize("code", [301, 302, 303, 307, 308, 401, 500])
def test_http_errors_never_read_or_echo_private_response(code, monkeypatch):
    class PrivateResponse:
        def read(self, *args):
            pytest.fail("Error response body must not be read")

        def close(self):
            pass

    class Opener:
        def open(self, *args, **kwargs):
            raise HTTPError("http://127.0.0.1", code, "private-body-or-key", {}, PrivateResponse())

    monkeypatch.setattr(import_lab, "build_opener", lambda *args: Opener())
    with pytest.raises(import_lab.ImportErrorSafe) as exc:
        import_lab.request_import("http://127.0.0.1", "/api/ingest/zeek", b"private-body", "application/json", "private-key")
    assert str(code) in str(exc.value)
    assert "private" not in str(exc.value)


@pytest.mark.parametrize("raw", [b"not-json", b"[]", b'{"ingested":true,"origin":"lab","source":"zeek"}', b'{"ingested":1,"origin":"live","source":"zeek"}', b'x' * (import_lab.MAX_RESPONSE_BYTES + 1)], ids=["invalid-json", "non-object", "boolean-count", "wrong-origin", "too-large"])
def test_bad_or_oversized_acknowledgment_is_bounded_and_not_echoed(raw, monkeypatch):
    class Opener:
        def open(self, *args, **kwargs):
            return Response(raw)

    monkeypatch.setattr(import_lab, "build_opener", lambda *args: Opener())
    with pytest.raises(import_lab.ImportErrorSafe):
        import_lab.request_import("http://127.0.0.1", "/api/ingest/zeek", b"body", "application/json", "test-key")


@pytest.mark.parametrize("error", [URLError("private-api-key-or-traffic"), BadStatusLine("private-response-content")], ids=["network", "malformed-http"])
def test_network_error_does_not_echo_url_or_key(monkeypatch, error):
    class Opener:
        def open(self, *args, **kwargs):
            raise error

    monkeypatch.setattr(import_lab, "build_opener", lambda *args: Opener())
    with pytest.raises(import_lab.ImportErrorSafe) as exc:
        import_lab.request_import("http://127.0.0.1", "/api/ingest/zeek", b"body", "application/json", "private-key")
    assert "private" not in str(exc.value)


def test_documented_valid_cli_preserves_local_zeek_import(monkeypatch, capsys):
    fixture = Path(__file__).resolve().parents[1] / "data" / "examples" / "conn.json"
    observed = {}

    def fake_import(api, endpoint, body, mime, key):
        observed.update(api=api, endpoint=endpoint, payload=json.loads(body), mime=mime, key=key)
        return {"ingested": 3, "origin": "lab", "source": "zeek"}

    monkeypatch.setenv("SENTINEL_API_KEY", "test-only-key")
    monkeypatch.setattr(import_lab.sys, "argv", ["import_lab.py", str(fixture), "--format", "json"])
    monkeypatch.setattr(import_lab, "request_import", fake_import)
    assert import_lab.main() == 0
    assert observed == {"api": "http://127.0.0.1:8000", "endpoint": "/api/ingest/zeek",
        "payload": {"content": fixture.read_text(encoding="utf-8"), "format": "json"},
        "mime": "application/json", "key": "test-only-key"}
    printed = capsys.readouterr()
    assert json.loads(printed.out) == {"ingested": 3, "origin": "lab", "source": "zeek"}
    assert "test-only-key" not in printed.out + printed.err
