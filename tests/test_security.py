"""Browser boundary checks need no server, database, capture, or credentials."""
import pytest

from backend.app.security import monitor_host_allowed, monitor_origin_allowed


@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.1:8004", "localhost", "LOCALHOST:5176", "[::1]", "[::1]:8004"])
def test_monitor_accepts_explicit_loopback_host(host):
    assert monitor_host_allowed(host)


@pytest.mark.parametrize("host", [
    None, "", "testserver", "example.test", "localhost.example.test", "127.0.0.1.example.test",
    "127.1", "2130706433", "127.0.0.2", "0.0.0.0", "::1", "[::ffff:127.0.0.1]",
    "localhost.", "localhost:", "localhost:0", "localhost:65536", "localhost:+80", "localhost:abc",
    "localhost,example.test", "localhost:80,localhost:81", "user@localhost", "localhost/path",
    "localhost?query", "localhost#fragment", "localhost\\path", " localhost", "localhost ",
    "localhost\r\nX-Header: injected", "localh\u00f6st", "[::1]extra", "[::1]:+80",
])
def test_monitor_rejects_untrusted_or_ambiguous_host(host):
    assert not monitor_host_allowed(host)


def test_cli_origin_is_absent_not_an_empty_or_opaque_origin():
    assert monitor_origin_allowed(None, [])
    assert not monitor_origin_allowed("", [""])
    assert not monitor_origin_allowed("null", ["null"])


@pytest.mark.parametrize("origin", ["http://127.0.0.1:5176", "http://localhost:5176", "https://[::1]:5176"])
def test_monitor_accepts_only_exact_configured_loopback_origin(origin):
    assert monitor_origin_allowed(origin, [origin])
    assert not monitor_origin_allowed(origin, ["http://127.0.0.1:5173"])


@pytest.mark.parametrize("origin", [
    "http://example.test", "https://example.test", "http://127.0.0.1.example.test",
    "http://localhost:5176/", "http://localhost:5176/path", "http://localhost:5176?q=1",
    "http://localhost:5176#x", "http://user@localhost:5176", "http://localhost:0", "file://localhost",
    "http://127.1", "http://[::1]:65536", "http://localhost:5176 http://localhost:5173",
])
def test_remote_or_malformed_origin_never_allowed_even_if_misconfigured(origin):
    assert not monitor_origin_allowed(origin, [origin])
