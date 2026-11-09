"""Pure browser-boundary checks for the private loopback monitoring profile.

These checks supplement the socket-peer restriction and keyed ingestion. They do
not authenticate local users/processes or make a public monitoring API safe.
"""
from collections.abc import Iterable
from urllib.parse import urlsplit


LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


def monitor_host_allowed(host_header: str | None) -> bool:
    """Accept one explicit loopback Host with an optional valid numeric port.

    IPv6 Host syntax requires brackets. Do not add test-host exceptions here;
    test clients should use a real allowed loopback base URL.
    """
    if not isinstance(host_header, str) or not host_header or len(host_header) > 255:
        return False
    if not host_header.isascii() or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in host_header):
        return False
    if any(c in host_header for c in "/\\@,?#") or host_header.endswith(":"):
        return False
    try:
        parsed = urlsplit("http://" + host_header)
        if parsed.hostname not in LOOPBACK_HOSTS or parsed.username is not None or parsed.password is not None:
            return False
        if parsed.path or parsed.query or parsed.fragment or parsed.netloc != host_header:
            return False
        if parsed.hostname == "::1" and not host_header.startswith("["):
            return False
        port = parsed.port
        if port is not None and not 1 <= port <= 65535:
            return False
        # urlsplit accepts unusual port representations such as +80. Require digits.
        suffix = host_header.partition("]")[2] if host_header.startswith("[") else host_header.partition(":")[2]
        if suffix and not (suffix[1:].isdigit() if suffix.startswith(":") else suffix.isdigit()):
            return False
    except (ValueError, UnicodeError):
        return False
    return True


def _loopback_origin(origin: str) -> bool:
    if not isinstance(origin, str) or not origin:
        return False
    try:
        parsed = urlsplit(origin)
        return (parsed.scheme in {"http", "https"}
                and parsed.path == "" and not parsed.query and not parsed.fragment
                and origin == parsed.scheme + "://" + parsed.netloc
                and monitor_host_allowed(parsed.netloc))
    except (ValueError, UnicodeError):
        return False


def monitor_origin_allowed(origin: str | None, allowed_origins: Iterable[str]) -> bool:
    """Allow CLI requests without Origin, or an exact configured loopback origin.

    Check unsafe browser requests independently of CORS response headers. A
    present empty or opaque ``null`` Origin is not a CLI request.
    """
    if origin is None:
        return True
    return _loopback_origin(origin) and origin in allowed_origins
