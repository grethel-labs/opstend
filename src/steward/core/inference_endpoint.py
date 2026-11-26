"""Pure URL classification for inference endpoints (no I/O, no DNS).

A base URL is either a loopback address (local data path, usable with
`local_only`) or a public HTTPS URL (external). Anything else is rejected;
private LAN addresses are not accepted in this release. DNS results are checked
again at connection time by the transport.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import SplitResult, urlsplit

_HOST = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*")
_PATH = re.compile(r"/[A-Za-z0-9._~/-]{0,100}")


def _split(url: str) -> SplitResult | None:
    try:
        if any(ord(c) <= 32 or ord(c) >= 127 for c in url) or "\\" in url:
            return None
        parts = urlsplit(url)
        _ = parts.port  # raises on an invalid port
    except ValueError:
        return None
    if (
        parts.scheme not in ("http", "https")
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or parts.query
        or parts.fragment
        or (parts.path and not _PATH.fullmatch(parts.path))
    ):
        return None
    return parts


def is_loopback_host(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def loopback_url(url: str, *, schemes: tuple[str, ...] = ("http", "https")) -> bool:
    parts = _split(url)
    return parts is not None and parts.scheme in schemes and is_loopback_host(parts.hostname or "")


def public_https_url(url: str) -> bool:
    parts = _split(url)
    if parts is None or parts.scheme != "https" or parts.port not in (None, 443):
        return False
    host = parts.hostname or ""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return (
            bool(_HOST.fullmatch(host)) and host != "localhost" and not host.endswith(".localhost")
        )
    return ip.is_global and not ip.is_multicast and not ip.is_reserved


def parse(url: str) -> SplitResult:
    parts = _split(url)
    if parts is None:
        raise ValueError("invalid inference endpoint URL")
    return parts
