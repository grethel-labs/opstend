"""Pure URL classification for inference endpoints (no I/O, no DNS).

The direct transports classify loopback and public HTTPS URLs separately.
Managed private HTTPS uses its own exact numeric endpoint policy.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import SplitResult, urlsplit

_HOST = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*")
_PATH = re.compile(r"/[A-Za-z0-9._~/-]{0,100}")
_RFC1918 = tuple(
    ipaddress.IPv4Network(network) for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


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


def canonical_private_https_url(url: str) -> str:
    """Validate the exact HTTPS base URL used by the managed private relay."""
    parts = parse(url)
    try:
        address = ipaddress.IPv4Address(parts.hostname or "")
    except ValueError:
        raise ValueError("invalid managed private HTTPS endpoint") from None
    prefix = parts.path.removesuffix("/")
    if (
        parts.scheme != "https"
        or not parts.port
        or not any(address in network for network in _RFC1918)
        or url != f"https://{address}:{parts.port}{parts.path}"
        or (prefix and any(segment in ("", ".", "..") for segment in prefix[1:].split("/")))
    ):
        raise ValueError("invalid managed private HTTPS endpoint")
    return f"https://{address}:{parts.port}{prefix}"
