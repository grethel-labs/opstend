"""Bounded opaque identifiers shared by audit producers and consumers."""

import hashlib
import re

REQUEST_ID = re.compile(r"[A-Za-z0-9:_-]{8,80}")


def valid_request_id(value: object) -> bool:
    return isinstance(value, str) and REQUEST_ID.fullmatch(value) is not None


def graph_identifier(kind: str, *parts: str) -> str:
    """Derive a bounded identity from already validated graph identifiers."""
    digest = hashlib.sha256("/".join(parts).encode()).hexdigest()[:20]
    return f"{kind}{digest}"
