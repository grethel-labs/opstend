"""Closed JSON-schema subset for provider output, plus a strict validator.

Provider text is untrusted. A task declares one schema in this subset; the output
is accepted only if it validates. Every object is closed (`additionalProperties:
false`) and lists all its properties as required, so a provider cannot smuggle
extra keys such as tool names, SQL or shell commands into a result. Optional
values are expressed as `{"type": ["string", "null"], ...}`.
"""

from __future__ import annotations

import math
from typing import Any

MAX_DEPTH = 5
MAX_STRING = 4000
MAX_ITEMS = 50
_SCALARS = {"string", "integer", "number", "boolean", "null"}
_ALLOWED_KEYS = {
    "type",
    "properties",
    "required",
    "additionalProperties",
    "items",
    "maxItems",
    "enum",
    "maxLength",
    "minimum",
    "maximum",
}


class SchemaError(ValueError):
    """Either an invalid task schema (programming error) or a non-conforming output."""


def _kinds(schema: dict) -> list:
    kinds = schema.get("type")
    return [kinds] if isinstance(kinds, str) else kinds


def check_schema(schema: Any, *, depth: int = 0) -> None:
    """Reject schemas outside the closed subset (called when a task is defined)."""
    if depth > MAX_DEPTH or not isinstance(schema, dict) or set(schema) - _ALLOWED_KEYS:
        raise SchemaError("unsupported schema")
    kinds = _kinds(schema)
    if not kinds or not isinstance(kinds, list) or not set(kinds) <= _SCALARS | {"object", "array"}:
        raise SchemaError("unsupported schema type")
    if "object" in kinds:
        props = schema.get("properties")
        if (
            len(kinds) != 1
            or not isinstance(props, dict)
            or schema.get("additionalProperties") is not False
            or sorted(schema.get("required", [])) != sorted(props)
        ):
            raise SchemaError("objects must be closed with every property required")
        for sub in props.values():
            check_schema(sub, depth=depth + 1)
    if "array" in kinds:
        if len(kinds) != 1 or not 1 <= schema.get("maxItems", 0) <= MAX_ITEMS:
            raise SchemaError("arrays need a bounded maxItems")
        check_schema(schema.get("items"), depth=depth + 1)
    if (
        "string" in kinds
        and "enum" not in schema
        and not 1 <= schema.get("maxLength", 0) <= MAX_STRING
    ):
        raise SchemaError("strings need a bounded maxLength or an enum")


def validate(value: Any, schema: dict, *, depth: int = 0) -> Any:
    kinds = _kinds(schema)
    if depth > MAX_DEPTH:
        raise SchemaError("output too deep")
    if value is None:
        if "null" in kinds:
            return None
        raise SchemaError("unexpected null")
    if isinstance(value, bool):
        if "boolean" in kinds:
            return value
        raise SchemaError("unexpected boolean")
    if isinstance(value, int):
        if "integer" in kinds or "number" in kinds:
            return _bounded(value, schema)
        raise SchemaError("unexpected number")
    if isinstance(value, float):
        if "number" in kinds and math.isfinite(value):
            return _bounded(value, schema)
        raise SchemaError("unexpected number")
    if isinstance(value, str):
        if "string" not in kinds:
            raise SchemaError("unexpected string")
        if "enum" in schema and value not in schema["enum"]:
            raise SchemaError("value not in enum")
        if len(value) > schema.get("maxLength", MAX_STRING):
            raise SchemaError("string too long")
        return value
    if isinstance(value, list):
        if "array" not in kinds or len(value) > schema["maxItems"]:
            raise SchemaError("invalid array")
        return [validate(item, schema["items"], depth=depth + 1) for item in value]
    if isinstance(value, dict):
        if "object" not in kinds or set(value) != set(schema["properties"]):
            raise SchemaError("object keys do not match the schema")
        return {
            key: validate(item, schema["properties"][key], depth=depth + 1)
            for key, item in value.items()
        }
    raise SchemaError("unsupported value")


def _bounded(value, schema: dict):
    if "minimum" in schema and value < schema["minimum"]:
        raise SchemaError("number below minimum")
    if "maximum" in schema and value > schema["maximum"]:
        raise SchemaError("number above maximum")
    return value


def wire_schema(schema: dict) -> dict:
    """Portable subset for provider-side structured output (bounds stay local)."""
    out: dict = {}
    for key in ("type", "properties", "required", "additionalProperties", "items", "enum"):
        if key not in schema:
            continue
        value = schema[key]
        if key == "properties":
            value = {k: wire_schema(v) for k, v in value.items()}
        elif key == "items":
            value = wire_schema(value)
        out[key] = value
    return out
