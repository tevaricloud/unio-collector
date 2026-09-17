from __future__ import annotations  # noqa: D100

import json
from math import isfinite
from typing import Any


def dump_json(payload: Any) -> bytes:  # noqa: ANN401
    """Encode a deterministic indented JSON bundle member."""
    return json.dumps(payload, indent=2, sort_keys=True, allow_nan=False).encode("utf-8")


def dump_jsonl(records: list[Any]) -> bytes:
    """Encode deterministic JSON Lines bundle records."""
    return "".join(json.dumps(record, sort_keys=True, allow_nan=False) + "\n" for record in records).encode("utf-8")


def load_json(value: str) -> Any:  # noqa: ANN401
    """Decode finite JSON with unambiguous member identities."""
    return json.loads(value, object_pairs_hook=_unique_members, parse_constant=_reject_constant, parse_float=_finite_float)


def load_json_object(value: str) -> dict[str, Any]:
    """Require populated metadata while leaving generic JSON arrays supported."""
    payload = load_json(value)
    if not isinstance(payload, dict) or not payload:
        message = "Metadata must contain a non-empty JSON object."
        raise ValueError(message)
    return payload


def _unique_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            message = "JSON contains duplicate member names."
            raise ValueError(message)
        result[name] = value
    return result


def _reject_constant(_value: str) -> object:
    message = "JSON contains a non-finite number."
    raise ValueError(message)


def _finite_float(value: str) -> float:
    number = float(value)
    if not isfinite(number):
        _reject_constant(value)
    return number


def validate_internal_path(name: str) -> None:
    """Reject non-portable or traversal-capable bundle member paths."""
    if "\\" in name or name.startswith("/") or ".." in name.split("/"):
        msg = f"Invalid platform-neutral bundle path: {name}"
        raise ValueError(msg)
