from __future__ import annotations  # noqa: D100

import json
from collections.abc import Mapping, Sequence
from dataclasses import fields, is_dataclass
from datetime import date, datetime
from decimal import Decimal
from enum import Enum
from math import isfinite
from pathlib import Path
from typing import Any

SCANNER_EVIDENCE_PAYLOAD_SCHEMA_VERSION = "2026-01"
SERIALIZATION_FAILURE = "Scanner evidence contains an unsupported or invalid value."


def build_scanner_evidence_payload(  # noqa: D103
    *,
    scanner_id: str,
    evidence: object,
    provider_id: str | None = None,
) -> dict[str, Any]:
    payload, status, limitations = _serialize_evidence(evidence)
    evidence_type = type(evidence)
    result = {
        "bundle_schema_version": SCANNER_EVIDENCE_PAYLOAD_SCHEMA_VERSION,
        "scanner_id": scanner_id,
        "serialization_status": status,
        "serialization_format": "json-compatible-python-object",
        "evidence_type": evidence_type.__name__,
        "evidence_module": evidence_type.__module__,
        "payload": payload,
        "limitations": limitations,
    }
    if provider_id:
        result["provider_id"] = provider_id
    return result


def _serialize_evidence(evidence: object) -> tuple[Any, str, list[str]]:
    limitations: list[str] = []
    try:
        return _to_json_value(evidence, limitations), "serialized", limitations
    except Exception:  # noqa: BLE001
        return None, "serialization_failed", [SERIALIZATION_FAILURE]


def require_serialized_scanner_evidence(payload: Mapping[str, object]) -> None:
    """Prevent unavailable serialization from entering collection or analysis."""
    if payload.get("serialization_status") != "serialized":
        raise ValueError(SERIALIZATION_FAILURE)


def _to_json_value(value: object, limitations: list[str]) -> Any:  # noqa: ANN401, C901
    if isinstance(value, float) and not isfinite(value):
        raise ValueError(SERIALIZATION_FAILURE)
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ValueError(SERIALIZATION_FAILURE)
        return str(value)
    if isinstance(value, datetime | date):
        return value.isoformat()
    if isinstance(value, Enum):
        return _to_json_value(value.value, limitations)
    if isinstance(value, Path):
        return value.as_posix()
    if hasattr(value, "model_dump") and callable(value.model_dump):  # type: ignore[attr-defined]
        return _to_json_value(value.model_dump(mode="json"), limitations)  # type: ignore[attr-defined]
    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: _to_json_value(getattr(value, field.name), limitations) for field in fields(value)}
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if key is not None and not isinstance(key, str | int | float | bool | Decimal | date | Path | Enum):
                raise ValueError(SERIALIZATION_FAILURE)
            _to_json_value(key, limitations)
            name = str(key)
            if name in result:
                raise ValueError(SERIALIZATION_FAILURE)
            result[name] = _to_json_value(item, limitations)
        return result
    if isinstance(value, set | frozenset):
        normalized = [_to_json_value(item, limitations) for item in value]
        return sorted(normalized, key=lambda item: json.dumps(item, sort_keys=True, allow_nan=False))
    if isinstance(value, Sequence) and not isinstance(value, bytes | bytearray):
        return [_to_json_value(item, limitations) for item in value]
    raise ValueError(SERIALIZATION_FAILURE)
