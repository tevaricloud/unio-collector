from __future__ import annotations  # noqa: D100

from typing import Any


def build_scanner_evidence_payloads(
    payloads: object,
    *,
    schema_version: str,
) -> list[dict[str, Any]]:
    """Return scanner-evidence payloads stamped with the bundle schema."""
    normalized: list[dict[str, Any]] = []
    if not isinstance(payloads, list):
        message = "Scanner evidence payloads must be a complete list of objects."
        raise ValueError(message)
    for payload in payloads:
        if not isinstance(payload, dict):
            message = "Scanner evidence payloads contain a malformed record."
            raise ValueError(message)
        normalized_payload = dict(payload)
        normalized_payload["bundle_schema_version"] = schema_version
        normalized.append(normalized_payload)
    return normalized
