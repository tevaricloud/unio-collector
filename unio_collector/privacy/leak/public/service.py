"""Finite service producer literals in the known-original scan view only."""

from __future__ import annotations

from copy import deepcopy
from datetime import date
from typing import TYPE_CHECKING, Any

from unio_collector.privacy.service.fields import SCANNERS, VOCABULARIES

MONTH_PRECISION_LENGTH = 7

if TYPE_CHECKING:
    from unio_collector.privacy.service.coverage import ServiceCoveragePrivacyContract


def admitted_service_record(value: Any, contract: ServiceCoveragePrivacyContract) -> bool:  # noqa: ANN401
    """Leave malformed or wrong-kind records entirely visible to known-value scanning."""
    candidate = deepcopy(value)
    if isinstance(candidate, dict) and isinstance(candidate.get("attributes"), dict):
        timestamp = candidate["attributes"].get("creation_date")
        if isinstance(timestamp, str) and len(timestamp) == MONTH_PRECISION_LENGTH:
            try:
                date.fromisoformat(timestamp + "-01")
            except ValueError:
                return False
            candidate["attributes"]["creation_date"] = timestamp + "-01"
    return not contract.unknown_paths(candidate, "", "records[]")


def is_service_literal(contract: ServiceCoveragePrivacyContract, suffix: str, value: str) -> bool:
    """Recognize exact finite metadata positions, never identifiers or tag values."""
    service, kinds, metadata = SCANNERS[contract.scanner_id]
    if suffix == "records[].service":
        return value == service
    if suffix == "records[].resource_type":
        return value in kinds
    if suffix == "records[].attributes.state":
        return value in {"running", "stopped"}
    if suffix.startswith("metadata.") and suffix.removeprefix("metadata.").removesuffix("[]") not in metadata:
        return False
    spec = contract.fields.get(suffix)
    return spec is not None and spec[1] == "safe_metadata" and value in VOCABULARIES.get(spec[0], set())
