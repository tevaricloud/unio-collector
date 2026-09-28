from __future__ import annotations  # noqa: D100

from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.collector.parity.operation import AwsOperationCapability


@dataclass(frozen=True)
class AwsScannerCapability:
    """One scanner's collection capability and owning provenance."""

    scanner_id: str
    definition_source_id: str
    factory_path: str
    implementation_path: str
    implementation_identity: tuple[tuple[str, str], ...]
    collection_callable: str
    evidence_return_annotation: str
    default_enabled: bool
    supports_regions: bool
    execution_phase: str
    dependencies: tuple[str, ...]
    operations: tuple[AwsOperationCapability, ...]
    permissions: tuple[dict[str, Any], ...]
    may_incur_charges: bool
    chargeable_reason: str
    output_finding_types: tuple[str, ...]

    def semantic_dict(self) -> dict[str, Any]:
        """Return fields that must be equal across the two runtime paths."""
        payload = self.convert_to_dict()
        payload.pop("factory_path")
        payload.pop("implementation_path")
        return payload

    def convert_to_dict(self) -> dict[str, Any]:
        """Return deterministic JSON-compatible scanner metadata."""
        payload = asdict(self)
        payload["implementation_identity"] = dict(
            self.implementation_identity,
        )
        payload["operations"] = [item.convert_to_dict() for item in self.operations]
        payload["permissions"] = [dict(item) for item in self.permissions]
        return payload


__all__ = ["AwsScannerCapability"]
