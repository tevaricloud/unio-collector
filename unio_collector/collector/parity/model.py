from __future__ import annotations  # noqa: D100

import hashlib
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from unio_collector.collector.parity.scanner import AwsScannerCapability

AWS_COLLECTION_PARITY_SCHEMA_VERSION = "2026-09-aws-collection-parity-v1"
AwsCollectionRuntimePath = Literal["core", "collector"]


@dataclass(frozen=True)
class AwsCollectionCapabilityModel:
    """Machine-readable AWS collection projection for one runtime path."""

    runtime_path: AwsCollectionRuntimePath
    scanners: tuple[AwsScannerCapability, ...]
    configuration_fields: tuple[str, ...]
    execution_contract: dict[str, Any]
    schema_version: str = AWS_COLLECTION_PARITY_SCHEMA_VERSION

    def convert_to_dict(self) -> dict[str, Any]:
        """Return deterministic JSON-compatible capability metadata."""
        return {
            "schema_version": self.schema_version,
            "runtime_path": self.runtime_path,
            "configuration_fields": list(self.configuration_fields),
            "execution_contract": self.execution_contract,
            "scanners": [item.convert_to_dict() for item in self.scanners],
        }

    def semantic_dict(self) -> dict[str, Any]:
        """Return the path-neutral contract used for parity comparison."""
        return {
            "schema_version": self.schema_version,
            "configuration_fields": list(self.configuration_fields),
            "execution_contract": self.execution_contract,
            "scanners": [item.semantic_dict() for item in self.scanners],
        }

    def to_json(self) -> str:
        """Serialize deterministically for validation and release evidence."""
        return (
            json.dumps(
                self.convert_to_dict(),
                indent=2,
                sort_keys=True,
                separators=(",", ": "),
            )
            + "\n"
        )

    def semantic_sha256(self) -> str:
        """Hash the normalized parity contract without runtime-path labels."""
        serialized = json.dumps(
            self.semantic_dict(),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(serialized).hexdigest()


__all__ = [
    "AWS_COLLECTION_PARITY_SCHEMA_VERSION",
    "AwsCollectionCapabilityModel",
    "AwsCollectionRuntimePath",
]
