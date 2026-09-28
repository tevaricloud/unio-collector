"""Structured result contract for integrated protected collection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path


@dataclass(frozen=True)
class ProtectedCollectionResult:
    """Non-secret result of an integrated protected collection."""

    provider: str
    protected_bundle_path: Path
    protected_bundle_sha256: str
    vault_path: Path
    vault_sha256: str
    recovery_material_path: Path | None
    recovery_material_sha256: str | None
    receipt_path: Path
    receipt_sha256: str
    privacy_profile: str
    token_scope: str
    engagement_id: str
    cost_data_included: bool
    token_count: int
    relationship_count: int
    leak_scan_passed: bool
    validation_passed: bool
    raw_bundle_retained: bool
    raw_bundle_path: Path | None
    raw_bundle_sha256: str | None
    collection_status: str
    collection_limitations: tuple[dict[str, Any], ...]
    stages: dict[str, str]
    cleanup: dict[str, object]
    warnings: tuple[str, ...] = ()
    limitations: tuple[dict[str, Any], ...] = ()

    def convert_to_dict(self) -> dict[str, object]:
        """Return the stable machine-readable workflow result."""
        recovery = (
            {
                "path": str(self.recovery_material_path),
                "sha256": self.recovery_material_sha256,
            }
            if self.recovery_material_path is not None
            else {"path": None, "sha256": None, "mode": "passphrase"}
        )
        return {
            "status": "ready",
            "workflow": "collect-protected",
            "workflow_version": 1,
            "provider": self.provider,
            "stages": dict(self.stages),
            "protected_bundle": {
                "path": str(self.protected_bundle_path),
                "sha256": self.protected_bundle_sha256,
                "transferable": True,
            },
            "identity_vault": {
                "path": str(self.vault_path),
                "sha256": self.vault_sha256,
                "transferable": False,
            },
            "recovery_material": {**recovery, "transferable": False},
            "receipt": {
                "path": str(self.receipt_path),
                "sha256": self.receipt_sha256,
            },
            "privacy": {
                "profile": self.privacy_profile,
                "cost_data_included": self.cost_data_included,
                "token_scope": self.token_scope,
                "engagement_id": self.engagement_id,
                "token_count": self.token_count,
                "relationship_count": self.relationship_count,
            },
            "validation": {
                "protected_bundle_passed": self.validation_passed,
                "leak_scan_passed": self.leak_scan_passed,
            },
            "collection": {
                "status": self.collection_status,
                "limitations": list(self.collection_limitations),
            },
            "raw_bundle_retained": self.raw_bundle_retained,
            "raw_bundle": ({"path": str(self.raw_bundle_path), "sha256": self.raw_bundle_sha256} if self.raw_bundle_path is not None else None),
            "cleanup": dict(self.cleanup),
            "warnings": list(self.warnings),
            "limitations": list(self.limitations),
        }
