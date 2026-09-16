from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import Any

from unio_collector.collector.bundle.schema import BUNDLE_SCHEMA_VERSION


@dataclass(frozen=True)
class BundleSignatureMetadata:
    """Signature metadata contract for current unsigned evidence bundles."""

    status: str = "unsigned"
    metadata_version: str = BUNDLE_SCHEMA_VERSION
    digest_algorithm: str = "sha256"
    signed_payload: str = "checksums.json"
    signature_algorithm: str | None = None
    key_id: str | None = None
    created_at: str | None = None
    signature: str | None = None
    reason: str = "Bundle is unsigned in this phase; checksum metadata is present for integrity validation and future signed collector artifacts."

    def convert_to_dict(self) -> dict[str, Any]:  # noqa: D102
        return {
            "metadata_version": self.metadata_version,
            "status": self.status,
            "digest_algorithm": self.digest_algorithm,
            "signed_payload": self.signed_payload,
            "signature_algorithm": self.signature_algorithm,
            "key_id": self.key_id,
            "created_at": self.created_at,
            "signature": self.signature,
            "reason": self.reason,
        }


def build_unsigned_signature_metadata(
    *,
    metadata_version: str = BUNDLE_SCHEMA_VERSION,
) -> dict[str, Any]:
    """Build unsigned signature metadata for an evidence-bundle schema."""
    return BundleSignatureMetadata(metadata_version=metadata_version).convert_to_dict()
