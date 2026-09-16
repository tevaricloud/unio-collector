from __future__ import annotations  # noqa: D100

import base64
import json
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlparse
from urllib.request import urlopen

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

if TYPE_CHECKING:
    from unio_collector.collector_cli.services.versioning.options import VersionCheckOptions

MAX_RELEASE_METADATA_BYTES = 1_048_576


class CollectorVersionChecker:
    """Verify explicitly requested release metadata without automatic network access."""

    def check(
        self,
        *,
        current_version: str,
        options: VersionCheckOptions,
    ) -> dict[str, object]:
        """Load, verify, and summarize signed release metadata."""
        if not options.metadata_location or not options.signature_location or not options.public_key_path:
            return self._failure(current_version, "Release metadata, signature, and trusted public key must all be configured.")
        try:
            metadata = self._read_location(options.metadata_location)
            signature_text = self._read_location(options.signature_location).decode("ascii").strip()
            public_key = self._load_public_key(Path(options.public_key_path))
            public_key.verify(base64.b64decode(signature_text, validate=True), metadata)
            payload = self._metadata_payload(metadata)
            available = str(payload["version"])
        except Exception as exc:  # noqa: BLE001
            return self._failure(current_version, str(exc))
        return {
            "available_version": available,
            "installed_version": current_version,
            "metadata_verified": True,
            "schema_version": 1,
            "release_status": str(payload.get("release_status") or "active"),
            "rollback_version": payload.get("rollback_version"),
            "revocation_reason": payload.get("revocation_reason"),
            "status": (
                "release_revoked"
                if payload.get("release_status") == "revoked"
                else "current"
                if available == current_version
                else "different_version_available"
            ),
        }

    def _metadata_payload(self, metadata: bytes) -> dict[str, object]:
        payload = json.loads(metadata)
        if not isinstance(payload, dict) or payload.get("schema_version") != 1:
            message = "Release metadata must use schema version 1."
            raise ValueError(message)
        available = str(payload.get("version") or "")
        if not available:
            message = "Release metadata does not contain a version."
            raise ValueError(message)
        release_status = payload.get("release_status", "active")
        if release_status not in {"active", "revoked"}:
            message = "Release metadata status must be active or revoked."
            raise ValueError(message)
        if release_status == "revoked" and not str(payload.get("revocation_reason") or "").strip():
            message = "Revoked release metadata requires a revocation reason."
            raise ValueError(message)
        return payload

    def _read_location(self, location: str) -> bytes:
        local_path = Path(location)
        if local_path.is_file():
            content = local_path.read_bytes()
            if len(content) > MAX_RELEASE_METADATA_BYTES:
                message = "Release metadata exceeds the size limit."
                raise ValueError(message)
            return content
        parsed = urlparse(location)
        if parsed.scheme:
            if parsed.scheme != "https":
                message = "Release metadata URLs must use HTTPS."
                raise ValueError(message)
            with urlopen(location, timeout=10) as response:  # noqa: S310
                content = response.read(MAX_RELEASE_METADATA_BYTES + 1)
        else:
            content = local_path.read_bytes()
        if len(content) > MAX_RELEASE_METADATA_BYTES:
            message = "Release metadata exceeds the size limit."
            raise ValueError(message)
        return content

    def _load_public_key(self, path: Path) -> Ed25519PublicKey:
        public_key = serialization.load_pem_public_key(path.read_bytes())
        if not isinstance(public_key, Ed25519PublicKey):
            message = "Release public key must be an Ed25519 public key."
            raise ValueError(message)
        return public_key

    def _failure(self, current_version: str, message: str) -> dict[str, object]:
        return {
            "available_version": "unknown",
            "error": message,
            "installed_version": current_version,
            "metadata_verified": False,
            "schema_version": 1,
            "status": "verification_failed",
        }


__all__ = ["CollectorVersionChecker"]
