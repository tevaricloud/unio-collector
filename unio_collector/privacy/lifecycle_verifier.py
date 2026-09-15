from __future__ import annotations  # noqa: D100

# ruff: noqa: EM101,EM102,TRY003
import base64
import json
from typing import TYPE_CHECKING, Any

from unio_collector.collector.bundle.validator import EvidenceBundleValidator
from unio_collector.privacy.binding_verification import verify_export_binding
from unio_collector.privacy.leak_scan import ProtectedArchiveLeakScanner
from unio_collector.privacy.vault import decrypt_vault

if TYPE_CHECKING:
    from unio_collector.privacy.leak.result import LeakScanResult
    from unio_collector.privacy.prepared_artifact import PreparedArtifact


class ProtectedExportLifecycleVerifier:
    """Validate a fully staged export before any final path is published."""

    def verify(
        self,
        *,
        archive_artifact: PreparedArtifact,
        vault_artifact: PreparedArtifact,
        recovery_artifact: PreparedArtifact | None,
        passphrase: str | None,
        expected_vault_plaintext: dict[str, object],
        external_preview: dict[str, object] | None,
        known_original_values: set[str],
        existing_recovery_key: bytes | None = None,
    ) -> LeakScanResult:
        """Run validation, leak scan, decrypt-test, and binding verification."""
        EvidenceBundleValidator().validate_or_raise(archive_artifact.temporary_path)
        leak_scan = ProtectedArchiveLeakScanner().scan_zip_bytes(
            archive_path=archive_artifact.temporary_path,
            known_original_values=known_original_values,
        )
        if not leak_scan.passed:
            findings = ", ".join(f"{finding.path}:{finding.category}" for finding in leak_scan.findings[:10])
            raise ValueError(f"Protected archive leak scan failed: {findings}")
        vault_payload = self._read_object(
            vault_artifact.temporary_path.read_bytes(),
            "identity vault",
        )
        recovery_key = existing_recovery_key
        if recovery_artifact is not None:
            try:
                recovery_key = base64.b64decode(
                    recovery_artifact.temporary_path.read_bytes().strip(),
                    validate=True,
                )
            except (ValueError, TypeError) as exc:
                raise ValueError("Staged recovery key is invalid.") from exc
        decrypted = decrypt_vault(
            vault_payload,
            passphrase=passphrase,
            recovery_key=recovery_key,
        )
        if decrypted != expected_vault_plaintext:
            raise ValueError("Staged identity vault plaintext does not match the protected export token map.")
        verify_export_binding(
            archive_path=archive_artifact.temporary_path,
            vault_path=vault_artifact.temporary_path,
            external_preview=external_preview,
        )
        return leak_scan

    def _read_object(self, data: bytes, label: str) -> dict[str, Any]:
        try:
            payload = json.loads(data.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"Staged {label} is invalid JSON.") from exc
        if not isinstance(payload, dict):
            raise ValueError(f"Staged {label} must be an object.")
        return payload
