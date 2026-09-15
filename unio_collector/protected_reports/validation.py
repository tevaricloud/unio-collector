from __future__ import annotations  # noqa: D100

from typing import Any

from unio_collector.collector.protocol import EvidenceProtocol
from unio_collector.protected_reports.constants import (
    PROTECTED_REPORT_PACKAGE_SIGNATURE_ALGORITHM,
    PROTECTED_REPORT_PACKAGE_SIGNED_PAYLOAD,
    PROTECTED_REPORT_PACKAGE_SIGNED_STATUS,
    PROTECTED_REPORT_PACKAGE_UNSIGNED_STATUS,
    PROTECTED_REPORT_PACKAGE_V1_SCHEMA_VERSION,
    PROTECTED_REPORT_PACKAGE_V2_SCHEMA_VERSION,
)
from unio_collector.protected_reports.render_contract.validator import ProtectedRenderContractValidator
from unio_collector.protected_reports.validation_result import (
    ProtectedReportPackageValidationResult,
)

FORBIDDEN_PRIVATE_KEYS = {
    "client_root_key",
    "decrypted_vault",
    "identity_vault",
    "passphrase",
    "private_key",
    "recovery_key",
    "root_key",
    "vault_plaintext",
}


__all__ = [
    "ProtectedReportPackageValidationResult",
    "ProtectedReportPackageValidator",
]


class ProtectedReportPackageValidator:
    """Validate the v1 unsigned protected report-package contract."""

    def validate(
        self,
        payload: dict[str, Any],
    ) -> ProtectedReportPackageValidationResult:
        """Validate a protected report-package payload."""
        errors: list[str] = []
        schema_version = payload.get("package_schema_version")
        is_v2 = schema_version == PROTECTED_REPORT_PACKAGE_V2_SCHEMA_VERSION
        is_v1 = schema_version == PROTECTED_REPORT_PACKAGE_V1_SCHEMA_VERSION
        if not is_v1 and not is_v2:
            errors.append("package_schema_version is not supported.")
        self._validate_protocol(payload, "v2" if is_v2 else "v1", errors)
        expected_format = "structured_render_contracts_v2" if is_v2 else "signed_structured_json_v1"
        if payload.get("package_format") != expected_format:
            errors.append("package_format does not match its schema version.")
        signature = payload.get("signature")
        if not isinstance(signature, dict):
            errors.append("signature must be an object.")
        elif signature.get("status") == PROTECTED_REPORT_PACKAGE_SIGNED_STATUS:
            self._validate_signed_signature(signature, errors)
        elif signature.get("status") != PROTECTED_REPORT_PACKAGE_UNSIGNED_STATUS:
            errors.append("signature status must be 'unsigned' or 'signed'.")
        privacy = payload.get("privacy")
        if not isinstance(privacy, dict) or privacy.get("enabled") is not True:
            errors.append("privacy metadata must identify a protected source.")
        else:
            self._validate_binding_metadata(payload, privacy, errors)
        findings = payload.get("findings")
        if not isinstance(findings, list):
            errors.append("findings must be a list.")
        self._validate_no_private_material(payload, errors)
        if is_v2:
            errors.extend(ProtectedRenderContractValidator().validate(payload))
        return ProtectedReportPackageValidationResult(
            passed=not errors,
            errors=tuple(errors),
        )

    def _validate_protocol(self, payload: dict[str, Any], version: str, errors: list[str]) -> None:
        try:
            protocol = EvidenceProtocol.from_report_type(payload.get("package_type"), version)
        except ValueError:
            errors.append("package_type is not supported.")
            return
        privacy = payload.get("privacy")
        if isinstance(privacy, dict):
            try:
                protocol.validate_privacy(privacy)
            except ValueError:
                errors.append("package_type does not match privacy protocol family.")

    def _validate_binding_metadata(
        self,
        payload: dict[str, Any],
        privacy: dict[str, Any],
        errors: list[str],
    ) -> None:
        source = payload.get("source")
        if not isinstance(source, dict):
            errors.append("source metadata must be an object.")
            return
        for key in (
            "protected_bundle_id",
            "engagement_id",
            "token_scope",
        ):
            privacy_valid = self._require_non_empty_string(
                privacy,
                key,
                "privacy",
                errors,
            )
            source_valid = self._require_non_empty_string(
                source,
                key,
                "source",
                errors,
            )
            if privacy_valid and source_valid and privacy[key] != source[key]:
                errors.append(f"source {key} does not match privacy metadata.")
        self._require_non_empty_string(
            privacy,
            "privacy_policy_version",
            "privacy",
            errors,
        )

    def _require_non_empty_string(
        self,
        payload: dict[str, Any],
        key: str,
        prefix: str,
        errors: list[str],
    ) -> bool:
        value = payload.get(key)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{prefix} {key} must be a non-empty string.")
            return False
        return True

    def _validate_signed_signature(
        self,
        signature: dict[str, Any],
        errors: list[str],
    ) -> None:
        if signature.get("signature_algorithm") != PROTECTED_REPORT_PACKAGE_SIGNATURE_ALGORITHM:
            errors.append("signed packages must use Ed25519 signatures.")
        if signature.get("signed_payload") != PROTECTED_REPORT_PACKAGE_SIGNED_PAYLOAD:
            errors.append("signed packages must sign package_without_signature.")
        errors.extend(
            f"signed packages require signature.{key}."
            for key in (
                "signature",
                "key_id",
                "created_at",
                "public_key_fingerprint",
            )
            if not isinstance(signature.get(key), str) or not signature.get(key)
        )

    def _validate_no_private_material(
        self,
        payload: dict[str, Any],
        errors: list[str],
    ) -> None:
        self._validate_private_keys(payload, errors)

    def _validate_private_keys(self, value: object, errors: list[str]) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if str(key).casefold() in FORBIDDEN_PRIVATE_KEYS:
                    errors.append(f"protected report package contains private material field: {key}")
                self._validate_private_keys(child, errors)
        elif isinstance(value, list):
            for child in value:
                self._validate_private_keys(child, errors)
