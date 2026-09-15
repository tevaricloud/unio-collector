from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

from unio_collector.collector.bundle.encoding import load_json_object
from unio_collector.collector.protocol import DEFAULT_PROTOCOL, EvidenceProtocol
from unio_collector.privacy.admission.metadata import ProtectedMetadataConsistency
from unio_collector.privacy.constants import (
    PRIVACY_CLASSIFICATION_FILE,
    PRIVACY_LEAK_SCAN_FILE,
    PRIVACY_POLICY_FILE,
    PRIVACY_POLICY_VERSION,
    PRIVACY_PREVIEW_FILE,
    PRIVACY_TOKEN_METADATA_FILE,
    PROTECTED_EXPORT_RECEIPT_SCHEMA_VERSION,
    SUPPORTED_PRIVACY_PROFILES,
    SUPPORTED_TOKEN_SCOPES,
)
from unio_collector.privacy.source_identity import (
    LEGACY_SOURCE_BUNDLE_IDENTITY_SCHEME,
    resolve_source_bundle_identity_scheme,
)
from unio_collector.privacy.synthetic_private_markers import (
    synthetic_openssh_private_key_marker,
    synthetic_private_key_marker,
)

if TYPE_CHECKING:
    from zipfile import ZipFile

PRIVATE_MATERIAL_KEYS = {
    "client_root_key",
    "decrypted_vault",
    "encrypted_root_key",
    "identity_vault",
    "passphrase",
    "private_key",
    "recovery_key",
    "recovery_key_bytes",
    "root_key",
    "vault_ciphertext",
    "vault_plaintext",
    "wrapped_root_key",
}
PRIVATE_MATERIAL_TEXT = (
    synthetic_private_key_marker(),
    synthetic_openssh_private_key_marker(),
    "vault plaintext",
    "vault ciphertext",
    "client root key",
    "recovery key bytes",
)
LOCAL_PATH_MARKERS = (
    "\\users\\",
    "/users/",
    "\\appdata\\local\\temp\\",
    "/tmp/",  # noqa: S108
    "unio-collector-privacy-",
)


class ProtectedBundlePrivacyMetadataValidator:
    """Validate protected bundle privacy metadata without vault access."""

    def validate(
        self,
        archive: ZipFile,
        names: set[str],
        manifest: dict[str, object],
        errors: list[str],
        *,
        protocol: EvidenceProtocol | None = None,
    ) -> None:
        """Append privacy metadata validation errors for protected bundles."""
        privacy = manifest.get("privacy_protection")
        if not isinstance(privacy, dict) or privacy.get("enabled") is not True:
            return

        if protocol is None:
            try:
                protocol = EvidenceProtocol.from_identifier(privacy.get("token_format_version"), ("token-v1",))
            except ValueError:
                protocol = DEFAULT_PROTOCOL

        metadata = {
            PRIVACY_POLICY_FILE: self._read_json(archive, PRIVACY_POLICY_FILE, errors),
            PRIVACY_CLASSIFICATION_FILE: self._read_json(
                archive,
                PRIVACY_CLASSIFICATION_FILE,
                errors,
            ),
            PRIVACY_PREVIEW_FILE: self._read_json(archive, PRIVACY_PREVIEW_FILE, errors),
            PRIVACY_LEAK_SCAN_FILE: self._read_json(
                archive,
                PRIVACY_LEAK_SCAN_FILE,
                errors,
            ),
            PRIVACY_TOKEN_METADATA_FILE: self._read_json(
                archive,
                PRIVACY_TOKEN_METADATA_FILE,
                errors,
            ),
        }
        missing = [path for path, payload in metadata.items() if path not in names or not payload]
        errors.extend(f"Missing or invalid protected privacy metadata file: {path}" for path in missing)
        if missing:
            return

        policy = metadata[PRIVACY_POLICY_FILE]
        classification = metadata[PRIVACY_CLASSIFICATION_FILE]
        preview = metadata[PRIVACY_PREVIEW_FILE]
        leak_scan = metadata[PRIVACY_LEAK_SCAN_FILE]
        token_metadata = metadata[PRIVACY_TOKEN_METADATA_FILE]

        self._validate_manifest_privacy(privacy, errors, protocol)
        self._validate_policy(policy, privacy, errors, protocol)
        self._validate_preview(preview, privacy, errors)
        self._validate_leak_scan(leak_scan, errors)
        self._validate_token_metadata(token_metadata, privacy, errors, protocol)
        self._validate_classification(classification, privacy, errors)
        ProtectedMetadataConsistency().validate(privacy, metadata, names, errors)
        for path, payload in metadata.items():
            self._validate_no_private_material(path, payload, errors)

    def _read_json(
        self,
        archive: ZipFile,
        name: str,
        errors: list[str],
    ) -> dict[str, Any]:
        try:
            payload = load_json_object(archive.read(name).decode("utf-8"))
        except KeyError:
            return {}
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{name} is invalid JSON: {exc}")
            return {}
        if not isinstance(payload, dict):
            errors.append(f"{name} must be a JSON object.")
            return {}
        return payload

    def _validate_manifest_privacy(  # noqa: C901
        self,
        privacy: dict[str, Any],
        errors: list[str],
        protocol: EvidenceProtocol = DEFAULT_PROTOCOL,
    ) -> None:
        if privacy.get("privacy_policy_version") != PRIVACY_POLICY_VERSION:
            errors.append("manifest.json privacy policy version is not supported.")
        if privacy.get("profile_id") not in SUPPORTED_PRIVACY_PROFILES:
            errors.append("manifest.json privacy profile is not supported.")
        if privacy.get("profile_version") != PRIVACY_POLICY_VERSION:
            errors.append("manifest.json privacy profile version is not supported.")
        if privacy.get("token_format_version") != protocol.identifier("token-v1"):
            errors.append("manifest.json token format version is not supported.")
        if privacy.get("token_scope") not in SUPPORTED_TOKEN_SCOPES:
            errors.append("manifest.json token scope is not supported.")
        if not isinstance(privacy.get("protected_bundle_id"), str) or not privacy.get("protected_bundle_id"):
            errors.append("manifest.json protected bundle id is missing.")
        if not isinstance(privacy.get("engagement_id"), str) or not privacy.get("engagement_id"):
            errors.append("manifest.json engagement id is missing.")
        if "vault_id" in privacy:
            errors.extend(
                f"manifest.json {field} is missing or invalid."
                for field in ("vault_id", "root_key_fingerprint", "scope_fingerprint")
                if not isinstance(privacy.get(field), str) or not privacy.get(field)
            )
            self._validate_non_negative_counter(
                privacy,
                "vault_revision",
                "manifest privacy",
                errors,
            )
            if privacy.get("vault_revision") == 0:
                errors.append("manifest privacy vault_revision must be positive.")
        if privacy.get("vault_included") is not False:
            errors.append("manifest.json must record vault_included=false.")
        if privacy.get("recovery_material_included") is not False:
            errors.append("manifest.json must record recovery_material_included=false.")
        if privacy.get("leak_scan_passed") is not True:
            errors.append("manifest.json must record a passing final leak scan.")
        if "export_receipt_required" in privacy:
            if privacy.get("export_receipt_required") is not True:
                errors.append("manifest.json export receipt requirement is invalid.")
            if privacy.get("export_receipt_schema_version") != PROTECTED_EXPORT_RECEIPT_SCHEMA_VERSION:
                errors.append("manifest.json export receipt schema version is not supported.")
            for field in ("source_bundle_id", "source_bundle_id_scheme"):
                value = privacy.get(field)
                if not isinstance(value, str) or not value.strip():
                    errors.append(f"manifest.json {field} is missing for a receipt-enabled bundle.")

    def _validate_policy(  # noqa: C901
        self,
        policy: dict[str, Any],
        privacy: dict[str, Any],
        errors: list[str],
        protocol: EvidenceProtocol = DEFAULT_PROTOCOL,
    ) -> None:
        if policy.get("policy_version") != PRIVACY_POLICY_VERSION:
            errors.append("privacy/protection-policy.json policy version is not supported.")
        bundle_id = policy.get("bundle_id")
        if not isinstance(bundle_id, str) or not bundle_id.strip():
            errors.append("privacy/protection-policy.json bundle_id is missing.")
        identity_scheme = resolve_source_bundle_identity_scheme(policy)
        if identity_scheme not in {
            protocol.identifier("source-bundle-content-sha256-v1"),
            LEGACY_SOURCE_BUNDLE_IDENTITY_SCHEME,
        }:
            errors.append("privacy/protection-policy.json bundle identity scheme is not supported.")
        if identity_scheme == protocol.identifier("source-bundle-content-sha256-v1") and (
            not isinstance(bundle_id, str) or not bundle_id.startswith("sha256:") or len(bundle_id) != len("sha256:") + 64
        ):
            errors.append("privacy/protection-policy.json content bundle_id is invalid.")
        if "export_receipt_required" in policy:
            if policy.get("export_receipt_required") is not True:
                errors.append("privacy/protection-policy.json export receipt requirement is invalid.")
            if policy.get("export_receipt_schema_version") != PROTECTED_EXPORT_RECEIPT_SCHEMA_VERSION:
                errors.append("privacy/protection-policy.json export receipt schema version is not supported.")
            if privacy.get("export_receipt_required") is not True:
                errors.append("privacy policy export receipt requirement does not match manifest.")
        profile = policy.get("profile")
        if not isinstance(profile, dict):
            errors.append("privacy/protection-policy.json profile must be an object.")
            return
        if profile.get("profile_id") != privacy.get("profile_id"):
            errors.append("privacy profile id does not match manifest.")
        if profile.get("version") != privacy.get("profile_version"):
            errors.append("privacy profile version does not match manifest.")
        errors.extend(
            f"privacy policy {key} does not match manifest."
            for key in ("token_scope", "engagement_id", "protected_bundle_id")
            if policy.get(key) != privacy.get(key)
        )
        if "vault_id" in privacy:
            errors.extend(
                f"privacy policy {key} does not match manifest."
                for key in ("vault_id", "vault_revision", "root_key_fingerprint", "scope_fingerprint")
                if policy.get(key) != privacy.get(key)
            )
        self._validate_non_negative_counter(
            policy.get("coverage_gate", {}),
            "unclassified_field_count",
            "privacy policy",
            errors,
        )

    def _validate_preview(
        self,
        preview: dict[str, Any],
        privacy: dict[str, Any],
        errors: list[str],
    ) -> None:
        errors.extend(
            f"privacy preview {key} does not match manifest."
            for key in ("token_scope", "engagement_id", "protected_bundle_id")
            if preview.get(key) != privacy.get(key)
        )
        if "vault_id" in privacy:
            errors.extend(
                f"privacy preview {key} does not match manifest."
                for key in ("vault_id", "vault_revision", "root_key_fingerprint", "scope_fingerprint")
                if preview.get(key) != privacy.get(key)
            )
        if preview.get("vault_included") is not False:
            errors.append("privacy preview must record vault_included=false.")
        if preview.get("recovery_material_included") is not False:
            errors.append("privacy preview must record recovery_material_included=false.")
        self._validate_non_negative_counter(
            preview,
            "unclassified_field_count",
            "privacy preview",
            errors,
        )

    def _validate_leak_scan(
        self,
        leak_scan: dict[str, Any],
        errors: list[str],
    ) -> None:
        if leak_scan.get("passed") is not True:
            errors.append("privacy leak scan summary must record passed=true.")
        self._validate_non_negative_counter(
            leak_scan,
            "files_scanned",
            "privacy leak scan",
            errors,
        )

    def _validate_token_metadata(
        self,
        token_metadata: dict[str, Any],
        privacy: dict[str, Any],
        errors: list[str],
        protocol: EvidenceProtocol = DEFAULT_PROTOCOL,
    ) -> None:
        if token_metadata.get("token_format_version") != protocol.identifier("token-v1"):
            errors.append("privacy token metadata format version is not supported.")
        errors.extend(
            f"privacy token metadata {key} does not match manifest." for key in ("token_scope", "engagement_id") if token_metadata.get(key) != privacy.get(key)
        )
        self._validate_non_negative_counter(
            token_metadata,
            "token_count",
            "privacy token metadata",
            errors,
        )

    def _validate_classification(
        self,
        classification: dict[str, Any],
        privacy: dict[str, Any],
        errors: list[str],
    ) -> None:
        for key in ("preserved", "removed"):
            self._validate_non_negative_counter(
                classification,
                key,
                "privacy classification",
                errors,
            )
        unclassified = classification.get("unclassified")
        if not isinstance(unclassified, list):
            errors.append("privacy classification unclassified must be a list.")
            return
        if privacy.get("profile_id") in {"standard", "strict"} and unclassified:
            errors.append("standard/strict protected bundles must not contain unclassified fields.")
        self._validate_prohibited_paths(classification, errors)
        tokenised = classification.get("tokenised")
        if "tokenised" in classification and not isinstance(tokenised, dict):
            errors.append("privacy classification token counters must be an object.")
        if isinstance(tokenised, dict):
            for category, count in tokenised.items():
                if not isinstance(category, str) or type(count) is not int or count < 0:
                    errors.append("privacy classification token counters must be non-negative integers.")
                    break
        resolver_decisions = classification.get("resolver_decisions")
        if isinstance(resolver_decisions, dict):
            for key in (
                "registry_decisions_used",
                "fallback_decisions_used",
                "prohibited_decisions",
                "unsupported_decisions",
            ):
                self._validate_non_negative_counter(
                    resolver_decisions,
                    key,
                    "privacy classification resolver decisions",
                    errors,
                )

    def _validate_prohibited_paths(
        self,
        classification: dict[str, Any],
        errors: list[str],
    ) -> None:
        prohibited_paths = classification.get("prohibited_paths")
        if prohibited_paths is None:
            return
        if not isinstance(prohibited_paths, list):
            errors.append("privacy classification prohibited_paths must be a list.")
            return
        if prohibited_paths:
            errors.append("protected bundles must not contain prohibited privacy-registry paths.")

    def _validate_non_negative_counter(
        self,
        payload: object,
        key: str,
        label: str,
        errors: list[str],
    ) -> None:
        if not isinstance(payload, dict):
            errors.append(f"{label} counters must be an object.")
            return
        value = payload.get(key)
        if type(value) is not int or value < 0:
            errors.append(f"{label} {key} must be a non-negative integer.")

    def _validate_no_private_material(
        self,
        path: str,
        payload: object,
        errors: list[str],
    ) -> None:
        self._walk_for_private_material(path, payload, errors)

    def _walk_for_private_material(
        self,
        path: str,
        value: object,
        errors: list[str],
    ) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                key_text = str(key).casefold()
                if key_text in PRIVATE_MATERIAL_KEYS:
                    errors.append(f"{path} contains private material key: {key}")
                self._walk_for_private_material(f"{path}.{key}", child, errors)
            return
        if isinstance(value, list):
            for index, child in enumerate(value):
                self._walk_for_private_material(f"{path}[{index}]", child, errors)
            return
        if isinstance(value, str):
            text = value.casefold()
            if any(marker.casefold() in text for marker in PRIVATE_MATERIAL_TEXT):
                errors.append(f"{path} contains private material marker.")
            if any(marker in text for marker in LOCAL_PATH_MARKERS):
                errors.append(f"{path} contains a local temporary or user path.")
