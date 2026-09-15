from __future__ import annotations  # noqa: D100

# ruff: noqa: C901,EM101,EM102,TRY003
from typing import Any

from unio_collector.collector.protocol import EvidenceProtocol
from unio_collector.protected_reports.constants import PROTECTED_REPORT_PACKAGE_V2_SCHEMA_VERSION


class VaultPackageBindingValidator:
    """Validate public vault metadata and encrypted package export bindings."""

    def validate_metadata(
        self,
        package: dict[str, Any],
        vault_payload: dict[str, object],
    ) -> None:
        """Validate legacy identity fields or v2 lineage fingerprints."""
        metadata = vault_payload.get("metadata")
        privacy = package.get("privacy")
        if not isinstance(metadata, dict):
            raise ValueError("Vault metadata is missing or invalid.")
        if not isinstance(privacy, dict):
            raise ValueError("Protected report package privacy metadata is missing.")
        protocol = EvidenceProtocol.from_identifier(metadata.get("format"), ("vault-v1", "vault-v2"))
        version = "v2" if package.get("package_schema_version") == PROTECTED_REPORT_PACKAGE_V2_SCHEMA_VERSION else "v1"
        if EvidenceProtocol.from_report_type(package.get("package_type"), version) != protocol:
            raise ValueError("Vault and protected report package protocol families do not match.")
        protocol.validate_privacy(metadata, vault=True)
        protocol.validate_privacy(privacy)
        if package.get("package_schema_version") == PROTECTED_REPORT_PACKAGE_V2_SCHEMA_VERSION and privacy.get("vault_id") is not None:
            for key in ("vault_id", "root_key_fingerprint", "scope_fingerprint"):
                value = privacy.get(key)
                if not isinstance(value, str) or not value.strip() or value != metadata.get(key):
                    raise ValueError(f"Vault metadata {key} does not match package privacy metadata.")
            package_revision = privacy.get("vault_revision")
            vault_revision = metadata.get("revision")
            if type(package_revision) is not int or type(vault_revision) is not int or package_revision < 1 or vault_revision < package_revision:
                raise ValueError("Vault revision is older than the protected report package binding.")
            if privacy.get("token_format_version") != protocol.identifier("token-v1") or metadata.get("token_format_version") != protocol.identifier(
                "token-v1"
            ):
                raise ValueError("Vault token format does not match the protected report package.")
            return
        for package_key, vault_key in (
            ("protected_bundle_id", "protected_bundle_id"),
            ("engagement_id", "engagement_id"),
            ("token_scope", "token_scope"),
            ("privacy_policy_version", "policy_version"),
        ):
            package_value = privacy.get(package_key)
            vault_value = metadata.get(vault_key)
            if not isinstance(package_value, str) or not package_value.strip():
                raise ValueError(f"Protected report package privacy {package_key} must be a non-empty string.")
            if not isinstance(vault_value, str) or not vault_value.strip():
                raise ValueError(f"Vault metadata {vault_key} must be a non-empty string.")
            if package_value != vault_value:
                raise ValueError(f"Vault metadata {vault_key} does not match package privacy {package_key}.")

    def validate_export_binding(
        self,
        package: dict[str, Any],
        plaintext: dict[str, object],
    ) -> None:
        """Require a matching encrypted export binding when v2 bindings exist."""
        if package.get("package_schema_version") != PROTECTED_REPORT_PACKAGE_V2_SCHEMA_VERSION:
            return
        bindings = plaintext.get("export_bindings")
        if "export_bindings" not in plaintext:
            return
        privacy = package.get("privacy")
        if not isinstance(bindings, list) or not isinstance(privacy, dict):
            raise ValueError("Vault export bindings are invalid.")
        protected_bundle_id = privacy.get("protected_bundle_id")
        if not isinstance(protected_bundle_id, str) or not protected_bundle_id.strip():
            raise ValueError("Protected package export identity is missing.")
        identities: set[str] = set()
        for item in bindings:
            identity = item.get("protected_bundle_id") if isinstance(item, dict) else None
            if not isinstance(identity, str) or not identity.strip() or identity in identities:
                raise ValueError("Vault export bindings contain invalid or duplicate identities.")
            identities.add(identity)
        if protected_bundle_id not in identities:
            raise ValueError("Vault does not contain the protected package export binding.")
