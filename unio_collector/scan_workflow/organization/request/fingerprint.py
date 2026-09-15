"""Neutral organization request fingerprinting for safe resume."""

from __future__ import annotations

import hashlib
import json
import posixpath
import re
from dataclasses import asdict
from typing import TYPE_CHECKING

from unio_collector.collector.organization import ORGANIZATION_ENVELOPE_SCHEMA_VERSION

if TYPE_CHECKING:
    from unio_collector.collector.config.protocol import CollectionConfigProtocol
    from unio_collector.collector.minimisation import EvidenceMinimisationOptions
    from unio_collector.config.organization import AwsOrganizationConfig
    from unio_collector.providers.aws.organization import OrganizationDiscoveryResult
    from unio_collector.scanners.selection import ScannerSelection


class OrganizationRequestFingerprint:
    """Bind resume authority to declared execution inputs and opaque extension data."""

    def build_digest(
        self,
        config: AwsOrganizationConfig,
        scan_config: CollectionConfigProtocol,
        selection: ScannerSelection,
        discovery: OrganizationDiscoveryResult,
        *,
        operation: str,
        minimisation: EvidenceMinimisationOptions | None,
        report_payload: dict[str, object] | None,
    ) -> str:
        """Return a deterministic fingerprint without including secret values."""
        payload = {
            "authorization": asdict(config.authorization),
            "selection": asdict(config.selection),
            "role": {
                "role_name": config.audit_role.role_name,
                "arn_template": config.audit_role.arn_template,
                "duration_seconds": config.audit_role.duration_seconds,
                "external_id_source_kind": self._external_id_kind(config),
                **self._external_id_identity(config),
            },
            "accounts": [(item.account_id, item.state, item.parent_id) for item in discovery.selection.selected],
            "scanners": sorted(getattr(selection, "enabled_ids", ())),
            "regions": sorted(getattr(scan_config, "regions", ())),
            "period": str(getattr(scan_config, "scan_period", "")),
            "operation": operation,
            "scan_config": {
                name: getattr(scan_config, name, None)
                for name in (
                    "provider_id",
                    "scan_mode",
                    "scan_preset",
                    "scan_pillars",
                    "scan_detail_profile",
                    "allow_chargeable_scanners",
                    "report_currency",
                    "report_date_format",
                    "redacted_reports",
                    "redacted_trial_pack",
                    "redact_audit_ledger",
                    "redact_generative_input",
                    "scanner_options",
                )
            },
            "minimisation": asdict(minimisation) if minimisation is not None else None,
            "report": report_payload,
            "schema": ORGANIZATION_ENVELOPE_SCHEMA_VERSION,
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()

    def _external_id_kind(self, config: AwsOrganizationConfig) -> str | None:
        if config.audit_role.external_id and config.audit_role.external_id.environment_variable:
            return "environment_variable"
        return "file" if config.audit_role.external_id else None

    def _external_id_identity(self, config: AwsOrganizationConfig) -> dict[str, str]:
        reference = config.audit_role.external_id
        if reference is None:
            return {}
        if reference.environment_variable:
            return {"external_id_reference_identity": reference.environment_variable}
        if reference.file is not None:
            return {"external_id_reference_identity": _canonical_file_reference(str(reference.file))}
        return {}


__all__ = ["OrganizationRequestFingerprint"]


_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:[\\/]")


def _canonical_file_reference(value: str) -> str:
    """Normalize configured path syntax without consulting the host filesystem."""
    windows_style = bool(_WINDOWS_DRIVE.match(value) or value.startswith(("\\\\", "//")))
    normalized = posixpath.normpath(value.replace("\\", "/"))
    return normalized.casefold() if windows_style else normalized
