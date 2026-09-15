from __future__ import annotations  # noqa: D100

import json
import re
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from unio_collector.privacy.constants import PROTECTED_EXPORT_RECEIPT_SCHEMA_VERSION
from unio_collector.privacy.content_hash import sha256_file

if TYPE_CHECKING:
    from unio_collector.privacy.prepared_artifact import PreparedArtifact
    from unio_collector.privacy.security_warning import SecurityWarning

SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
RECEIPT_STATUSES = {"complete", "complete_with_warnings"}


def default_receipt_path(bundle_path: Path) -> Path:
    """Return the deterministic adjacent receipt path for a protected ZIP."""
    return Path(f"{bundle_path}.receipt.json")


def build_export_receipt(
    *,
    protected_bundle_id: str,
    source_bundle_id: str,
    source_bundle_id_scheme: str,
    privacy_policy_version: str,
    profile_id: str,
    profile_version: str,
    token_scope: str,
    engagement_id: str,
    artifacts: tuple[PreparedArtifact, ...],
    warning_details: tuple[SecurityWarning, ...],
    created_at: datetime,
) -> dict[str, object]:
    """Build a non-secret completion receipt from fully staged artifacts."""
    return {
        "receipt_schema_version": PROTECTED_EXPORT_RECEIPT_SCHEMA_VERSION,
        "status": "complete_with_warnings" if warning_details else "complete",
        "protected_bundle_id": protected_bundle_id,
        "source_bundle_id": source_bundle_id,
        "source_bundle_id_scheme": source_bundle_id_scheme,
        "privacy_policy_version": privacy_policy_version,
        "profile_id": profile_id,
        "profile_version": profile_version,
        "token_scope": token_scope,
        "engagement_id": engagement_id,
        "validation": {"protected_bundle": "passed"},
        "leak_scan": {"status": "passed"},
        "artifacts": [
            {
                "role": artifact.artifact,
                "classification": "private" if artifact.private else "public",
                "sha256": artifact.content_hash,
            }
            for artifact in sorted(artifacts, key=lambda item: item.artifact)
        ],
        "warning_details": [warning.convert_to_dict() for warning in warning_details],
        "created_at": created_at.isoformat().replace("+00:00", "Z"),
    }


def encode_receipt(payload: dict[str, object]) -> bytes:
    """Encode a receipt deterministically for publication."""
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")


def validate_export_receipt(  # noqa: C901
    payload: dict[str, Any],
    *,
    bundle_path: Path,
    privacy: dict[str, Any],
    policy: dict[str, Any],
) -> tuple[str, ...]:
    """Validate a receipt against the protected bundle available to inspect."""
    errors: list[str] = []
    expected_fields = {
        "receipt_schema_version",
        "status",
        "protected_bundle_id",
        "source_bundle_id",
        "source_bundle_id_scheme",
        "privacy_policy_version",
        "profile_id",
        "profile_version",
        "token_scope",
        "engagement_id",
        "validation",
        "leak_scan",
        "artifacts",
        "warning_details",
        "created_at",
    }
    if set(payload) != expected_fields:
        errors.append("Completion receipt fields are invalid.")
    if payload.get("receipt_schema_version") != PROTECTED_EXPORT_RECEIPT_SCHEMA_VERSION:
        errors.append("Completion receipt schema version is not supported.")
    if payload.get("status") not in RECEIPT_STATUSES:
        errors.append("Completion receipt status is invalid.")
    expected = {
        "protected_bundle_id": privacy.get("protected_bundle_id"),
        "source_bundle_id": policy.get("bundle_id"),
        "source_bundle_id_scheme": policy.get("bundle_id_scheme"),
        "privacy_policy_version": privacy.get("privacy_policy_version"),
        "profile_id": privacy.get("profile_id"),
        "profile_version": privacy.get("profile_version"),
        "token_scope": privacy.get("token_scope"),
        "engagement_id": privacy.get("engagement_id"),
    }
    for field, expected_value in expected.items():
        value = payload.get(field)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"Completion receipt {field} is missing or invalid.")
        elif value != expected_value:
            errors.append(f"Completion receipt {field} does not match the protected bundle.")
    validation = payload.get("validation")
    if not isinstance(validation, dict) or validation.get("protected_bundle") != "passed":
        errors.append("Completion receipt does not record passing bundle validation.")
    leak_scan = payload.get("leak_scan")
    if not isinstance(leak_scan, dict) or leak_scan.get("status") != "passed":
        errors.append("Completion receipt does not record a passing leak scan.")
    artifacts = payload.get("artifacts")
    roles: set[str] = set()
    bundle_hash = None
    if not isinstance(artifacts, list):
        errors.append("Completion receipt artifacts must be an array.")
    else:
        for artifact in artifacts:
            if not isinstance(artifact, dict):
                errors.append("Completion receipt artifact entries must be objects.")
                continue
            if set(artifact) != {"role", "classification", "sha256"}:
                errors.append("Completion receipt artifact fields are invalid.")
                continue
            role = artifact.get("role")
            classification = artifact.get("classification")
            digest = artifact.get("sha256")
            if not isinstance(role, str) or not role.strip() or role in roles:
                errors.append("Completion receipt artifact roles must be non-empty and unique.")
                continue
            roles.add(role)
            if classification not in {"public", "private"}:
                errors.append(f"Completion receipt artifact {role} has an invalid classification.")
            if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
                errors.append(f"Completion receipt artifact {role} has an invalid SHA-256 hash.")
            if role == "protected_bundle":
                bundle_hash = digest
        if "identity_vault" not in roles or "protected_bundle" not in roles:
            errors.append("Completion receipt is missing a required artifact role.")
    if bundle_hash is not None and bundle_hash != sha256_file(bundle_path):
        errors.append("Completion receipt protected bundle hash does not match.")
    warnings = payload.get("warning_details")
    if not isinstance(warnings, list):
        errors.append("Completion receipt warning_details must be an array.")
    else:
        for warning in warnings:
            if not isinstance(warning, dict) or set(warning) != {"code", "category", "artifact", "message"}:
                errors.append("Completion receipt warning detail is invalid.")
                continue
            if any(not isinstance(warning.get(field), str) or not str(warning[field]).strip() for field in warning):
                errors.append("Completion receipt warning fields must be non-empty strings.")
    created_at = payload.get("created_at")
    if not isinstance(created_at, str) or not created_at.endswith("Z"):
        errors.append("Completion receipt creation timestamp is invalid.")
    else:
        try:
            datetime.fromisoformat(created_at.removesuffix("Z") + "+00:00")
        except ValueError:
            errors.append("Completion receipt creation timestamp is invalid.")
    return tuple(errors)
