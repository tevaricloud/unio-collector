from __future__ import annotations  # noqa: D100

import json
from typing import TYPE_CHECKING, Any

from unio_collector.privacy.constants import RESTORATION_COMPLETION_SCHEMA_VERSION

if TYPE_CHECKING:
    from datetime import datetime

    from unio_collector.privacy.prepared_artifact import PreparedArtifact
    from unio_collector.privacy.security_warning import SecurityWarning


def build_restoration_completion(
    *,
    package: dict[str, Any],
    artifacts: tuple[PreparedArtifact, ...],
    warning_details: tuple[SecurityWarning, ...],
    created_at: datetime,
) -> dict[str, object]:
    """Build a non-secret local completion marker for restored outputs."""
    privacy = package.get("privacy")
    privacy = privacy if isinstance(privacy, dict) else {}
    return {
        "completion_schema_version": RESTORATION_COMPLETION_SCHEMA_VERSION,
        "status": "complete_with_warnings" if warning_details else "complete",
        "package_schema_version": package.get("package_schema_version"),
        "protected_bundle_id": privacy.get("protected_bundle_id"),
        "engagement_id": privacy.get("engagement_id"),
        "token_scope": privacy.get("token_scope"),
        "artifacts": [{"role": artifact.artifact, "sha256": artifact.content_hash} for artifact in sorted(artifacts, key=lambda item: item.artifact)],
        "warning_details": [warning.convert_to_dict() for warning in warning_details],
        "created_at": created_at.isoformat().replace("+00:00", "Z"),
    }


def encode_restoration_completion(payload: dict[str, object]) -> bytes:
    """Encode a restoration marker deterministically."""
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
