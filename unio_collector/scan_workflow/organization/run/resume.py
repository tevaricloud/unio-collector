"""Verification of resumable parent-committed organization bundles."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from unio_collector.collector.bundle.checksums import build_sha256
from unio_collector.collector.bundle.validator import EvidenceBundleValidator

if TYPE_CHECKING:
    from pathlib import Path


class OrganizationBundleResumer:
    """Reuse only an existing checksum-matched and schema-valid account bundle."""

    def restore(self, saved: dict[str, Any], bundle_path: Path, *, resume: bool) -> str | None:
        """Normalize verified commit state without executing account or report work."""
        resumable_status = saved.get("status") in {"bundle_commit_pending", "bundle_committed", "completed", "degraded"}
        if not resume or not resumable_status or not bundle_path.exists():
            return None
        digest = build_sha256(bundle_path.read_bytes())
        validation = EvidenceBundleValidator().validate(bundle_path)
        if digest != saved.get("bundle_sha256") or not validation.passed:
            return None
        saved.update(
            {
                "bundle_state": "committed",
                "status": saved.get("status") if saved.get("status") in {"completed", "degraded"} else "bundle_committed",
            },
        )
        return digest
