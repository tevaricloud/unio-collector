from __future__ import annotations  # noqa: D100

import json
from typing import TYPE_CHECKING
from zipfile import ZipFile

from unio_collector.collector.bundle.validator import EvidenceBundleValidator
from unio_collector.privacy.constants import (
    PRIVACY_LEAK_SCAN_FILE,
    PRIVACY_POLICY_FILE,
    PRIVACY_PREVIEW_FILE,
)
from unio_collector.privacy.inspect_result import PrivacyInspectResult
from unio_collector.privacy.receipt import default_receipt_path, validate_export_receipt

if TYPE_CHECKING:
    from pathlib import Path


class ProtectedBundleInspector:
    """Inspect protected evidence bundles without vault access."""

    def inspect(
        self,
        path: Path,
        *,
        receipt_path: Path | None = None,
    ) -> PrivacyInspectResult:
        """Validate and summarize a protected bundle."""
        validation = EvidenceBundleValidator().validate(path)
        summary: dict[str, object] = {
            "protected": False,
            "privacy_protection": {},
            "archive_inventory": {},
        }
        errors = tuple(validation.errors)
        if not validation.passed:
            return PrivacyInspectResult(path=path, protected=False, validation_passed=False, summary=summary, errors=errors)
        try:
            with ZipFile(path, "r") as archive:
                names = sorted(archive.namelist())
                manifest = json.loads(archive.read("manifest.json").decode("utf-8"))
                privacy = manifest.get("privacy_protection")
                policy = json.loads(archive.read(PRIVACY_POLICY_FILE).decode("utf-8"))
                summary = {
                    "protected": bool(
                        isinstance(privacy, dict) and privacy.get("enabled") is True,
                    ),
                    "privacy_protection": privacy if isinstance(privacy, dict) else {},
                    "archive_inventory": {
                        "file_count": len(names),
                        "privacy_files": [name for name in names if name.startswith("privacy/")],
                    },
                }
                if PRIVACY_PREVIEW_FILE in names:
                    summary["preview"] = json.loads(
                        archive.read(PRIVACY_PREVIEW_FILE).decode("utf-8"),
                    )
                if PRIVACY_LEAK_SCAN_FILE in names:
                    summary["leak_scan"] = json.loads(
                        archive.read(PRIVACY_LEAK_SCAN_FILE).decode("utf-8"),
                    )
                explicit_receipt = receipt_path is not None
                candidate_receipt = receipt_path or default_receipt_path(path)
                receipt_required = bool(
                    isinstance(privacy, dict) and privacy.get("export_receipt_required") is True,
                )
                summary["receipt"] = {
                    "available": candidate_receipt.exists(),
                    "required": receipt_required,
                    "verified": False,
                }
                if candidate_receipt.exists():
                    receipt_payload = json.loads(candidate_receipt.read_text(encoding="utf-8"))
                    if not isinstance(receipt_payload, dict):
                        errors = (*errors, "Completion receipt must be a JSON object.")
                    elif not isinstance(policy, dict):
                        errors = (*errors, "Protected bundle privacy policy must be a JSON object.")
                    else:
                        receipt_errors = validate_export_receipt(
                            receipt_payload,
                            bundle_path=path,
                            privacy=privacy if isinstance(privacy, dict) else {},
                            policy=policy,
                        )
                        errors = (*errors, *receipt_errors)
                        if not receipt_errors:
                            summary["receipt"] = {
                                "available": True,
                                "required": receipt_required,
                                "verified": True,
                                "receipt": receipt_payload,
                            }
                elif receipt_required or explicit_receipt:
                    errors = (*errors, "Required protected export completion receipt is missing.")
        except Exception as exc:  # noqa: BLE001
            errors = (*errors, f"Could not inspect protected bundle metadata: {exc}")
        return PrivacyInspectResult(
            path=path,
            protected=bool(summary.get("protected")),
            validation_passed=validation.passed and not errors,
            summary=summary,
            errors=errors,
        )
