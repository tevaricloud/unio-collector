"""Cross-check repeated factual privacy metadata without vault access."""

from __future__ import annotations

from typing import Any

from unio_collector.privacy.constants import PRIVACY_CLASSIFICATION_FILE, PRIVACY_LEAK_SCAN_FILE, PRIVACY_POLICY_FILE, PRIVACY_PREVIEW_FILE
from unio_collector.privacy.leak.scan import TEXT_SUFFIXES


class ProtectedMetadataConsistency:
    """Reject contradictory counts and positive leak-scan declarations."""

    def validate(self, privacy: dict[str, Any], metadata: dict[str, dict[str, Any]], names: set[str], errors: list[str]) -> None:
        """Compare present legacy-safe fields and required scan evidence."""
        classification = metadata[PRIVACY_CLASSIFICATION_FILE]
        preview = metadata[PRIVACY_PREVIEW_FILE]
        policy = metadata[PRIVACY_POLICY_FILE]
        leak = metadata[PRIVACY_LEAK_SCAN_FILE]
        errors.extend(
            "Privacy vault revisions must be positive integers."
            for payload in (privacy, policy, preview)
            if "vault_revision" in payload and (type(payload["vault_revision"]) is not int or payload["vault_revision"] < 1)
        )
        for source_key, preview_key in (("preserved", "preserved_count"), ("removed", "removed_count")):
            if preview_key in preview and (type(preview[preview_key]) is not int or preview[preview_key] != classification.get(source_key)):
                errors.append("Privacy preview counts contradict classification metadata.")
        self._validate_unclassified(classification, preview, privacy, policy, errors)
        self._compare_map(classification, "tokenised", preview, "tokenised_categories", errors)
        for payload in (privacy, policy, preview):
            self._compare_map(classification, "resolver_decisions", payload, "resolver_decisions", errors)
            self._compare_map(classification, "applied_transformations", payload, "actual_applied_transformations", errors)
        self._validate_scan(leak, preview, names, errors)

    def _validate_unclassified(
        self, classification: dict[str, Any], preview: dict[str, Any], privacy: dict[str, Any], policy: dict[str, Any], errors: list[str]
    ) -> None:
        unclassified = classification.get("unclassified")
        if isinstance(unclassified, list):
            if any(not isinstance(value, str) for value in unclassified):
                errors.append("Privacy unclassified paths must be strings.")
            expected = len(unclassified)
            if preview.get("unclassified_field_count") != expected:
                errors.append("Privacy preview unclassified count contradicts classification metadata.")
            if "unclassified_fields" in preview and preview["unclassified_fields"] != unclassified:
                errors.append("Privacy preview unclassified paths contradict classification metadata.")
            for payload in (privacy, policy):
                if "coverage_gate" in payload:
                    coverage = payload["coverage_gate"]
                    if (
                        not isinstance(coverage, dict)
                        or type(coverage.get("unclassified_field_count")) is not int
                        or coverage["unclassified_field_count"] != expected
                    ):
                        errors.append("Privacy coverage count contradicts classification metadata.")

    def _validate_scan(self, leak: dict[str, Any], preview: dict[str, Any], names: set[str], errors: list[str]) -> None:
        if not isinstance(leak.get("findings"), list) or leak["findings"]:
            errors.append("Passing privacy leak scan must contain an empty findings list.")
        expected_scanned = sum(name.lower().endswith(TEXT_SUFFIXES) for name in names)
        if type(leak.get("files_scanned")) is not int or leak["files_scanned"] != expected_scanned:
            errors.append("Privacy leak scan file count does not cover the archive's text members.")
        if "leak_scan" in preview:
            nested = preview["leak_scan"]
            if not isinstance(nested, dict) or nested.get("passed") is not True or type(nested.get("files_scanned")) is not int or nested != leak:
                errors.append("Privacy preview leak scan contradicts final scan metadata.")

    def _compare_map(self, left: dict[str, Any], left_key: str, right: dict[str, Any], right_key: str, errors: list[str]) -> None:
        for payload, key in ((left, left_key), (right, right_key)):
            if key in payload:
                value = payload[key]
                if not isinstance(value, dict) or any(not isinstance(name, str) or type(count) is not int or count < 0 for name, count in value.items()):
                    errors.append("Privacy aggregate counters must be non-negative integers.")
        if left_key in left and right_key in right and left[left_key] != right[right_key]:
            errors.append("Repeated privacy aggregate counters contradict classification metadata.")
