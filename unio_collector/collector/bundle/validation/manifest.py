from __future__ import annotations  # noqa: D100

from unio_collector.collector.bundle.schema import (
    COLLECTION_MODE,
    MANIFEST_FIELDS,
    SUPPORTED_SCHEMA_VERSIONS,
)


class BundleManifestValidator:
    """Validate evidence-bundle manifest metadata."""

    def validate(
        self,
        manifest: dict[str, object],
        names: set[str],
        errors: list[str],
    ) -> None:
        """Validate manifest content against the supported bundle contract."""
        self._validate_manifest_fields(manifest, errors)
        self._validate_schema_and_collection(manifest, errors)
        self._validate_scope_fields(manifest, errors)
        self._validate_region_scope(manifest, errors)
        self._validate_service_lists(manifest, errors)
        self._validate_evidence_files(manifest, names, errors)
        self._validate_permission_limitations(manifest, errors)
        self._validate_minimisation(manifest, errors)
        count = manifest.get("permission_degradation_record_count")
        if count is not None and (type(count) is not int or count < 0):
            errors.append(
                "manifest.json permission_degradation_record_count must be a non-negative integer.",
            )

    def _validate_schema_and_collection(
        self,
        manifest: dict[str, object],
        errors: list[str],
    ) -> None:
        schema_version = manifest.get("bundle_schema_version")
        if not schema_version:
            errors.append("manifest.json is missing bundle_schema_version.")
        elif schema_version not in SUPPORTED_SCHEMA_VERSIONS:
            errors.append(
                f"Unsupported bundle schema version: {schema_version}. Supported: {', '.join(SUPPORTED_SCHEMA_VERSIONS)}.",
            )
        if not manifest.get("collector_version"):
            errors.append("manifest.json is missing collector_version.")
        if manifest.get("bundle_purpose") not in (None, "collector_evidence", "result_evidence"):
            errors.append("manifest.json bundle_purpose must be a supported collector or result evidence purpose.")
        if manifest.get("collection_mode") != COLLECTION_MODE:
            errors.append(
                f"manifest.json collection_mode must be {COLLECTION_MODE!r}.",
            )

    def _validate_evidence_files(
        self,
        manifest: dict[str, object],
        names: set[str],
        errors: list[str],
    ) -> None:
        evidence_files = manifest.get("evidence_files")
        if not isinstance(evidence_files, list):
            errors.append("manifest.json evidence_files must be a list.")
            evidence_files = []
        for item in evidence_files:
            if not isinstance(item, str):
                errors.append("manifest.json evidence_files entries must be strings.")
                continue
            if item not in names:
                errors.append(f"Manifest references missing evidence file: {item}")
        checksums = manifest.get("checksums")
        if not isinstance(checksums, dict) or not checksums:
            errors.append("manifest.json checksums must be a non-empty object.")

    def _validate_permission_limitations(
        self,
        manifest: dict[str, object],
        errors: list[str],
    ) -> None:
        limitations = manifest.get("permission_limitations", [])
        if not isinstance(limitations, list):
            errors.append("manifest.json permission_limitations must be a list.")
            return
        for index, item in enumerate(limitations):
            if not isinstance(item, dict):
                errors.append(
                    f"manifest.json permission_limitations[{index}] must be an object.",
                )
                continue
            if not item.get("type") or not item.get("reason"):
                errors.append(
                    f"manifest.json permission limitations require type and reason at index {index}.",
                )

    def _validate_manifest_fields(
        self,
        manifest: dict[str, object],
        errors: list[str],
    ) -> None:
        allowed = set[str](MANIFEST_FIELDS)
        errors.extend(f"manifest.json contains unsupported field: {key}." for key in sorted(set(manifest) - allowed))

    def _validate_scope_fields(
        self,
        manifest: dict[str, object],
        errors: list[str],
    ) -> None:
        errors.extend(f"manifest.json is missing {key}." for key in ("account_id", "partition", "regions") if key not in manifest)
        if "account_id" in manifest and not isinstance(manifest.get("account_id"), str):
            errors.append("manifest.json account_id must be a string.")
        if "partition" in manifest and not isinstance(manifest.get("partition"), str):
            errors.append("manifest.json partition must be a string.")
        regions = manifest.get("regions")
        if not isinstance(regions, list):
            errors.append("manifest.json regions must be a list.")
            return
        for index, region in enumerate(regions):
            if not isinstance(region, str):
                errors.append(f"manifest.json regions[{index}] must be a string.")

    def _validate_service_lists(
        self,
        manifest: dict[str, object],
        errors: list[str],
    ) -> None:
        for key in (
            "services_attempted",
            "services_collected",
            "services_unavailable",
        ):
            value = manifest.get(key)
            if not isinstance(value, list):
                errors.append(f"manifest.json {key} must be a list.")
                continue
            for index, item in enumerate(value):
                if not isinstance(item, str):
                    errors.append(f"manifest.json {key}[{index}] must be a string.")

    def _validate_region_scope(
        self,
        manifest: dict[str, object],
        errors: list[str],
    ) -> None:
        scope = manifest.get("region_scope")
        if scope is None:
            return
        if not isinstance(scope, dict):
            errors.append("manifest.json region_scope must be an object.")
            return
        version = scope.get("scope_version")
        if version not in (None, "2026-07", "2026-08"):
            errors.append("manifest.json region_scope contains an unsupported scope_version.")
            return
        if version != "2026-08":
            return
        self._validate_current_scope(scope, errors)

    def _validate_current_scope(self, scope: dict[str, object], errors: list[str]) -> None:
        required = (
            "selection_mode",
            "regions_from_billing_requested",
            "regions_from_billing_effective",
            "billing_active_regions",
            "normalized_candidate_regions",
            "material_billing_candidate_regions",
            "residual_billing_candidate_regions",
            "explicit_requested_regions",
            "selected_regional_targets",
            "excluded_regions",
            "global_scope",
            "control_sources",
        )
        errors.extend(f"manifest.json region_scope is missing {key}." for key in required if key not in scope)
        for key in (
            "billing_active_regions",
            "normalized_candidate_regions",
            "material_billing_candidate_regions",
            "residual_billing_candidate_regions",
            "explicit_requested_regions",
            "selected_regional_targets",
        ):
            value = scope.get(key)
            if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                errors.append(f"manifest.json region_scope.{key} must be a string list.")
                continue
            if any(item in {"global", "aws-global"} for item in value):
                errors.append(
                    f"manifest.json region_scope.{key} must not contain the global pseudo-scope.",
                )
        exclusions = scope.get("excluded_regions")
        if isinstance(exclusions, list):
            for index, item in enumerate(exclusions):
                if not isinstance(item, dict) or not all(item.get(key) for key in ("region_name", "stage", "reason")):
                    errors.append(
                        f"manifest.json region_scope exclusions require region_name, stage, and reason at index {index}.",
                    )

    def _validate_minimisation(
        self,
        manifest: dict[str, object],
        errors: list[str],
    ) -> None:
        value = manifest.get("redaction_or_minimisation")
        if not isinstance(value, dict):
            errors.append("manifest.json redaction_or_minimisation must be an object.")
            return
        enabled = value.get("enabled")
        if not isinstance(enabled, bool):
            errors.append(
                "manifest.json redaction_or_minimisation.enabled must be a boolean.",
            )
        mode = value.get("mode")
        if not isinstance(mode, str) or not mode:
            errors.append(
                "manifest.json redaction_or_minimisation.mode must be a non-empty string.",
            )
