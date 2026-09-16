from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.collector.analysis.contract_validator import AnalysisContractValidator
from unio_collector.collector.analysis.readiness_validator import (
    StrictAnalysisReadinessValidator,
)
from unio_collector.collector.bundle.schema import required_files_for_schema_version
from unio_collector.collector.evidence.scanner.boundary import (
    validate_scanner_analysis_boundary_summary,
)
from unio_collector.collector.evidence.scanner.payload import (
    ScannerEvidencePayloadValidator,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from zipfile import ZipFile

    from unio_collector.collector.protocol import EvidenceProtocol


class BundleMetadataFilesValidator:
    """Validate evidence-bundle metadata member files."""

    def __init__(
        self,
        read_json: Callable[[ZipFile, str, list[str]], dict[str, object]],
    ) -> None:
        """Create a validator with the caller's JSON error collector."""
        self._read_json = read_json

    def validate(
        self,
        archive: ZipFile,
        manifest: dict[str, object],
        errors: list[str],
        *,
        protocol: EvidenceProtocol | None = None,
    ) -> None:
        """Validate all metadata files tied to the manifest."""
        self._validate_analysis_contract_file(archive, manifest, errors)
        self._validate_bundle_schema_file(archive, manifest, errors)
        self._validate_collector_version_file(archive, manifest, errors)
        self._validate_account_scope_file(archive, manifest, errors)
        collection_summary = self._validate_collection_summary_file(
            archive,
            manifest,
            errors,
        )
        scanner_evidence_payload = ScannerEvidencePayloadValidator().validate(
            archive,
            manifest,
            errors,
            protocol=protocol,
        )
        StrictAnalysisReadinessValidator().validate(
            archive,
            manifest,
            collection_summary,
            scanner_evidence_payload,
            errors,
        )
        self._validate_signature_file(archive, manifest, errors)

    def _validate_analysis_contract_file(
        self,
        archive: ZipFile,
        manifest: dict[str, object],
        errors: list[str],
    ) -> None:
        AnalysisContractValidator().validate(archive, manifest, errors)

    def _validate_bundle_schema_file(
        self,
        archive: ZipFile,
        manifest: dict[str, object],
        errors: list[str],
    ) -> None:
        payload = self._read_json(archive, "bundle-schema.json", errors)
        if not payload:
            return
        schema_version = payload.get("bundle_schema_version")
        if schema_version != manifest.get("bundle_schema_version"):
            errors.append(
                "bundle-schema.json bundle_schema_version does not match manifest.json.",
            )
        if payload.get("path_format") != "posix":
            errors.append("bundle-schema.json path_format must be 'posix'.")
        if payload.get("encoding") != "utf-8":
            errors.append("bundle-schema.json encoding must be 'utf-8'.")
        required_files = payload.get("required_files")
        if not isinstance(required_files, list):
            errors.append("bundle-schema.json required_files must be a list.")
            return
        expected = set[str](
            required_files_for_schema_version(manifest.get("bundle_schema_version")),
        )
        actual = {item for item in required_files if isinstance(item, str)}
        if len(actual) != len(required_files):
            errors.append("bundle-schema.json required_files must contain unique strings.")
        if actual != expected:
            errors.append(
                "bundle-schema.json required_files do not match the supported schema.",
            )

    def _validate_collector_version_file(
        self,
        archive: ZipFile,
        manifest: dict[str, object],
        errors: list[str],
    ) -> None:
        payload = self._read_json(archive, "collector-version.json", errors)
        if not payload:
            return
        collector_version = payload.get("collector_version")
        if not isinstance(collector_version, str) or not collector_version:
            errors.append("collector-version.json collector_version must be a string.")
        elif collector_version != manifest.get("collector_version"):
            errors.append(
                "collector-version.json collector_version does not match manifest.json.",
            )
        package_version = payload.get("package_version")
        if package_version is not None and not isinstance(package_version, str):
            errors.append("collector-version.json package_version must be a string.")

    def _validate_account_scope_file(
        self,
        archive: ZipFile,
        manifest: dict[str, object],
        errors: list[str],
    ) -> None:
        payload = self._read_json(archive, "account-scope.json", errors)
        if not payload:
            return
        errors.extend(f"account-scope.json is missing {key}." for key in ("account_id", "partition", "regions", "scan_period") if key not in payload)
        if payload.get("account_id") != manifest.get("account_id"):
            errors.append("account-scope.json account_id does not match manifest.json.")
        if payload.get("partition") != manifest.get("partition"):
            errors.append("account-scope.json partition does not match manifest.json.")
        regions = payload.get("regions")
        manifest_regions = manifest.get("regions")
        if not isinstance(regions, list):
            errors.append("account-scope.json regions must be a list.")
        elif not isinstance(manifest_regions, list):
            errors.append("manifest.json regions must be a list.")
        elif any(not isinstance(region, str) for region in [*regions, *manifest_regions]):
            errors.append("account-scope.json and manifest.json regions must contain strings.")
        elif sorted(regions) != sorted(manifest_regions):
            errors.append("account-scope.json regions do not match manifest.json.")
        if not isinstance(payload.get("scan_period"), dict):
            errors.append("account-scope.json scan_period must be an object.")
        if (payload.get("region_scope") or {}) != (manifest.get("region_scope") or {}):
            errors.append(
                "account-scope.json region_scope does not match manifest.json.",
            )

    def _validate_collection_summary_file(
        self,
        archive: ZipFile,
        manifest: dict[str, object],
        errors: list[str],
    ) -> dict[str, object]:
        payload = self._read_json(archive, "collection-summary.json", errors)
        if not payload:
            return {}
        minimisation = payload.get("minimisation")
        if minimisation != manifest.get("redaction_or_minimisation"):
            errors.append(
                "collection-summary.json minimisation does not match manifest.json.",
            )
        limitations = payload.get("limitations")
        if not isinstance(limitations, list):
            errors.append("collection-summary.json limitations must be a list.")
        for key in (
            "scanner_count",
            "finding_count",
            "evidence_count",
            "api_call_count",
        ):
            value = payload.get(key)
            if type(value) is not int or value < 0:
                errors.append(
                    f"collection-summary.json {key} must be a non-negative integer.",
                )
        validate_scanner_analysis_boundary_summary(payload, errors)
        if (payload.get("region_scope") or {}) != (manifest.get("region_scope") or {}):
            errors.append(
                "collection-summary.json region_scope does not match manifest.json.",
            )
        return payload

    def _validate_signature_file(
        self,
        archive: ZipFile,
        manifest: dict[str, object],
        errors: list[str],
    ) -> None:
        payload = self._read_json(archive, "signature.json", errors)
        if not payload:
            return
        metadata_version = payload.get("metadata_version")
        if metadata_version is not None and metadata_version != manifest.get(
            "bundle_schema_version",
        ):
            errors.append(
                "signature.json metadata_version does not match manifest.json.",
            )
        status = payload.get("status")
        if status not in ("unsigned", "signed"):
            errors.append("signature.json status must be 'unsigned' or 'signed'.")
            return
        if payload.get("digest_algorithm") != "sha256":
            errors.append("signature.json digest_algorithm must be 'sha256'.")
        if payload.get("signed_payload") != "checksums.json":
            errors.append("signature.json signed_payload must be 'checksums.json'.")
        if status == "unsigned":
            self._validate_unsigned_signature_metadata(payload, errors)
            return
        self._validate_signed_signature_metadata(payload, errors)

    def _validate_unsigned_signature_metadata(
        self,
        payload: dict[str, object],
        errors: list[str],
    ) -> None:
        if payload.get("signature") is not None:
            errors.append(
                "signature.json unsigned bundles must not include a signature.",
            )
        errors.extend(
            f"signature.json unsigned bundles must not include {key}."
            for key in ("signature_algorithm", "key_id", "created_at")
            if payload.get(key) is not None
        )
        reason = payload.get("reason")
        if reason is not None and not isinstance(reason, str):
            errors.append("signature.json reason must be a string.")

    def _validate_signed_signature_metadata(
        self,
        payload: dict[str, object],
        errors: list[str],
    ) -> None:
        errors.extend(
            f"signature.json signed bundles require {key}."
            for key in ("signature", "signature_algorithm", "key_id", "created_at")
            if not isinstance(payload.get(key), str) or not payload.get(key)
        )
