from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING
from zipfile import BadZipFile, ZipFile

from unio_collector.collector.bundle.checksums import build_sha256
from unio_collector.collector.bundle.encoding import load_json, load_json_object
from unio_collector.collector.bundle.schema import (
    required_files_for_schema_version,
)
from unio_collector.collector.bundle.validation.error import (
    EvidenceBundleValidationError,
)
from unio_collector.collector.bundle.validation.manifest import BundleManifestValidator
from unio_collector.collector.bundle.validation.metadata_files import (
    BundleMetadataFilesValidator,
)
from unio_collector.collector.bundle.validation.permission_records import (
    validate_permission_degradation_records,
)
from unio_collector.collector.bundle.validation.protocol import BundleProtocolValidator
from unio_collector.collector.bundle.validation.result import BundleValidationResult
from unio_collector.collector.package.raw_zip import validate_raw_zip_paths
from unio_collector.pricing.replay.context import (
    PRICING_CONTEXT_FILE,
    PricingReplayContext,
)
from unio_collector.privacy.metadata_validation import (
    ProtectedBundlePrivacyMetadataValidator,
)

if TYPE_CHECKING:
    from pathlib import Path
    from zipfile import ZipInfo

MAX_BUNDLE_TOTAL_UNCOMPRESSED_BYTES = 250 * 1024 * 1024
MAX_BUNDLE_ENTRY_UNCOMPRESSED_BYTES = 50 * 1024 * 1024
MAX_BUNDLE_FILE_COUNT = 1000


class EvidenceBundleValidator:
    """Validate evidence-bundle structure, paths, metadata, and checksums."""

    def validate(self, path: Path) -> BundleValidationResult:
        """Return all validation errors for an evidence bundle path."""
        errors: list[str] = []
        try:
            with ZipFile(path, "r") as archive:
                infos = archive.infolist()
                self._validate_zip_limits(infos, errors)
                if errors:
                    return BundleValidationResult(
                        path=path,
                        passed=False,
                        errors=errors,
                    )
                names = {info.filename for info in infos}
                validate_raw_zip_paths(path, errors, infos, archive)
                if errors:
                    return BundleValidationResult(
                        path=path,
                        passed=False,
                        errors=errors,
                    )
                manifest = self._read_json(archive, "manifest.json", errors)
                protocol_errors: list[str] = []
                protocol = BundleProtocolValidator().validate(archive, manifest, protocol_errors)
                errors.extend(protocol_errors)
                self._validate_required_files(names, errors, manifest)
                validate_permission_degradation_records(
                    archive,
                    names,
                    errors,
                    self._read_json,
                    manifest=manifest,
                )
                checksums = self._read_json(archive, "checksums.json", errors)
                if isinstance(manifest, dict):
                    BundleManifestValidator().validate(manifest, names, errors)

                    if not protocol_errors and protocol is not None:
                        BundleMetadataFilesValidator(self._read_json).validate(archive, manifest, errors, protocol=protocol)
                        ProtectedBundlePrivacyMetadataValidator().validate(archive, names, manifest, errors, protocol=protocol)
                if isinstance(checksums, dict):
                    self._validate_checksums(archive, checksums, manifest, errors)
                self._validate_json_files(archive, names, errors)
                self._validate_pricing_context(archive, names, errors)
        except BadZipFile:
            errors.append("Bundle is not a readable ZIP file.")
        except FileNotFoundError:
            errors.append(f"Bundle does not exist: {path}")
        return BundleValidationResult(path=path, passed=not errors, errors=errors)

    def validate_or_raise(self, path: Path) -> None:
        """Raise an evidence-bundle validation error when validation fails."""
        result = self.validate(path)
        if not result.passed:
            raise EvidenceBundleValidationError("; ".join(result.errors))

    def _validate_zip_limits(
        self,
        infos: list[ZipInfo],
        errors: list[str],
    ) -> None:
        if len(infos) > MAX_BUNDLE_FILE_COUNT:
            errors.append(
                f"Bundle contains {len(infos)} ZIP entries; maximum allowed is {MAX_BUNDLE_FILE_COUNT}.",
            )
        total_size = sum(info.file_size for info in infos)
        if total_size > MAX_BUNDLE_TOTAL_UNCOMPRESSED_BYTES:
            errors.append(
                f"Bundle uncompressed size is {total_size} bytes; maximum allowed is {MAX_BUNDLE_TOTAL_UNCOMPRESSED_BYTES} bytes.",
            )
        for info in sorted(infos, key=lambda item: item.filename):
            if info.file_size <= MAX_BUNDLE_ENTRY_UNCOMPRESSED_BYTES:
                continue
            errors.append(
                f"Bundle entry {info.filename} is {info.file_size} bytes; maximum allowed per entry is {MAX_BUNDLE_ENTRY_UNCOMPRESSED_BYTES} bytes.",
            )

    def _validate_required_files(
        self,
        names: set[str],
        errors: list[str],
        manifest: object,
    ) -> None:
        schema_version = manifest.get("bundle_schema_version") if isinstance(manifest, dict) else None
        required_files = set[str](required_files_for_schema_version(schema_version))
        missing = sorted(required_files - names)
        errors.extend(f"Missing required bundle file: {name}" for name in missing)

    def _validate_checksums(
        self,
        archive: ZipFile,
        checksums_payload: dict[str, object],
        manifest: object,
        errors: list[str],
    ) -> None:
        if checksums_payload.get("algorithm") != "sha256":
            errors.append("checksums.json algorithm must be 'sha256'.")
        checksums = checksums_payload.get("checksums")
        if not isinstance(checksums, dict) or not checksums:
            errors.append("checksums.json checksums must be a non-empty object.")
            return
        expected_members = {info.filename for info in archive.infolist() if not info.is_dir()} - {"manifest.json", "checksums.json"}
        if set(checksums) != expected_members:
            errors.append("checksums.json must cover every retained bundle member except manifest.json and checksums.json.")
        manifest_checksums = manifest.get("checksums") if isinstance(manifest, dict) else None
        if isinstance(manifest_checksums, dict) and manifest_checksums != checksums:
            errors.append("manifest.json checksums do not match checksums.json.")
        for name, expected in sorted(checksums.items()):
            if not isinstance(name, str) or not isinstance(expected, str):
                errors.append("checksums.json entries must map file names to strings.")
                continue
            try:
                actual = build_sha256(archive.read(name))
            except KeyError:
                errors.append(f"Checksum references missing file: {name}")
                continue
            if actual != expected:
                errors.append(f"Checksum mismatch for {name}.")

    def _validate_json_files(
        self,
        archive: ZipFile,
        names: set[str],
        errors: list[str],
    ) -> None:
        for name in sorted(names):
            if not name.endswith(".json"):
                continue
            try:
                load_json(archive.read(name).decode("utf-8"))
            except Exception:  # noqa: BLE001
                errors.append(f"{name} is invalid JSON.")
        for name in sorted(names):
            if not name.endswith(".jsonl"):
                continue
            line_number = 0
            try:
                for _line_number, line in enumerate(
                    archive.read(name).decode("utf-8").splitlines(),
                    start=1,
                ):
                    line_number = _line_number
                    if line.strip():
                        load_json(line)
            except Exception:  # noqa: BLE001
                errors.append(f"{name}:{line_number} is invalid JSONL.")

    def _read_json(
        self,
        archive: ZipFile,
        name: str,
        errors: list[str],
    ) -> dict[str, object]:
        try:
            return load_json_object(archive.read(name).decode("utf-8"))
        except KeyError:
            return {}
        except Exception:  # noqa: BLE001
            errors.append(f"{name} must contain a valid non-empty JSON object.")
            return {}

    def _validate_pricing_context(
        self,
        archive: ZipFile,
        names: set[str],
        errors: list[str],
    ) -> None:
        if PRICING_CONTEXT_FILE not in names:
            return
        payload = self._read_json(archive, PRICING_CONTEXT_FILE, errors)
        try:
            PricingReplayContext.model_validate(payload)
        except ValueError as exc:
            errors.append(f"{PRICING_CONTEXT_FILE} is invalid: {exc}")
