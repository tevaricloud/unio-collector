from __future__ import annotations  # noqa: D100

# ruff: noqa: EM101, EM102, TRY003, TRY301
import json
import uuid
from dataclasses import replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from zipfile import ZipFile

from unio_collector.collector.bundle.checksums import build_checksums
from unio_collector.collector.bundle.encoding import dump_json, dump_jsonl
from unio_collector.collector.bundle.validator import EvidenceBundleValidator
from unio_collector.privacy.archive_scan import scan_provisional_archive
from unio_collector.privacy.artifact_transaction import ArtifactTransaction
from unio_collector.privacy.constants import (
    PRIVACY_BUNDLE_FILES,
    PRIVACY_CLASSIFICATION_FILE,
    PRIVACY_LEAK_SCAN_FILE,
    PRIVACY_POLICY_FILE,
    PRIVACY_POLICY_VERSION,
    PRIVACY_PREVIEW_FILE,
    PRIVACY_TOKEN_METADATA_FILE,
    PROTECTED_BUNDLE_SCHEMA_VERSION,
    PROTECTED_EXPORT_RECEIPT_SCHEMA_VERSION,
    TOKEN_FORMAT_VERSION,
)
from unio_collector.privacy.inspect_result import PrivacyInspectResult
from unio_collector.privacy.inspector import ProtectedBundleInspector
from unio_collector.privacy.known_originals import collect_known_original_values
from unio_collector.privacy.lifecycle_verifier import ProtectedExportLifecycleVerifier
from unio_collector.privacy.options import PrivacyProtectOptions
from unio_collector.privacy.preview import build_privacy_preview
from unio_collector.privacy.profiles import PrivacyProfile, load_privacy_profile
from unio_collector.privacy.protect_result import PrivacyProtectResult
from unio_collector.privacy.public_writer import PublicArtifactWriter
from unio_collector.privacy.publication_preparer import ProtectionArtifactPreparer
from unio_collector.privacy.receipt import (
    build_export_receipt,
    default_receipt_path,
    encode_receipt,
)
from unio_collector.privacy.registry import is_supported_json_path
from unio_collector.privacy.schema_versioning import replace_schema_versions
from unio_collector.privacy.security_warning import SecurityWarning, warning_messages
from unio_collector.privacy.source_identity import derive_source_bundle_identity
from unio_collector.privacy.state_factory import ProtectionStateFactory
from unio_collector.privacy.strict_verifier import StrictTransformationVerifier
from unio_collector.privacy.transaction_coordinator import ArtifactTransactionCoordinator
from unio_collector.privacy.transform import PrivacyTransformer
from unio_collector.privacy.vault_public_metadata import build_vault_public_metadata

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from unio_collector.privacy.prepared_artifact import PreparedArtifact
    from unio_collector.privacy.protection_state import ProtectionState

MINIMUM_KNOWN_ORIGINAL_VALUE_LENGTH = 4

__all__ = [
    "PrivacyInspectResult",
    "PrivacyProtectOptions",
    "PrivacyProtectResult",
    "ProtectedBundleInspector",
    "ProtectedBundleProtector",
]


class ProtectedBundleProtector:
    """Create protected evidence bundles without report/analyzer imports."""

    def __init__(self, *, clock: Callable[[], datetime] | None = None) -> None:
        """Create a protector with an injectable receipt clock."""
        self._clock = clock or (lambda: datetime.now(UTC))

    def protect(self, options: PrivacyProtectOptions) -> PrivacyProtectResult:  # noqa: C901
        """Protect a collector evidence bundle and write a private vault."""
        if options.in_place_vault_update and not options.overwrite:
            options = replace(options, overwrite=True)
        if not options.acknowledge_vault_loss_risk:
            message = (
                "Protected export requires acknowledgement that losing the client-held vault, passphrase, or recovery material may make restoration impossible."
            )
            raise ValueError(
                message,
            )
        receipt_path = options.receipt_path or default_receipt_path(options.output_path)
        targets = [options.output_path, options.vault_path, receipt_path]
        if options.recovery_key_path is not None:
            targets.append(options.recovery_key_path)
        if options.preview_output_path is not None:
            targets.append(options.preview_output_path)
        coordinator = ArtifactTransactionCoordinator(
            tuple(targets),
            overwrite=options.overwrite,
        )
        coordinator.validate_destinations()
        EvidenceBundleValidator().validate_or_raise(options.bundle_path)
        profile = load_privacy_profile(
            options.profile_id,
            token_scope=options.token_scope,
            allow_unknown_fields=options.allow_unknown_fields,
        )
        protected_bundle_id = str(uuid.uuid4())
        source_identity = derive_source_bundle_identity(options.bundle_path)
        ProtectionStateFactory().validate_paths(options)
        state = self._build_state(
            options,
            profile,
            source_bundle_id=source_identity.value,
            protected_bundle_id=protected_bundle_id,
        )
        files, source_manifest = self._read_and_transform_files(
            options.bundle_path,
            state,
        )
        StrictTransformationVerifier().verify(files, profile)
        if state.classification.prohibited_paths:
            details = "; ".join(state.classification.prohibited_paths[:20])
            raise ValueError(
                f"Protected export failed because prohibited privacy-registry fields were encountered: {details}",
            )
        if state.classification.unclassified and not profile.preserve_unknown_fields:
            details = "; ".join(state.classification.unclassified[:20])
            raise ValueError(f"Protected export failed because unclassified fields were encountered: {details}")
        self._add_privacy_files(
            files,
            options=options,
            state=state,
            source_manifest=source_manifest,
            bundle_id=source_identity.value,
            bundle_id_scheme=source_identity.scheme,
            protected_bundle_id=protected_bundle_id,
            leak_scan={"passed": False, "files_scanned": 0, "findings": []},
        )
        self._rewrite_checksums_and_manifest(files)
        final_leak_scan = scan_provisional_archive(
            files,
            known_original_values=collect_known_original_values(
                state.token_service,
                minimum_length=MINIMUM_KNOWN_ORIGINAL_VALUE_LENGTH,
            ),
        )
        self._add_privacy_files(
            files,
            options=options,
            state=state,
            source_manifest=source_manifest,
            bundle_id=source_identity.value,
            bundle_id_scheme=source_identity.scheme,
            protected_bundle_id=protected_bundle_id,
            leak_scan=final_leak_scan,
        )
        artifact_preparer = ProtectionArtifactPreparer()
        staged: list[PreparedArtifact] = []
        with coordinator:
            try:
                private_artifacts, private_warnings = artifact_preparer.prepare_private_artifacts(
                    options,
                    state=state,
                    source_identity=source_identity,
                    protected_bundle_id=protected_bundle_id,
                    transaction_id=coordinator.transaction_id,
                )
                staged.extend(private_artifacts)
                warning_details = (*options.warning_details, *private_warnings)
                compatibility_warnings = (*state.warnings, *warning_messages(warning_details))
                self._add_privacy_files(
                    files,
                    options=options,
                    state=state,
                    source_manifest=source_manifest,
                    bundle_id=source_identity.value,
                    bundle_id_scheme=source_identity.scheme,
                    protected_bundle_id=protected_bundle_id,
                    leak_scan=final_leak_scan,
                    warning_details=warning_details,
                    warnings=compatibility_warnings,
                )
                self._rewrite_checksums_and_manifest(files)
                preview = json.loads(files[PRIVACY_PREVIEW_FILE].decode("utf-8"))
                if not isinstance(preview, dict):
                    raise ValueError("Generated privacy preview must be an object.")
                preview_artifact = None
                if options.preview_output_path is not None:
                    preview_artifact = PublicArtifactWriter().prepare(
                        options.preview_output_path,
                        json.dumps(preview, indent=2, sort_keys=True).encode("utf-8") + b"\n",
                        overwrite=options.overwrite,
                        artifact="privacy_preview",
                        transaction_id=coordinator.transaction_id,
                    )
                    staged.append(preview_artifact)
                archive_artifact = artifact_preparer.prepare_protected_archive(
                    options,
                    files,
                    transaction_id=coordinator.transaction_id,
                )
                staged.append(archive_artifact)
                vault_artifact = next(item for item in private_artifacts if item.artifact == "identity_vault")
                recovery_artifact = next(
                    (item for item in private_artifacts if item.artifact == "recovery_key"),
                    None,
                )
                ProtectedExportLifecycleVerifier().verify(
                    archive_artifact=archive_artifact,
                    vault_artifact=vault_artifact,
                    recovery_artifact=recovery_artifact,
                    passphrase=options.passphrase,
                    expected_vault_plaintext=state.vault_plaintext(),
                    external_preview=preview if preview_artifact is not None else None,
                    known_original_values=collect_known_original_values(
                        state.token_service,
                        minimum_length=MINIMUM_KNOWN_ORIGINAL_VALUE_LENGTH,
                    ),
                    existing_recovery_key=state.vault_context.recovery_key,
                )
                published_artifacts = [*private_artifacts]
                if preview_artifact is not None:
                    published_artifacts.append(preview_artifact)
                published_artifacts.append(archive_artifact)
                published_set = tuple(published_artifacts)
                receipt = build_export_receipt(
                    protected_bundle_id=protected_bundle_id,
                    source_bundle_id=source_identity.value,
                    source_bundle_id_scheme=source_identity.scheme,
                    privacy_policy_version=PRIVACY_POLICY_VERSION,
                    profile_id=state.profile.profile_id,
                    profile_version=state.profile.version,
                    token_scope=options.token_scope,
                    engagement_id=options.engagement_id,
                    artifacts=published_set,
                    warning_details=warning_details,
                    created_at=self._clock(),
                )
                receipt_artifact = PublicArtifactWriter().prepare(
                    receipt_path,
                    encode_receipt(receipt),
                    overwrite=options.overwrite,
                    artifact="completion_receipt",
                    transaction_id=coordinator.transaction_id,
                )
                staged.append(receipt_artifact)
                transaction = ArtifactTransaction((*published_set, receipt_artifact))
                transaction.commit()
            except BaseException:
                for artifact in staged:
                    artifact.cleanup()
                raise
        return PrivacyProtectResult(
            output_path=options.output_path,
            vault_path=options.vault_path,
            recovery_key_path=options.recovery_key_path,
            preview_output_path=options.preview_output_path,
            receipt_path=receipt_path,
            preview=preview,
            warnings=compatibility_warnings,
            warning_details=warning_details,
        )

    def _build_state(
        self,
        options: PrivacyProtectOptions,
        profile: PrivacyProfile,
        *,
        source_bundle_id: str,
        protected_bundle_id: str,
    ) -> ProtectionState:
        return ProtectionStateFactory().build(
            options,
            profile,
            source_bundle_id=source_bundle_id,
            protected_bundle_id=protected_bundle_id,
        )

    def _read_and_transform_files(
        self,
        bundle_path: Path,
        state: ProtectionState,
    ) -> tuple[dict[str, bytes], dict[str, Any]]:
        files: dict[str, bytes] = {}
        source_manifest: dict[str, Any] = {}
        transformer = PrivacyTransformer(
            token_service=state.token_service,
            profile=state.profile,
            allow_unknown_fields=state.profile.preserve_unknown_fields,
            summary=state.classification,
        )
        with ZipFile(bundle_path, "r") as archive:
            for name in sorted(archive.namelist()):
                data = archive.read(name)
                if name == "manifest.json":
                    source_manifest = json.loads(data.decode("utf-8"))
                if name.endswith(".json") and is_supported_json_path(name):
                    payload = json.loads(data.decode("utf-8"))
                    files[name] = dump_json(transformer.transform(payload, file_name=name))
                elif name.endswith(".jsonl") and is_supported_json_path(name):
                    records = [transformer.transform(json.loads(line), file_name=name) for line in data.decode("utf-8").splitlines() if line.strip()]
                    files[name] = dump_jsonl(records)
                elif name.endswith((".json", ".jsonl")) and not name.startswith("privacy/"):
                    state.classification.unclassified.append(name)
                    files[name] = data
                else:
                    if name and not name.endswith("/"):
                        state.classification.unclassified.append(name)
                    files[name] = data
        return files, source_manifest

    def _add_privacy_files(
        self,
        files: dict[str, bytes],
        *,
        options: PrivacyProtectOptions,
        state: ProtectionState,
        source_manifest: dict[str, Any],
        bundle_id: str,
        bundle_id_scheme: str,
        protected_bundle_id: str,
        leak_scan: dict[str, object],
        warnings: tuple[str, ...] | None = None,
        warning_details: tuple[SecurityWarning, ...] = (),
    ) -> None:
        preview = build_privacy_preview(
            options=options,
            state=state,
            source_manifest=source_manifest,
            source_bundle_id=bundle_id,
            source_bundle_id_scheme=bundle_id_scheme,
            protected_bundle_id=protected_bundle_id,
            leak_scan=leak_scan,
            warnings=warnings or tuple(state.warnings),
            warning_details=warning_details,
        )
        files[PRIVACY_POLICY_FILE] = dump_json(
            {
                "policy_version": PRIVACY_POLICY_VERSION,
                "profile": state.profile.convert_to_dict(),
                "token_format_version": TOKEN_FORMAT_VERSION,
                "token_scope": options.token_scope,
                "engagement_id": options.engagement_id,
                **build_vault_public_metadata(state),
                "bundle_id": bundle_id,
                "bundle_id_scheme": bundle_id_scheme,
                "protected_bundle_id": protected_bundle_id,
                "export_receipt_required": True,
                "export_receipt_schema_version": PROTECTED_EXPORT_RECEIPT_SCHEMA_VERSION,
                "coverage_gate": {
                    "fail_unclassified_fields": not state.profile.preserve_unknown_fields,
                    "unclassified_field_count": len(state.classification.unclassified),
                },
                "actual_applied_transformations": state.classification.applied_transformations(),
                "resolver_decisions": state.classification.resolver_decisions(),
                "vault_loss_risk_acknowledged": options.acknowledge_vault_loss_risk,
                "vault_loss_risk_notice": (
                    "The encrypted private identity vault and recovery material are "
                    "client-held and may be required for restoration. They must not "
                    "be transferred with the protected bundle."
                ),
            },
        )
        files[PRIVACY_CLASSIFICATION_FILE] = dump_json(
            state.classification.convert_to_dict(),
        )
        files[PRIVACY_PREVIEW_FILE] = dump_json(preview)
        files[PRIVACY_LEAK_SCAN_FILE] = dump_json(leak_scan)
        files[PRIVACY_TOKEN_METADATA_FILE] = dump_json(
            {
                "token_format_version": TOKEN_FORMAT_VERSION,
                "token_scope": options.token_scope,
                "engagement_id": options.engagement_id,
                "token_count": len(state.token_service.vault_builder.entries_by_token),
                "categories": sorted(state.classification.tokenised),
                "vault_required_for_restoration": True,
                "vault_loss_risk_acknowledged": options.acknowledge_vault_loss_risk,
            },
        )
        self._update_manifest(
            files,
            source_manifest=source_manifest,
            options=options,
            state=state,
            bundle_id=bundle_id,
            bundle_id_scheme=bundle_id_scheme,
            protected_bundle_id=protected_bundle_id,
            leak_scan=leak_scan,
        )

    def _update_manifest(
        self,
        files: dict[str, bytes],
        *,
        source_manifest: dict[str, Any],
        options: PrivacyProtectOptions,
        state: ProtectionState,
        bundle_id: str,
        bundle_id_scheme: str,
        protected_bundle_id: str,
        leak_scan: dict[str, object],
    ) -> None:
        manifest = json.loads(files["manifest.json"].decode("utf-8"))
        manifest["bundle_schema_version"] = PROTECTED_BUNDLE_SCHEMA_VERSION
        manifest["privacy_protection"] = {
            "enabled": True,
            "privacy_policy_version": PRIVACY_POLICY_VERSION,
            "profile_id": state.profile.profile_id,
            "profile_version": state.profile.version,
            "token_format_version": TOKEN_FORMAT_VERSION,
            "token_scope": options.token_scope,
            "engagement_id": options.engagement_id,
            **build_vault_public_metadata(state),
            "protected_bundle_id": protected_bundle_id,
            "source_bundle_id": bundle_id,
            "source_bundle_id_scheme": bundle_id_scheme,
            "export_receipt_required": True,
            "export_receipt_schema_version": PROTECTED_EXPORT_RECEIPT_SCHEMA_VERSION,
            "source_bundle_schema_version": source_manifest.get("bundle_schema_version"),
            "vault_included": False,
            "recovery_material_included": False,
            "pseudonymisation_notice": (
                "Protected bundles are pseudonymised, not anonymised. Cost, "
                "utilisation, topology, timing, service usage, and derived "
                "facts may remain sensitive."
            ),
            "coverage_gate": {
                "fail_unclassified_fields": not state.profile.preserve_unknown_fields,
                "unclassified_field_count": len(state.classification.unclassified),
            },
            "leak_scan_passed": bool(leak_scan.get("passed")),
            "actual_applied_transformations": state.classification.applied_transformations(),
            "resolver_decisions": state.classification.resolver_decisions(),
            "vault_loss_risk_acknowledged": options.acknowledge_vault_loss_risk,
        }
        if state.profile.profile_id == "strict" and not state.profile.cost_data_included:
            manifest.setdefault("permission_limitations", [])
            if isinstance(manifest["permission_limitations"], list):
                manifest["permission_limitations"].append(
                    {
                        "type": "privacy_policy",
                        "reason": (
                            "Strict privacy profile removed or generalised cost precision. Financial and clean-cost conclusions are limited by privacy policy."
                        ),
                        "profile_id": state.profile.profile_id,
                    },
                )
        files["manifest.json"] = dump_json(manifest)
        schema = json.loads(files["bundle-schema.json"].decode("utf-8"))
        schema["bundle_schema_version"] = PROTECTED_BUNDLE_SCHEMA_VERSION
        schema["required_files"] = sorted({*schema.get("required_files", []), *PRIVACY_BUNDLE_FILES})
        schema["privacy_protection"] = {
            "format": "unio-protected-evidence-bundle",
            "policy_version": PRIVACY_POLICY_VERSION,
        }
        files["bundle-schema.json"] = dump_json(schema)
        for name in (
            "analysis-contract.json",
            "analysis-readiness.json",
            "collection-summary.json",
            "scan-result/scanner-evidence.json",
        ):
            if name not in files:
                continue
            payload = json.loads(files[name].decode("utf-8"))
            payload = replace_schema_versions(
                payload,
                PROTECTED_BUNDLE_SCHEMA_VERSION,
            )
            if isinstance(payload, dict):
                payload["privacy_protection_enabled"] = True
                payload["privacy_profile_id"] = state.profile.profile_id
                payload["protected_bundle_id"] = protected_bundle_id
                payload["protected_llm_policy"] = "llm_disabled_in_v1"
                if state.profile.profile_id == "strict" and not state.profile.cost_data_included:
                    payload.setdefault("privacy_limitations", [])
                    if isinstance(payload["privacy_limitations"], list):
                        payload["privacy_limitations"].append(
                            {
                                "type": "privacy_policy_cost_precision_reduced",
                                "reason": ("Strict privacy profile reduced cost precision; financial conclusions are limited."),
                            },
                        )
            files[name] = dump_json(payload)
        if "signature.json" in files:
            signature = json.loads(files["signature.json"].decode("utf-8"))
            signature["metadata_version"] = PROTECTED_BUNDLE_SCHEMA_VERSION
            files["signature.json"] = dump_json(signature)

    def _rewrite_checksums_and_manifest(self, files: dict[str, bytes]) -> None:
        files.pop("checksums.json", None)
        checksum_files = {name: data for name, data in files.items() if name not in {"manifest.json", "checksums.json"}}
        checksums = build_checksums(checksum_files)
        manifest = json.loads(files["manifest.json"].decode("utf-8"))
        manifest["checksums"] = checksums
        manifest["evidence_files"] = [name for name in sorted(files) if name.startswith(("evidence/", "scan-result/"))]
        files["manifest.json"] = dump_json(manifest)
        files["checksums.json"] = dump_json(
            {"algorithm": "sha256", "checksums": checksums},
        )
