"""Collector-safe integrated privacy-protection orchestration."""

from __future__ import annotations

# ruff: noqa: EM101,EM102,TRY003,TRY301
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from unio_collector.collector.bundle.collection_writer import CollectorEvidenceBundleWriter
from unio_collector.collector.bundle.validator import EvidenceBundleValidator
from unio_collector.collector.execution.service import CollectorExecutionService
from unio_collector.collector.minimisation import EvidenceMinimisationOptions
from unio_collector.collector.protected_workflow.error import ProtectedCollectionWorkflowError
from unio_collector.collector.protected_workflow.publisher import ProtectedCollectionArtifactPublisher
from unio_collector.collector.protected_workflow.result import ProtectedCollectionResult
from unio_collector.privacy.bundle import ProtectedBundleInspector, ProtectedBundleProtector
from unio_collector.privacy.content_hash import sha256_file
from unio_collector.privacy.options import PrivacyProtectOptions

if TYPE_CHECKING:
    from collections.abc import Callable

    from unio_collector.collector.protected_workflow.options import ProtectedCollectionOptions
    from unio_collector.collector.protected_workflow.paths import ProtectedCollectionPaths


class ProtectedCollectionWorkflowService:
    """Collect, protect, validate, and publish one client-safe artifact set."""

    def __init__(
        self,
        *,
        collector: CollectorExecutionService | None = None,
        protector: ProtectedBundleProtector | None = None,
        inspector: ProtectedBundleInspector | None = None,
        publisher: ProtectedCollectionArtifactPublisher | None = None,
    ) -> None:
        """Store injectable production service boundaries."""
        self._collector = collector or CollectorExecutionService()
        self._protector = protector or ProtectedBundleProtector()
        self._inspector = inspector or ProtectedBundleInspector()
        self._publisher = publisher or ProtectedCollectionArtifactPublisher()

    def execute(
        self,
        *,
        config: object,
        selection: object,
        paths: ProtectedCollectionPaths,
        options: ProtectedCollectionOptions,
        minimisation: EvidenceMinimisationOptions | None = None,
        collection_progress: object | None = None,
    ) -> ProtectedCollectionResult:
        """Execute the fail-closed protected-collection workflow."""
        stages = {
            "validation": "pending",
            "collection": "pending",
            "protection": "pending",
            "protected_validation": "pending",
            "publication": "pending",
            "cleanup": "pending",
        }
        cleanup: dict[str, object] = {"raw_bundle_removed": False, "temporary_workspace_removed": False}
        temporary_root = options.temporary_directory
        try:
            paths.validate(temporary_root=temporary_root, overwrite=options.overwrite)
            self._validate_options(options, paths)
        except Exception as exc:
            stages["validation"] = "failed"
            raise ProtectedCollectionWorkflowError(
                str(exc),
                failed_stage="validation",
                stages=stages,
                cleanup=cleanup,
            ) from exc
        stages["validation"] = "complete"
        self._progress(options.progress, "validation", "complete")
        minimisation_options = minimisation or EvidenceMinimisationOptions()
        retained_warning = (
            "Raw evidence retention was explicitly requested. Keep the retained raw bundle on the client device and do not transfer it to Tevari."
            if paths.retained_raw_bundle is not None
            else None
        )
        workspace_path: Path | None = None
        stage_paths: tuple[Path, ...] = ()
        active_stage = "collection"
        with tempfile.TemporaryDirectory(
            prefix="Unio-collect-protected-",
            dir=temporary_root,
        ) as workspace_name:
            workspace_path = Path(workspace_name)
            workspace_path.chmod(0o700)
            raw_bundle = workspace_path / "raw-evidence-bundle.zip"
            stage_paths = self._publisher.stage_paths(paths, workspace_path)
            try:
                self._progress(options.progress, "collection", "running")
                collection = self._collector.execute(
                    config,
                    selection,
                    collection_progress,
                    minimisation=minimisation_options,
                )
                CollectorEvidenceBundleWriter().write(
                    path=raw_bundle,
                    result=collection,
                    minimisation=minimisation_options,
                )
                raw_bundle.chmod(0o600)
                EvidenceBundleValidator().validate_or_raise(raw_bundle)
                stages["collection"] = "complete"
                self._progress(options.progress, "collection", "complete")

                active_stage = "protection"
                self._progress(options.progress, "protection", "running")
                protected, vault, recovery, receipt = stage_paths
                protection = self._protector.protect(
                    PrivacyProtectOptions(
                        bundle_path=raw_bundle,
                        output_path=protected,
                        vault_path=vault,
                        recovery_key_path=recovery if paths.recovery_key is not None else None,
                        receipt_path=receipt,
                        recovery_mode=options.recovery_mode,
                        passphrase=options.passphrase,
                        profile_id=options.privacy_profile,
                        token_scope=options.token_scope,
                        engagement_id=options.engagement_id,
                        overwrite=False,
                        allow_unknown_fields=options.allow_unknown_fields,
                        acknowledge_vault_loss_risk=options.acknowledge_vault_loss_risk,
                        warning_details=options.warning_details,
                        existing_vault_path=options.existing_vault_path,
                        existing_recovery_key_path=options.existing_recovery_key_path,
                        client_id=options.client_id,
                        environment_alias_file=options.environment_alias_file,
                        environment_semantics=options.environment_semantics,
                    ),
                )
                stages["protection"] = "complete"
                self._progress(options.progress, "protection", "complete")

                active_stage = "protected_validation"
                self._progress(options.progress, "protected_validation", "running")
                inspection = self._inspector.inspect(protected, receipt_path=receipt)
                leak_scan = protection.preview.get("leak_scan")
                leak_passed = isinstance(leak_scan, dict) and leak_scan.get("passed") is True
                if not inspection.protected or not inspection.validation_passed or not leak_passed:
                    details = "; ".join(inspection.errors) or "protected bundle leak scan did not pass"
                    raise ValueError(f"Protected bundle validation failed: {details}")
                stages["protected_validation"] = "complete"
                self._progress(options.progress, "protected_validation", "complete")

                active_stage = "publication"
                self._progress(options.progress, "publication", "running")
                self._publisher.publish(
                    paths=paths,
                    stage_paths=stage_paths,
                    raw_bundle=raw_bundle,
                    overwrite=options.overwrite,
                )
                stages["publication"] = "complete"
                self._progress(options.progress, "publication", "complete")
                cleanup["raw_bundle_removed"] = paths.retained_raw_bundle is None
                token_metadata = inspection.summary.get("token_metadata")
                token_data = token_metadata if isinstance(token_metadata, dict) else {}
                relationships = protection.preview.get("relationship_count", 0)
                warnings = list(dict.fromkeys(protection.warnings))
                if retained_warning:
                    warnings.append(retained_warning)
                result = ProtectedCollectionResult(
                    provider=str(getattr(collection, "provider_id", "aws")),
                    protected_bundle_path=paths.protected_bundle,
                    protected_bundle_sha256=sha256_file(paths.protected_bundle),
                    vault_path=paths.vault,
                    vault_sha256=sha256_file(paths.vault),
                    recovery_material_path=paths.recovery_key,
                    recovery_material_sha256=(sha256_file(paths.recovery_key) if paths.recovery_key else None),
                    receipt_path=paths.receipt,
                    receipt_sha256=sha256_file(paths.receipt),
                    privacy_profile=options.privacy_profile,
                    token_scope=options.token_scope,
                    engagement_id=options.engagement_id,
                    cost_data_included=bool(protection.preview.get("cost_data_remains_visible", True)) and not minimisation_options.no_cost_data,
                    token_count=self._integer(token_data.get("token_count")),
                    relationship_count=self._integer(relationships),
                    leak_scan_passed=leak_passed,
                    validation_passed=inspection.validation_passed,
                    raw_bundle_retained=paths.retained_raw_bundle is not None,
                    raw_bundle_path=paths.retained_raw_bundle,
                    raw_bundle_sha256=(sha256_file(paths.retained_raw_bundle) if paths.retained_raw_bundle else None),
                    collection_status=str(getattr(collection, "collection_status", "unknown")),
                    collection_limitations=tuple(getattr(collection, "limitations", ()) or ()),
                    stages=stages,
                    cleanup=cleanup,
                    warnings=tuple(warnings),
                    limitations=tuple(getattr(collection, "limitations", ()) or ()),
                )
            except BaseException as exc:
                self._publisher.cleanup(stage_paths)
                stages[active_stage] = "failed"
                if isinstance(exc, Exception):
                    raise ProtectedCollectionWorkflowError(
                        str(exc),
                        failed_stage=active_stage,
                        stages=stages,
                        cleanup=cleanup,
                    ) from exc
                raise
        cleanup["temporary_workspace_removed"] = bool(workspace_path and not workspace_path.exists())
        stages["cleanup"] = "complete"
        self._progress(options.progress, "cleanup", "complete")
        return result

    def _validate_options(
        self,
        options: ProtectedCollectionOptions,
        paths: ProtectedCollectionPaths,
    ) -> None:
        if not options.acknowledge_vault_loss_risk:
            raise ValueError("collect-protected requires --acknowledge-vault-loss-risk.")
        if options.token_scope == "client" and not options.client_id:  # noqa: S105
            raise ValueError("Client token scope requires --client-id.")
        if options.token_scope != "client" and options.client_id:  # noqa: S105
            raise ValueError("--client-id is only valid with --token-scope client.")
        if options.recovery_mode in {"recovery-key", "passphrase-and-key"} and paths.recovery_key is None:
            raise ValueError("Selected recovery mode requires a recovery-key destination.")
        if options.allow_unknown_fields and options.privacy_profile != "custom":
            raise ValueError("--allow-unknown-fields is only available with --privacy-profile custom.")
        if options.existing_recovery_key_path is not None and options.existing_vault_path is None:
            raise ValueError("--existing-recovery-key requires --existing-vault.")
        if options.temporary_directory is not None and not options.temporary_directory.is_dir():
            raise ValueError("--temporary-directory must name an existing directory.")

    def _integer(self, value: object) -> int:
        return value if isinstance(value, int) and not isinstance(value, bool) else 0

    def _progress(
        self,
        callback: Callable[[str, str], None] | None,
        stage: str,
        status: str,
    ) -> None:
        if callback is not None:
            callback(stage, status)


__all__ = ["ProtectedCollectionWorkflowService"]
