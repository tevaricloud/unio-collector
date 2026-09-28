"""CLI adapter for integrated protected collection."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from unio_collector.collector.minimisation import EvidenceMinimisationOptions
from unio_collector.collector.protected_workflow.error import ProtectedCollectionWorkflowError
from unio_collector.collector.protected_workflow.options import ProtectedCollectionOptions
from unio_collector.collector.protected_workflow.paths import resolve_protected_collection_paths
from unio_collector.collector.protected_workflow.service import ProtectedCollectionWorkflowService
from unio_collector.collector_cli.console import print_success, print_warning
from unio_collector.collector_cli.passphrase import PassphraseResolver
from unio_collector.collector_cli.services.config import CollectorConfigResolver
from unio_collector.collector_cli.services.progress import CollectorProgressReporter
from unio_collector.collector_cli.services.progress_jsonl import CollectorJsonlProgressWriter
from unio_collector.privacy.vault import read_vault_recovery_mode

if TYPE_CHECKING:
    import argparse

    from unio_collector.scan_workflow.progress import ScanProgressEvent


class CollectorProtectedService:
    """Run the integrated protected-collection workflow for the CLI."""

    def __init__(
        self,
        console: Any,  # noqa: ANN401
        *,
        workflow: ProtectedCollectionWorkflowService | None = None,
        passphrase_resolver: PassphraseResolver | None = None,
    ) -> None:
        """Store output and injectable workflow dependencies."""
        self.console = console
        self.workflow = workflow or ProtectedCollectionWorkflowService()
        self.passphrase_resolver = passphrase_resolver or PassphraseResolver()

    def run(self, args: argparse.Namespace) -> int:
        """Resolve CLI inputs and execute one coordinated workflow."""
        if args.json:
            args.quiet = True
        protected_path = Path(str(args.output))
        existing_vault = Path(args.existing_vault) if args.existing_vault else None
        existing_mode = read_vault_recovery_mode(existing_vault) if existing_vault else None
        recovery_mode = args.recovery_mode or existing_mode or "passphrase"
        paths = resolve_protected_collection_paths(
            protected_path,
            vault=Path(args.vault) if args.vault else None,
            recovery_key=Path(args.recovery_key) if args.recovery_key else None,
            receipt=Path(args.receipt_output) if args.receipt_output else None,
            retained_raw_bundle=Path(args.retain_raw_bundle) if args.retain_raw_bundle else None,
            recovery_mode=recovery_mode,
        )
        resolved = CollectorConfigResolver(self.console).resolve(
            args,
            output=protected_path.parent or Path(),
        )
        passphrase = self.passphrase_resolver.resolve(
            required=(recovery_mode in {"passphrase", "passphrase-and-key"} or existing_mode in {"passphrase", "passphrase-and-key"}),
            legacy_value=args.passphrase,
            file_path=args.passphrase_file,
            use_stdin=bool(args.passphrase_stdin),
            confirm=True,
            artifact="identity_vault",
        )
        progress = CollectorProgressReporter(
            console=self.console,
            quiet=bool(args.quiet) or bool(args.json),
            verbose=bool(args.verbose),
            compact_progress=bool(args.compact_progress),
        )
        jsonl_writer = CollectorJsonlProgressWriter.from_args(args)

        def collection_progress(event: ScanProgressEvent) -> None:
            progress.handle_event(event)
            jsonl_writer.write(event)

        try:
            result = self.workflow.execute(
                config=resolved.config,
                selection=resolved.selection,
                paths=paths,
                options=ProtectedCollectionOptions(
                    protected_bundle_path=paths.protected_bundle,
                    vault_path=paths.vault,
                    recovery_key_path=paths.recovery_key,
                    receipt_path=paths.receipt,
                    retain_raw_bundle_path=paths.retained_raw_bundle,
                    temporary_directory=(Path(args.temporary_directory) if args.temporary_directory else None),
                    recovery_mode=recovery_mode,
                    passphrase=passphrase.value,
                    privacy_profile=args.privacy_profile,
                    token_scope=args.token_scope,
                    engagement_id=args.engagement_id,
                    client_id=args.client_id,
                    existing_vault_path=existing_vault,
                    existing_recovery_key_path=(Path(args.existing_recovery_key) if args.existing_recovery_key else None),
                    allow_unknown_fields=bool(args.allow_unknown_fields),
                    acknowledge_vault_loss_risk=bool(args.acknowledge_vault_loss_risk),
                    overwrite=bool(args.overwrite),
                    warning_details=passphrase.warning_details,
                    progress=(
                        None
                        if args.json
                        else lambda stage, status: self.console.print(
                            f"Protected collection stage {stage}: {status}",
                        )
                    ),
                    environment_alias_file=(Path(args.environment_alias_file) if args.environment_alias_file else None),
                    environment_semantics=args.environment_semantics,
                ),
                minimisation=EvidenceMinimisationOptions.from_args(args),
                collection_progress=collection_progress,
            )
        except ProtectedCollectionWorkflowError as exc:
            if args.json:
                self.console.print(json.dumps(exc.convert_to_dict(), indent=2, sort_keys=True))
            else:
                print_warning(self.console, f"Protected collection failed during {exc.failed_stage}: {exc}")
            return 1
        finally:
            jsonl_writer.close()
        payload = result.convert_to_dict()
        if args.json:
            self.console.print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print_success(self.console, f"Protected evidence bundle ready: {result.protected_bundle_path}")
            print_success(self.console, f"Client-held identity vault: {result.vault_path}")
            if result.recovery_material_path is not None:
                print_success(self.console, f"Client-held recovery material: {result.recovery_material_path}")
            self.console.print("Transfer only the protected evidence bundle; keep the vault and recovery material with the client.")
            for warning in result.warnings:
                print_warning(self.console, f"Warning: {warning}")
        return 1 if args.fail_on_warning and result.warnings else 0


__all__ = ["CollectorProtectedService"]
