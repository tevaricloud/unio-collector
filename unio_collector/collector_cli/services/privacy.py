from __future__ import annotations  # noqa: D100

# ruff: noqa: EM101,S105,TRY003
import json
from pathlib import Path
from typing import TYPE_CHECKING

from unio_collector.collector_cli.console import (
    print_error,
    print_success,
    print_warning,
)
from unio_collector.collector_cli.passphrase import PassphraseResolver
from unio_collector.privacy.bundle import (
    PrivacyProtectOptions,
    ProtectedBundleInspector,
    ProtectedBundleProtector,
)
from unio_collector.privacy.preview_options import PrivacyPreviewOptions
from unio_collector.privacy.previewer import PrivacyPreviewer
from unio_collector.privacy.vault import read_vault_recovery_mode
from unio_collector.privacy.vault_rekey.options import VaultRekeyOptions
from unio_collector.privacy.vault_rekey.service import VaultRekeyer
from unio_collector.protected_reports.restoration import (
    ProtectedReportRestoreOptions,
    ProtectedReportRestorer,
)

if TYPE_CHECKING:
    import argparse

    from unio_collector.core.console_like import ConsoleLike


class CollectorPrivacyService:
    """Run collector-safe privacy bundle commands."""

    def __init__(
        self,
        console: ConsoleLike,
        passphrase_resolver: PassphraseResolver | None = None,
    ) -> None:
        """Create a privacy command service."""
        self.console = console
        self.passphrase_resolver = passphrase_resolver or PassphraseResolver()

    def run(self, args: argparse.Namespace) -> int:
        """Dispatch a collector privacy subcommand."""
        privacy_command = getattr(args, "privacy_command", "")
        if privacy_command == "protect":
            return self._protect(args)
        if privacy_command == "preview":
            return self._preview(args)
        if privacy_command == "rekey-vault":
            return self._rekey_vault(args)
        if privacy_command == "inspect":
            return self._inspect(args)
        if privacy_command == "restore-report":
            return self._restore_report(args)
        return 1

    def _protect(self, args: argparse.Namespace) -> int:
        self._validate_recovery_args(args)
        existing_vault = Path(args.existing_vault) if args.existing_vault else None
        existing_mode = read_vault_recovery_mode(existing_vault) if existing_vault else None
        recovery_mode = args.recovery_mode or existing_mode or "passphrase"
        passphrase = self.passphrase_resolver.resolve(
            required=(recovery_mode in {"passphrase", "passphrase-and-key"} or existing_mode in {"passphrase", "passphrase-and-key"}),
            legacy_value=args.passphrase,
            file_path=args.passphrase_file,
            use_stdin=bool(args.passphrase_stdin),
            confirm=True,
            artifact="identity_vault",
        )
        result = ProtectedBundleProtector().protect(
            PrivacyProtectOptions(
                bundle_path=Path(args.bundle),
                output_path=Path(args.output),
                vault_path=Path(args.vault),
                recovery_key_path=(Path(args.recovery_key) if args.recovery_key else None),
                preview_output_path=(Path(args.preview_output) if args.preview_output else None),
                receipt_path=(Path(args.receipt_output) if args.receipt_output else None),
                recovery_mode=recovery_mode,
                passphrase=passphrase.value,
                profile_id=args.profile,
                token_scope=args.token_scope,
                engagement_id=args.engagement_id,
                overwrite=bool(args.overwrite),
                allow_unknown_fields=bool(args.allow_unknown_fields),
                acknowledge_vault_loss_risk=bool(
                    args.acknowledge_vault_loss_risk,
                ),
                warning_details=passphrase.warning_details,
                existing_vault_path=existing_vault,
                existing_recovery_key_path=(Path(args.existing_recovery_key) if args.existing_recovery_key else None),
                client_id=args.client_id,
                in_place_vault_update=bool(args.in_place_vault_update),
            ),
        )
        if args.json:
            self.console.print(json.dumps(result.preview, indent=2, sort_keys=True))
        else:
            print_success(self.console, f"Protected evidence bundle written: {result.output_path}")
            print_success(self.console, f"Encrypted private identity vault written: {result.vault_path}")
            if result.recovery_key_path is not None:
                print_success(self.console, f"Recovery key file written: {result.recovery_key_path}")
            if result.preview_output_path is not None:
                print_success(self.console, f"Privacy preview written: {result.preview_output_path}")
            print_success(self.console, f"Completion receipt written: {result.receipt_path}")
            warning_count = len(result.warnings)
            self.console.print(
                f"Privacy preview: {result.preview['unclassified_field_count']} unclassified fields, {warning_count} warnings.",
            )
            for warning in result.warning_details:
                print_warning(self.console, f"Warning [{warning.code}]: {warning.message}")
        if args.fail_on_warning and result.warnings:
            return 1
        return 0

    def _preview(self, args: argparse.Namespace) -> int:
        if args.allow_unknown_fields and args.profile != "custom":
            raise ValueError("--allow-unknown-fields is only available with --profile custom.")
        existing_vault = Path(args.existing_vault) if args.existing_vault else None
        recovery_mode = read_vault_recovery_mode(existing_vault) if existing_vault else "passphrase"
        passphrase = self.passphrase_resolver.resolve(
            required=existing_vault is not None and recovery_mode in {"passphrase", "passphrase-and-key"},
            legacy_value=args.passphrase,
            file_path=args.passphrase_file,
            use_stdin=bool(args.passphrase_stdin),
            confirm=False,
            artifact="identity_vault",
        )
        payload = PrivacyPreviewer().preview(
            PrivacyPreviewOptions(
                bundle_path=Path(args.bundle),
                profile_id=args.profile,
                token_scope=args.token_scope,
                engagement_id=args.engagement_id,
                client_id=args.client_id,
                allow_unknown_fields=bool(args.allow_unknown_fields),
                existing_vault_path=existing_vault,
                existing_recovery_key_path=(Path(args.existing_recovery_key) if args.existing_recovery_key else None),
                passphrase=passphrase.value,
            ),
        )
        self.console.print(json.dumps(payload, indent=2, sort_keys=True))
        failed = bool(payload["unclassified_field_count"] or payload["prohibited_field_count"])
        leak_risk = payload.get("leak_risk")
        if isinstance(leak_risk, dict) and leak_risk.get("passed") is not True:
            failed = True
        if args.fail_on_warning and payload.get("limitations"):
            failed = True
        return 1 if failed else 0

    def _inspect(self, args: argparse.Namespace) -> int:
        result = ProtectedBundleInspector().inspect(
            Path(args.bundle),
            receipt_path=(Path(args.receipt) if args.receipt else None),
        )
        payload = {
            "path": str(result.path),
            "protected": result.protected,
            "validation_passed": result.validation_passed,
            "summary": result.summary,
            "errors": list(result.errors),
        }
        if args.json:
            self.console.print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            status = "passed" if result.validation_passed else "failed"
            protected = "yes" if result.protected else "no"
            self.console.print(f"Protected: {protected}")
            self.console.print(f"Validation: {status}")
            privacy = result.summary.get("privacy_protection")
            if isinstance(privacy, dict) and privacy:
                self.console.print(
                    f"Token scope: {privacy.get('token_scope', 'unknown')} ({privacy.get('profile_id', 'unknown')} profile)",
                )
            receipt = result.summary.get("receipt")
            if isinstance(receipt, dict):
                if receipt.get("verified") is True:
                    self.console.print("Completion receipt: verified")
                elif receipt.get("available") is True:
                    self.console.print("Completion receipt: invalid")
                else:
                    self.console.print("Completion receipt: unavailable")
            for error in result.errors:
                print_error(self.console, f"Error: {error}")
        return 0 if result.validation_passed else 1

    def _rekey_vault(self, args: argparse.Namespace) -> int:
        old_mode = read_vault_recovery_mode(Path(args.vault))
        old_passphrase = self.passphrase_resolver.resolve(
            required=old_mode in {"passphrase", "passphrase-and-key"},
            legacy_value=args.passphrase,
            file_path=args.passphrase_file,
            use_stdin=bool(args.passphrase_stdin),
            confirm=False,
            artifact="identity_vault",
        )
        new_passphrase = self.passphrase_resolver.resolve(
            required=args.new_recovery_mode in {"passphrase", "passphrase-and-key"},
            legacy_value=args.new_passphrase,
            file_path=args.new_passphrase_file,
            use_stdin=bool(args.new_passphrase_stdin),
            confirm=True,
            artifact="identity_vault",
        )
        result = VaultRekeyer().rekey(
            VaultRekeyOptions(
                vault_path=Path(args.vault),
                output_vault_path=Path(args.output_vault),
                old_passphrase=old_passphrase.value,
                old_recovery_key_path=(Path(args.recovery_key) if args.recovery_key else None),
                new_recovery_mode=args.new_recovery_mode,
                new_passphrase=new_passphrase.value,
                new_recovery_key_path=(Path(args.new_recovery_key) if args.new_recovery_key else None),
                in_place=bool(args.in_place),
                overwrite=bool(args.overwrite),
            ),
        )
        if args.json:
            self.console.print(json.dumps({"status": "rekeyed", "vault_revision_written": True}, sort_keys=True))
        else:
            print_success(self.console, f"Rekeyed vault written: {result.vault_path}")
            if result.recovery_key_path is not None:
                print_success(self.console, f"New recovery key written: {result.recovery_key_path}")
        return 0

    def _restore_report(self, args: argparse.Namespace) -> int:
        recovery_mode = read_vault_recovery_mode(Path(args.vault))
        passphrase = self.passphrase_resolver.resolve(
            required=recovery_mode in {"passphrase", "passphrase-and-key"},
            legacy_value=args.passphrase,
            file_path=args.passphrase_file,
            use_stdin=bool(args.passphrase_stdin),
            confirm=False,
            artifact="identity_vault",
        )
        result = ProtectedReportRestorer().restore(
            ProtectedReportRestoreOptions(
                package_path=Path(args.package),
                vault_path=Path(args.vault),
                output_dir=Path(args.output_dir),
                passphrase=passphrase.value,
                recovery_key_path=(Path(args.recovery_key) if args.recovery_key else None),
                tevari_public_key_path=(Path(args.tevari_public_key) if args.tevari_public_key else None),
                expected_key_id=args.expected_key_id,
                allow_unsigned=bool(args.allow_unsigned),
                overwrite=bool(args.overwrite),
                warning_details=passphrase.warning_details,
            ),
        )
        if args.json:
            self.console.print(json.dumps(result.audit, indent=2, sort_keys=True))
        else:
            print_success(self.console, f"Restored report written: {result.markdown_path}")
            print_success(self.console, f"Restored HTML written: {result.html_path}")
            print_success(self.console, f"Restoration audit written: {result.audit_path}")
            print_success(self.console, f"Restoration completion marker written: {result.completion_path}")
            for warning in result.warning_details:
                print_warning(self.console, f"Warning [{warning.code}]: {warning.message}")
        if args.fail_on_warning and result.warnings:
            return 1
        return 0

    def _validate_recovery_args(self, args: argparse.Namespace) -> None:
        mode = str(args.recovery_mode or "passphrase")
        if mode in {"recovery-key", "passphrase-and-key"} and not (args.recovery_key or args.existing_recovery_key):
            raise ValueError("Selected recovery mode requires --recovery-key.")
        if args.allow_unknown_fields and args.profile != "custom":
            raise ValueError(
                "--allow-unknown-fields is only available with --profile custom.",
            )
        if not args.acknowledge_vault_loss_risk:
            raise ValueError(
                "privacy protect requires --acknowledge-vault-loss-risk when creating a client-held vault. "
                "Tevari cannot restore original identifiers if the vault, passphrase, or recovery key is lost, "
                "and vault/recovery material must not be transferred with the protected bundle.",
            )
        if args.token_scope == "client" and not args.client_id:
            raise ValueError("Client token scope requires --client-id.")
        if args.token_scope != "client" and args.client_id:
            raise ValueError("--client-id is only valid with --token-scope client.")
        if args.existing_recovery_key and not args.existing_vault:
            raise ValueError("--existing-recovery-key requires --existing-vault.")
