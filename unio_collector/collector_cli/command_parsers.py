from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.collector_cli.parser_arguments import (
    add_bundle_minimisation_arguments,
    add_collection_scope_arguments,
    add_debug_argument,
    add_region_arguments,
    add_runtime_arguments,
    add_scanner_arguments,
)

if TYPE_CHECKING:
    import argparse


def add_collect_command(
    subparsers: argparse._SubParsersAction,
    command_name: str,
) -> None:
    """Add the collector-only evidence collection command."""
    collect = subparsers.add_parser(
        command_name,
        help="Collect read-only cloud evidence into an evidence bundle.",
    )
    add_debug_argument(collect)
    add_collection_scope_arguments(collect)
    add_region_arguments(collect)
    add_scanner_arguments(collect)
    add_runtime_arguments(collect)
    add_bundle_minimisation_arguments(collect)
    collect.add_argument(
        "--output",
        default="evidence-bundle.zip",
        help="Evidence bundle ZIP output path.",
    )
    collect.add_argument(
        "--fail-on-degraded",
        action="store_true",
        help="Return a non-zero exit code when collection completes with limitations.",
    )
    collect.add_argument(
        "--progress-jsonl",
        default=None,
        help="Optional schema-versioned JSONL progress event path.",
    )


def add_validate_bundle_command(
    subparsers: argparse._SubParsersAction,
    command_name: str,
) -> None:
    """Add the local bundle validation command."""
    validate = subparsers.add_parser(
        command_name,
        help="Validate an evidence bundle without cloud credentials.",
    )
    add_debug_argument(validate)
    validate.add_argument("bundle", help="Evidence bundle ZIP path.")


def add_policy_command(
    subparsers: argparse._SubParsersAction,
    command_name: str,
) -> None:
    """Add collector-safe permission policy planning commands."""
    policy = subparsers.add_parser(
        command_name,
        help="Plan collector-safe cloud permissions.",
    )
    add_debug_argument(policy)
    policy_subparsers = policy.add_subparsers(dest="policy_provider", required=True)
    aws = policy_subparsers.add_parser(
        "aws",
        help="Plan AWS least-permission collector access.",
    )
    add_debug_argument(aws)
    add_collection_scope_arguments(aws)
    add_region_arguments(aws)
    add_scanner_arguments(aws)
    aws.add_argument(
        "--format",
        choices=("json", "iam-policy", "summary"),
        default="json",
        help="Policy planning output format.",
    )
    aws.add_argument(
        "--include-conditional-actions",
        action="store_true",
        help=("Include conditional IAM actions in rendered policy documents. Chargeable scanner gating remains controlled separately."),
    )
    _add_policy_scope_arguments(aws)
    aws.add_argument("--output", default=None, help="Optional output path.")


def add_permission_preview_command(
    subparsers: argparse._SubParsersAction,
    command_name: str,
) -> None:
    """Add metadata-first permission preview command."""
    preview = subparsers.add_parser(
        command_name,
        help="Preview expected collector permissions without proving runtime access.",
    )
    add_debug_argument(preview)
    add_collection_scope_arguments(preview)
    add_region_arguments(preview)
    add_scanner_arguments(preview)
    preview.add_argument(
        "--probe",
        action="store_true",
        help="Record bounded read-only probe observations where implemented.",
    )
    _add_policy_scope_arguments(preview)
    preview.add_argument("--output", default=None, help="Optional JSON output path.")


def _add_policy_scope_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--policy-account-id",
        default=None,
        help=("Planning-only AWS account ID used when authenticated identity is unavailable."),
    )
    parser.add_argument(
        "--policy-partition",
        default=None,
        help=("Planning-only AWS partition used when runtime and regional scope cannot resolve it."),
    )


def add_privacy_command(
    subparsers: argparse._SubParsersAction,
    command_name: str,
) -> None:
    """Add collector-safe privacy protection commands."""
    privacy = subparsers.add_parser(
        command_name,
        help="Protect and inspect evidence bundles before transfer.",
    )
    add_debug_argument(privacy)
    privacy_subparsers = privacy.add_subparsers(
        dest="privacy_command",
        required=True,
    )
    protect = privacy_subparsers.add_parser(
        "protect",
        help="Create a protected evidence bundle and local encrypted vault.",
    )
    add_debug_argument(protect)
    protect.add_argument("--bundle", required=True, help="Input evidence bundle ZIP.")
    protect.add_argument(
        "--output",
        required=True,
        help="Protected evidence bundle ZIP output path.",
    )
    protect.add_argument(
        "--vault",
        required=True,
        help="Encrypted private identity vault output path.",
    )
    protect.add_argument(
        "--recovery-mode",
        choices=("passphrase", "recovery-key", "passphrase-and-key"),
        default=None,
        help="Local root-key recovery mode (default: passphrase, or retain an existing vault mode).",
    )
    protect_passphrase = protect.add_mutually_exclusive_group()
    protect_passphrase.add_argument(
        "--passphrase",
        default=None,
        help=("DEPRECATED: passphrase used to wrap the random root key; command-line values may be exposed through process listings or logs."),
    )
    protect_passphrase.add_argument(
        "--passphrase-file",
        default=None,
        help="Read the client-held passphrase from a single-line UTF-8 file.",
    )
    protect_passphrase.add_argument(
        "--passphrase-stdin",
        action="store_true",
        help="Read the client-held passphrase from redirected standard input.",
    )
    protect.add_argument(
        "--recovery-key",
        default=None,
        help="High-entropy recovery key file output path.",
    )
    protect.add_argument(
        "--profile",
        choices=("standard", "strict", "custom"),
        default="standard",
        help="Privacy profile to apply.",
    )
    protect.add_argument(
        "--token-scope",
        choices=("bundle", "engagement", "client"),
        default="engagement",
        help="Token correlation scope.",
    )
    protect.add_argument(
        "--engagement-id",
        default="default-engagement",
        help="Engagement identifier included in token domain separation.",
    )
    protect.add_argument("--client-id", default=None, help="Client correlation boundary required for client token scope.")
    protect.add_argument("--existing-vault", default=None, help="Existing encrypted vault to unlock and extend.")
    protect.add_argument("--existing-recovery-key", default=None, help="Recovery key used only to unlock --existing-vault.")
    protect.add_argument(
        "--in-place-vault-update",
        action="store_true",
        help="Explicitly replace --existing-vault atomically; otherwise write a distinct vault revision.",
    )
    protect.add_argument(
        "--preview-output",
        default=None,
        help="Optional JSON privacy preview output path.",
    )
    protect.add_argument(
        "--receipt-output",
        default=None,
        help="Completion receipt path (default: <protected ZIP>.receipt.json).",
    )
    protect.add_argument(
        "--allow-unknown-fields",
        action="store_true",
        help="Custom profile only: preserve unclassified fields with an audit record.",
    )
    protect.add_argument(
        "--acknowledge-vault-loss-risk",
        action="store_true",
        help=("Acknowledge that the private vault and recovery material are client-held and may be required for restoration."),
    )
    protect.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing protected bundle, vault, and recovery-key files.",
    )
    protect.add_argument(
        "--fail-on-warning",
        action="store_true",
        help="Return non-zero when local file-safety or privacy warnings are emitted.",
    )
    protect.add_argument(
        "--json",
        action="store_true",
        help="Print the privacy preview as JSON.",
    )

    preview = privacy_subparsers.add_parser(
        "preview",
        help="Simulate privacy transformation without writing artifacts.",
    )
    add_debug_argument(preview)
    preview.add_argument("--bundle", required=True, help="Input evidence bundle ZIP.")
    preview.add_argument("--profile", choices=("standard", "strict", "custom"), default="standard")
    preview.add_argument("--token-scope", choices=("bundle", "engagement", "client"), default="engagement")
    preview.add_argument("--engagement-id", default="default-engagement")
    preview.add_argument("--client-id", default=None)
    preview.add_argument("--existing-vault", default=None)
    preview.add_argument("--existing-recovery-key", default=None)
    preview_passphrase = preview.add_mutually_exclusive_group()
    preview_passphrase.add_argument("--passphrase", default=None)
    preview_passphrase.add_argument("--passphrase-file", default=None)
    preview_passphrase.add_argument("--passphrase-stdin", action="store_true")
    preview.add_argument("--allow-unknown-fields", action="store_true")
    preview.add_argument("--fail-on-warning", action="store_true")
    preview.add_argument("--json", action="store_true")

    rekey = privacy_subparsers.add_parser(
        "rekey-vault",
        help="Rotate vault wrapping material without changing stable tokens.",
    )
    add_debug_argument(rekey)
    rekey.add_argument("--vault", required=True, help="Existing encrypted vault.")
    rekey.add_argument("--output-vault", required=True, help="Next encrypted vault revision.")
    old_passphrase = rekey.add_mutually_exclusive_group()
    old_passphrase.add_argument("--passphrase", default=None)
    old_passphrase.add_argument("--passphrase-file", default=None)
    old_passphrase.add_argument("--passphrase-stdin", action="store_true")
    rekey.add_argument("--recovery-key", default=None, help="Existing recovery key input.")
    rekey.add_argument(
        "--new-recovery-mode",
        choices=("passphrase", "recovery-key", "passphrase-and-key"),
        default="passphrase",
    )
    new_passphrase = rekey.add_mutually_exclusive_group()
    new_passphrase.add_argument("--new-passphrase", default=None)
    new_passphrase.add_argument("--new-passphrase-file", default=None)
    new_passphrase.add_argument("--new-passphrase-stdin", action="store_true")
    rekey.add_argument("--new-recovery-key", default=None, help="New recovery key output path.")
    rekey.add_argument("--in-place", action="store_true", help="Explicitly replace the source vault atomically.")
    rekey.add_argument("--overwrite", action="store_true")
    rekey.add_argument("--json", action="store_true")

    inspect = privacy_subparsers.add_parser(
        "inspect",
        help="Inspect protected bundle metadata without vault access.",
    )
    add_debug_argument(inspect)
    inspect.add_argument("--bundle", required=True, help="Protected bundle ZIP path.")
    inspect.add_argument(
        "--json",
        action="store_true",
        help="Print inspection metadata as JSON.",
    )
    inspect.add_argument(
        "--receipt",
        default=None,
        help="Optional receipt path; otherwise use the adjacent default when present.",
    )

    restore = privacy_subparsers.add_parser(
        "restore-report",
        help="Restore a protected report package locally with a private vault.",
    )
    add_debug_argument(restore)
    restore.add_argument(
        "--package",
        required=True,
        help="Protected report package JSON path.",
    )
    restore.add_argument(
        "--vault",
        required=True,
        help="Encrypted private identity vault path.",
    )
    restore.add_argument(
        "--output-dir",
        required=True,
        help="Local directory for restored JSON, Markdown, HTML, and audit files.",
    )
    restore_passphrase = restore.add_mutually_exclusive_group()
    restore_passphrase.add_argument(
        "--passphrase",
        default=None,
        help=("DEPRECATED: client-held passphrase used to unlock the private vault; command-line values may be exposed through process listings or logs."),
    )
    restore_passphrase.add_argument(
        "--passphrase-file",
        default=None,
        help="Read the client-held passphrase from a single-line UTF-8 file.",
    )
    restore_passphrase.add_argument(
        "--passphrase-stdin",
        action="store_true",
        help="Read the client-held passphrase from redirected standard input.",
    )
    restore.add_argument(
        "--recovery-key",
        default=None,
        help="Client-held high-entropy recovery key file used to unlock the vault.",
    )
    restore.add_argument(
        "--tevari-public-key",
        default=None,
        help="Trusted Tevari Ed25519 public key PEM for signed package verification.",
    )
    restore.add_argument(
        "--expected-key-id",
        default=None,
        help="Expected Tevari signing key id.",
    )
    restore.add_argument(
        "--allow-unsigned",
        action="store_true",
        help="Allow unsigned protected report packages for local testing.",
    )
    restore.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing restored report outputs.",
    )
    restore.add_argument(
        "--fail-on-warning",
        action="store_true",
        help="Return non-zero when local file-safety or security warnings are emitted.",
    )
    restore.add_argument(
        "--json",
        action="store_true",
        help="Print restoration audit metadata as JSON.",
    )


def add_version_command(
    subparsers: argparse._SubParsersAction,
    command_name: str,
) -> None:
    """Add the version subcommand."""
    version = subparsers.add_parser(
        command_name,
        help="Print the collector version.",
    )
    add_debug_argument(version)
    version.add_argument(
        "--check",
        action="store_true",
        help="Explicitly check signed release metadata for another version.",
    )
    version.add_argument(
        "--metadata-url",
        default=None,
        help="HTTPS URL or local path for signed release metadata.",
    )
    version.add_argument(
        "--signature-url",
        default=None,
        help="HTTPS URL or local path for the detached metadata signature.",
    )
    version.add_argument(
        "--public-key",
        default=None,
        help="Trusted Ed25519 release public-key PEM path.",
    )
    version.add_argument(
        "--json",
        action="store_true",
        help="Print version-check results as JSON.",
    )


def add_profiles_command(
    subparsers: argparse._SubParsersAction,
    command_name: str,
) -> None:
    """Add local AWS profile discovery."""
    profiles = subparsers.add_parser(
        command_name,
        help="List local AWS profile names without reading credential values.",
    )
    add_debug_argument(profiles)
    profiles.add_argument("--json", action="store_true", help="Print profile names as JSON.")


def add_scanners_command(
    subparsers: argparse._SubParsersAction,
    command_name: str,
) -> None:
    """Add collector-safe scanner catalogue output."""
    scanners = subparsers.add_parser(
        command_name,
        help="List AWS collector scanner metadata.",
    )
    add_debug_argument(scanners)
    scanners.add_argument("--json", action="store_true", help="Print scanner metadata as JSON.")


def add_package_plan_command(
    subparsers: argparse._SubParsersAction,
    command_name: str,
) -> None:
    """Add the collector package-closure validation command."""
    package_plan = subparsers.add_parser(
        command_name,
        help="Write the validated collector package closure.",
    )
    add_debug_argument(package_plan)
    package_plan.add_argument(
        "--output",
        default=None,
        help="Optional JSON path for the collector package plan.",
    )


__all__ = [
    "add_collect_command",
    "add_package_plan_command",
    "add_permission_preview_command",
    "add_policy_command",
    "add_privacy_command",
    "add_profiles_command",
    "add_scanners_command",
    "add_validate_bundle_command",
    "add_version_command",
]
