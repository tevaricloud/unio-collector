"""Parser registration for integrated protected collection."""

from __future__ import annotations

from typing import TYPE_CHECKING

from unio_collector.collector_cli.parser_arguments import (
    add_bundle_minimisation_arguments,
    add_collection_scope_arguments,
    add_debug_argument,
    add_environment_classification_argument,
    add_region_arguments,
    add_runtime_arguments,
    add_scanner_arguments,
)

if TYPE_CHECKING:
    import argparse


def add_collect_protected_command(
    subparsers: argparse._SubParsersAction,
    command_name: str,
) -> None:
    """Add the integrated protected evidence collection command."""
    collect = subparsers.add_parser(
        command_name,
        help="Collect and protect evidence in one fail-closed workflow.",
    )
    add_debug_argument(collect)
    add_collection_scope_arguments(collect)
    add_environment_classification_argument(collect)
    add_region_arguments(collect)
    add_scanner_arguments(collect)
    add_runtime_arguments(collect)
    add_bundle_minimisation_arguments(collect)
    collect.add_argument(
        "--output",
        "--protected-bundle",
        dest="output",
        default="protected-evidence-bundle.zip",
        help="Transferable protected evidence bundle output path.",
    )
    collect.add_argument(
        "--vault",
        default=None,
        help="Client-retained encrypted identity vault (default: derived sibling path).",
    )
    collect.add_argument(
        "--recovery-material",
        "--recovery-key",
        dest="recovery_key",
        default=None,
        help="Client-retained recovery-key output path.",
    )
    collect.add_argument(
        "--receipt-output",
        default=None,
        help="Completion receipt path (default: sibling of protected bundle).",
    )
    collect.add_argument(
        "--privacy-profile",
        choices=("standard", "strict", "custom"),
        default="standard",
    )
    collect.add_argument(
        "--environment-semantics",
        choices=("detailed", "coarse", "omit"),
        default=None,
        help="Transfer detailed, coarse, or no derived environment semantics.",
    )
    collect.add_argument(
        "--token-scope",
        choices=("bundle", "engagement", "client"),
        default="engagement",
    )
    collect.add_argument("--engagement-id", default="default-engagement")
    collect.add_argument("--client-id", default=None)
    collect.add_argument("--existing-vault", default=None)
    collect.add_argument("--existing-recovery-key", default=None)
    collect.add_argument(
        "--recovery-mode",
        choices=("passphrase", "recovery-key", "passphrase-and-key"),
        default=None,
    )
    passphrase = collect.add_mutually_exclusive_group()
    passphrase.add_argument(
        "--passphrase",
        default=None,
        help="DEPRECATED: vault passphrase; prefer file or redirected stdin.",
    )
    passphrase.add_argument("--passphrase-file", default=None)
    passphrase.add_argument("--passphrase-stdin", action="store_true")
    collect.add_argument("--allow-unknown-fields", action="store_true")
    collect.add_argument(
        "--acknowledge-vault-loss-risk",
        action="store_true",
        help="Acknowledge that vault and recovery material remain client-held.",
    )
    collect.add_argument(
        "--retain-raw-bundle",
        default=None,
        help="Advanced: explicitly retain raw evidence at this client-private path.",
    )
    collect.add_argument(
        "--temporary-directory",
        default=None,
        help="Existing client-private parent directory for temporary raw evidence.",
    )
    collect.add_argument("--overwrite", action="store_true")
    collect.add_argument("--fail-on-warning", action="store_true")
    collect.add_argument("--json", action="store_true", help="Print the structured workflow result as JSON.")
    collect.add_argument(
        "--progress-jsonl",
        default=None,
        help="Optional schema-versioned collection progress event path.",
    )


__all__ = ["add_collect_protected_command"]
