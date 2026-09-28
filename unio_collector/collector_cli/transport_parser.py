"""Collector recipient-encrypted transport parser."""

from __future__ import annotations

from typing import TYPE_CHECKING

from unio_collector.collector_cli.parser_arguments import add_debug_argument

if TYPE_CHECKING:
    import argparse


def add_encrypt_bundle_command(
    subparsers: argparse._SubParsersAction,
    command_name: str,
) -> None:
    """Add recipient-encrypted evidence transport packaging."""
    encrypt = subparsers.add_parser(
        command_name,
        help="Encrypt a validated evidence bundle for a configured recipient.",
    )
    add_debug_argument(encrypt)
    encrypt.add_argument("--bundle", required=True, help="Input evidence bundle ZIP.")
    encrypt.add_argument(
        "--recipient-public-key",
        required=True,
        help="Recipient RSA public-key PEM path.",
    )
    encrypt.add_argument(
        "--recipient-key-id",
        required=True,
        help="Recipient key identifier recorded for rotation and exact key selection.",
    )
    encrypt.add_argument(
        "--output",
        required=True,
        help="Encrypted transport package output path (recommended suffix: .uet).",
    )
    encrypt.add_argument(
        "--overwrite",
        action="store_true",
        help="Replace an existing regular output file atomically.",
    )
    encrypt.add_argument(
        "--json",
        action="store_true",
        help="Print non-sensitive machine-readable result metadata.",
    )


__all__ = ["add_encrypt_bundle_command"]
