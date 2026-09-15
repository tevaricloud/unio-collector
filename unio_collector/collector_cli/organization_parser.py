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


def add_organization_command(
    subparsers: argparse._SubParsersAction,
    command_name: str,
) -> None:
    """Add the collector-safe AWS organization command subset."""
    organization = subparsers.add_parser(
        command_name,
        help="Plan, collect, or validate explicit AWS Organization scope.",
    )
    commands = organization.add_subparsers(dest="organization_command", required=True)
    for name in ("plan", "collect"):
        command = commands.add_parser(name)
        add_debug_argument(command)
        add_collection_scope_arguments(command)
        add_region_arguments(command)
        add_scanner_arguments(command)
        add_runtime_arguments(command)
        add_bundle_minimisation_arguments(command)
        command.add_argument("--output", default="organizations")
        command.add_argument("--organization-fixture", default=None)
        command.add_argument("--probe-roles", action="store_true")
        command.add_argument("--resume", action="store_true")
        command.add_argument("--retry-failed-account", action="append", default=[])
        command.add_argument("--organization-signing-private-key", default=None)
        command.add_argument("--organization-signing-key-id", default=None)
    validate = commands.add_parser("validate")
    add_debug_argument(validate)
    validate.add_argument("--envelope", required=True)
    validate.add_argument("--trusted-public-key", default=None)
    validate.add_argument("--require-signed", action="store_true")


__all__ = ["add_organization_command"]
