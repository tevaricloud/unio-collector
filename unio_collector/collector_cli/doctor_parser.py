from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.collector_cli.parser_arguments import (
    add_collection_scope_arguments,
    add_debug_argument,
    add_region_arguments,
    add_runtime_arguments,
    add_scanner_arguments,
)

if TYPE_CHECKING:
    import argparse


def add_doctor_command(
    subparsers: argparse._SubParsersAction,
    command_name: str,
) -> None:
    """Add collector-safe local preflight checks."""
    doctor = subparsers.add_parser(
        command_name,
        help="Run collector-safe local preflight checks.",
    )
    add_debug_argument(doctor)
    add_collection_scope_arguments(doctor)
    add_region_arguments(doctor)
    add_scanner_arguments(doctor)
    add_runtime_arguments(doctor)
    doctor.add_argument(
        "--output",
        default="evidence-bundle.zip",
        help="Bundle path used for output writability checks.",
    )
    doctor.add_argument(
        "--check-identity",
        action="store_true",
        help="Run an explicit read-only identity check where supported.",
    )
    doctor.add_argument(
        "--json-output",
        default=None,
        help="Optional deterministic JSON doctor output path.",
    )


__all__ = ["add_doctor_command"]
