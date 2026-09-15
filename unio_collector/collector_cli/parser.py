from __future__ import annotations  # noqa: D100

import argparse

from unio_collector import __version__
from unio_collector.collector_cli.catalogue import COLLECTOR_COMMAND_CATALOGUE
from unio_collector.collector_cli.parser_arguments import add_debug_argument


def build_parser() -> argparse.ArgumentParser:
    """Build the standalone collector parser."""
    parser = argparse.ArgumentParser(
        prog="unio-collector",
        description="Unio Collector standalone read-only evidence collector.",
    )
    add_debug_argument(parser)
    parser.add_argument(
        "--version",
        action="version",
        version=f"unio-collector {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in COLLECTOR_COMMAND_CATALOGUE:
        command.parser_builder(subparsers, command.name)
    return parser


__all__ = ["build_parser"]
