from __future__ import annotations  # noqa: D100

import argparse

from unio_collector.collector.config.constants import SCAN_MODES
from unio_collector.collector.config.presets import SCAN_PRESET_IDS
from unio_collector.config.scan.modes import SCAN_MODE_IDS
from unio_collector.config.scan.profiles import SCAN_DETAIL_PROFILE_IDS
from unio_collector.scanners.pillars import SCAN_PILLAR_IDS


def add_collection_scope_arguments(parser: argparse.ArgumentParser) -> None:
    """Add collector-safe provider, config, and period arguments."""
    parser.add_argument("--provider", choices=("aws",), default=None)
    parser.add_argument("--profile", default=None, help="Local AWS profile.")
    parser.add_argument("--days", type=int, default=None, help="Window in days.")
    parser.add_argument("--months", type=int, default=None, help="Window in months.")
    parser.add_argument("--years", type=int, default=None, help="Window in years.")
    parser.add_argument("--date-from", default=None, help="Start date, YYYY-MM-DD.")
    parser.add_argument("--date-to", default=None, help="End date, YYYY-MM-DD.")
    parser.add_argument("--fixture", default=None, help="Local fixture JSON path.")
    parser.add_argument("--config", default=None, help="Optional YAML config path.")
    parser.add_argument("--strict-config", action="store_true")
    parser.add_argument("--preset", choices=SCAN_PRESET_IDS, default=None)
    parser.add_argument("--scan-mode", choices=SCAN_MODE_IDS, default=None)
    parser.add_argument("--mode", choices=SCAN_MODES, default=None)
    parser.add_argument("--required-tag", action="append", default=[])
    parser.add_argument("--group-costs-by", default=None)
    parser.add_argument("--cur-path", action="append", default=[])
    parser.add_argument("--quiet", action="store_true", help="Reduce output.")
    parser.add_argument("--verbose", action="store_true", help="Show more detail.")
    parser.add_argument("--compact-progress", action="store_true")


def add_region_arguments(parser: argparse.ArgumentParser) -> None:
    """Add region/location selection arguments."""
    parser.add_argument("--region", action="append", default=[])
    parser.add_argument("--regions", default=None)
    parser.add_argument("--regions-from-billing", action="store_true")
    parser.add_argument("--global-only", action="store_true")
    parser.add_argument("--include-global", action="store_true")


def add_scanner_arguments(parser: argparse.ArgumentParser) -> None:
    """Add collector-safe scanner selection arguments."""
    parser.add_argument("--allow-chargeable-scanners", action="store_true")
    parser.add_argument("--force-service-scanners", action="store_true")
    parser.add_argument(
        "--scan-pillar",
        action="append",
        choices=SCAN_PILLAR_IDS,
        default=[],
    )
    parser.add_argument(
        "--scan-detail-profile",
        choices=SCAN_DETAIL_PROFILE_IDS,
        default=None,
        help=(
            "Select scanner evidence depth. When explicitly supplied, this "
            "overrides conflicting profile-owned scanner YAML values for the "
            "current invocation; unrelated scanner settings remain unchanged."
        ),
    )
    parser.add_argument("--disable-scanner", action="append", default=[])
    parser.add_argument("--enable-scanner", action="append", default=[])
    parser.add_argument("--only-scanner", action="append", default=[])


def add_runtime_arguments(parser: argparse.ArgumentParser) -> None:
    """Add collector-safe runtime tuning arguments."""
    parser.add_argument("--scan-max-workers", type=int, default=None)
    parser.add_argument("--scanner-max-workers", type=int, default=None)
    parser.add_argument("--aws-max-pool-connections", type=int, default=None)
    parser.add_argument("--aws-total-max-attempts", type=int, default=None)
    parser.add_argument("--aws-connect-timeout-seconds", type=int, default=None)
    parser.add_argument("--aws-read-timeout-seconds", type=int, default=None)


def add_bundle_minimisation_arguments(parser: argparse.ArgumentParser) -> None:
    """Add evidence-bundle minimisation flags."""
    parser.add_argument("--exclude-service", action="append", default=[])
    parser.add_argument("--no-cost-data", action="store_true")
    parser.add_argument("--minimise-export", choices=("none", "standard"), default="none")
    parser.add_argument("--redact-before-export", action="store_true")


def add_debug_argument(parser: argparse.ArgumentParser) -> None:
    """Add the shared debug flag."""
    parser.add_argument(
        "--debug",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Show tracebacks for unexpected collector CLI failures.",
    )


__all__ = [
    "add_bundle_minimisation_arguments",
    "add_collection_scope_arguments",
    "add_debug_argument",
    "add_region_arguments",
    "add_runtime_arguments",
    "add_scanner_arguments",
]
