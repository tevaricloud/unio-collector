from __future__ import annotations  # noqa: D100

import argparse
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from unio_collector.collector_cli.command_parsers import (
    add_collect_command,
    add_package_plan_command,
    add_permission_preview_command,
    add_policy_command,
    add_privacy_command,
    add_profiles_command,
    add_scanners_command,
    add_validate_bundle_command,
    add_version_command,
)
from unio_collector.collector_cli.doctor_parser import add_doctor_command
from unio_collector.collector_cli.organization_parser import add_organization_command

ParserBuilder = Callable[[argparse._SubParsersAction, str], None]  # noqa: SLF001
ServiceBuilder = Callable[[Any], Any]


@dataclass(frozen=True)
class CollectorCommandSpec:
    """Associate one public command with its parser and deferred service."""

    name: str
    parser_builder: ParserBuilder
    service_builder: ServiceBuilder
    subcommands: tuple[str, ...] = ()


def _build_collect_service(console: Any) -> Any:  # noqa: ANN401
    from unio_collector.collector_cli.services.collect import CollectorCollectService  # noqa: PLC0415

    return CollectorCollectService(console)


def _build_validate_bundle_service(console: Any) -> Any:  # noqa: ANN401
    from unio_collector.collector_cli.services.validate_bundle import CollectorValidateBundleService  # noqa: PLC0415

    return CollectorValidateBundleService(console)


def _build_doctor_service(console: Any) -> Any:  # noqa: ANN401
    from unio_collector.collector_cli.services.doctor import CollectorDoctorService  # noqa: PLC0415

    return CollectorDoctorService(console)


def _build_permission_policy_service(console: Any) -> Any:  # noqa: ANN401
    from unio_collector.collector_cli.services.permission.plan import CollectorPermissionPolicyService  # noqa: PLC0415

    return CollectorPermissionPolicyService(console)


def _build_permission_preview_service(console: Any) -> Any:  # noqa: ANN401
    from unio_collector.collector_cli.services.permission.preview import CollectorPermissionPreviewService  # noqa: PLC0415

    return CollectorPermissionPreviewService(console)


def _build_privacy_service(console: Any) -> Any:  # noqa: ANN401
    from unio_collector.collector_cli.services.privacy import CollectorPrivacyService  # noqa: PLC0415

    return CollectorPrivacyService(console)


def _build_version_service(console: Any) -> Any:  # noqa: ANN401
    from unio_collector.collector_cli.services.version import CollectorVersionService  # noqa: PLC0415

    return CollectorVersionService(console)


def _build_profiles_service(console: Any) -> Any:  # noqa: ANN401
    from unio_collector.collector_cli.services.profiles import CollectorProfilesService  # noqa: PLC0415

    return CollectorProfilesService(console)


def _build_scanners_service(console: Any) -> Any:  # noqa: ANN401
    from unio_collector.collector_cli.services.scanners import CollectorScannersService  # noqa: PLC0415

    return CollectorScannersService(console)


def _build_package_plan_service(console: Any) -> Any:  # noqa: ANN401
    from unio_collector.collector_cli.services.package_plan import CollectorPackagePlanService  # noqa: PLC0415

    return CollectorPackagePlanService(console)


def _build_organization_service(console: Any) -> Any:  # noqa: ANN401
    from unio_collector.collector_cli.services.organization import CollectorOrganizationService  # noqa: PLC0415

    return CollectorOrganizationService(console)


COLLECTOR_COMMAND_CATALOGUE = (
    CollectorCommandSpec("collect", add_collect_command, _build_collect_service),
    CollectorCommandSpec(
        "organization",
        add_organization_command,
        _build_organization_service,
        ("plan", "collect", "validate"),
    ),
    CollectorCommandSpec(
        "validate-bundle",
        add_validate_bundle_command,
        _build_validate_bundle_service,
    ),
    CollectorCommandSpec("doctor", add_doctor_command, _build_doctor_service),
    CollectorCommandSpec(
        "policy",
        add_policy_command,
        _build_permission_policy_service,
        ("aws",),
    ),
    CollectorCommandSpec(
        "permission-preview",
        add_permission_preview_command,
        _build_permission_preview_service,
    ),
    CollectorCommandSpec(
        "privacy",
        add_privacy_command,
        _build_privacy_service,
        ("protect", "preview", "rekey-vault", "inspect", "restore-report"),
    ),
    CollectorCommandSpec("version", add_version_command, _build_version_service),
    CollectorCommandSpec("profiles", add_profiles_command, _build_profiles_service),
    CollectorCommandSpec("scanners", add_scanners_command, _build_scanners_service),
    CollectorCommandSpec(
        "package-plan",
        add_package_plan_command,
        _build_package_plan_service,
    ),
)


def collector_command_names() -> tuple[str, ...]:
    """Return public collector command names in registration order."""
    return tuple(spec.name for spec in COLLECTOR_COMMAND_CATALOGUE)


def find_collector_command(name: str) -> CollectorCommandSpec | None:
    """Find one collector command without introducing a mutable registry."""
    return next(
        (spec for spec in COLLECTOR_COMMAND_CATALOGUE if spec.name == name),
        None,
    )


__all__ = [
    "COLLECTOR_COMMAND_CATALOGUE",
    "CollectorCommandSpec",
    "collector_command_names",
    "find_collector_command",
]
