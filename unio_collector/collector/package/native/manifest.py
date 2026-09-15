from __future__ import annotations  # noqa: D100

import platform
from dataclasses import asdict, dataclass
from typing import Any

from unio_collector.collector.package.manifest import CollectorPackageManifest, build_collector_package_manifest
from unio_collector.collector.package.native.target import NativeCollectorTarget

NATIVE_COLLECTOR_SCHEMA_VERSION = "2026-08-native-v1"


@dataclass(frozen=True)
class NativeCollectorManifest:
    """Additive native release contract derived from the collector wheel."""

    artifact_name: str
    version: str
    schema_version: str
    distribution_model: str
    wheel_distribution_model: str
    entrypoints: dict[str, str]
    targets: tuple[NativeCollectorTarget, ...]
    forbidden_package_prefixes: tuple[str, ...]
    runtime_dependencies: tuple[str, ...]
    build_dependencies: tuple[str, ...]
    signing_hooks: tuple[str, ...]
    automatic_update_enabled: bool = False
    network_version_check: str = "manual_signed_metadata_only"
    tcl_tk_bundling_required: bool = True

    def convert_to_dict(self) -> dict[str, Any]:
        """Return deterministic manifest data."""
        return asdict(self)

    def validate(self) -> tuple[str, ...]:
        """Validate compatibility and release safety invariants."""
        errors: list[str] = []
        if self.entrypoints.get("unio-collector") != "unio_collector.collector_cli.app:main":
            errors.append("The native distribution must preserve unio-collector.")
        if self.entrypoints.get("Unio Collector") != "unio_collector.collector_launcher.app:main":
            errors.append("The native distribution must include the guided launcher.")
        if self.automatic_update_enabled:
            errors.append("The native collector must not update automatically.")
        expected_targets = {
            ("windows", "x86_64"),
            ("macos", "x86_64"),
            ("macos", "arm64"),
            ("linux", "x86_64"),
        }
        actual_targets = {(target.operating_system, target.architecture) for target in self.targets}
        if actual_targets != expected_targets:
            errors.append("Native target inventory does not match the initial release baseline.")
        return tuple(errors)


def build_native_collector_manifest(
    wheel_manifest: CollectorPackageManifest | None = None,
) -> NativeCollectorManifest:
    """Build the native contract from the authoritative collector wheel manifest."""
    collector = wheel_manifest or build_collector_package_manifest()
    return NativeCollectorManifest(
        artifact_name=collector.artifact_name,
        version=collector.version,
        schema_version=NATIVE_COLLECTOR_SCHEMA_VERSION,
        distribution_model="pyinstaller_onedir",
        wheel_distribution_model=collector.distribution_model,
        entrypoints={
            "Unio Collector": "unio_collector.collector_launcher.app:main",
            "unio-collector": "unio_collector.collector_cli.app:main",
        },
        targets=(
            NativeCollectorTarget("windows", "x86_64", "zip", "msi"),
            NativeCollectorTarget("macos", "x86_64", "tar.gz", "pkg"),
            NativeCollectorTarget("macos", "arm64", "tar.gz", "pkg"),
            NativeCollectorTarget("linux", "x86_64", "tar.gz", "deb"),
        ),
        forbidden_package_prefixes=collector.exclude_package_prefixes,
        runtime_dependencies=collector.required_dependencies,
        build_dependencies=("PyInstaller==6.22.2",),
        signing_hooks=(
            "windows_authenticode",
            "macos_codesign_notarize_staple",
            "linux_detached_gpg",
        ),
    )


def current_native_target() -> tuple[str, str]:
    """Return normalized current host target metadata."""
    system = platform.system().casefold()
    operating_system = {"darwin": "macos"}.get(system, system)
    machine = platform.machine().casefold()
    architecture = {"amd64": "x86_64", "aarch64": "arm64"}.get(machine, machine)
    return operating_system, architecture


__all__ = [
    "NATIVE_COLLECTOR_SCHEMA_VERSION",
    "NativeCollectorManifest",
    "NativeCollectorTarget",
    "build_native_collector_manifest",
    "current_native_target",
]
