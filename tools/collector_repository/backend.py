"""PEP 517 adapter that builds only the authoritative collector runtime plan."""

from __future__ import annotations

import tomllib
from importlib import import_module
from pathlib import Path

from tools.collector_repository.paths import require


def get_requires_for_build_wheel(config_settings: dict[str, object] | None = None) -> list[str]:
    """Install the dependencies needed to evaluate the collector package plan."""
    require(not config_settings, "Collector builds do not accept backend overrides.")
    project = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))["project"]
    return [str(item) for item in project["dependencies"]]


def build_wheel(wheel_directory: str, config_settings: dict[str, object] | None = None, metadata_directory: str | None = None) -> str:
    """Build from external staging, excluding repository-only build support."""
    require(not config_settings and metadata_directory is None, "Collector builds do not accept backend metadata or configuration overrides.")
    builder = import_module("unio_collector.collector.package.wheel.builder").CollectorWheelBuilder()
    result = builder.build(root=Path.cwd(), output_dir=Path(wheel_directory).resolve())
    return str(result.wheel_path.name)
