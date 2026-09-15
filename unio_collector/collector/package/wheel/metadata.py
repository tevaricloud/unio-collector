"""Shared project metadata for collector wheels and standalone source builds."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from unio_collector.collector.package.manifest import CollectorPackageManifest


class CollectorProjectMetadata:
    """Render only the existing collector distribution contract."""

    def render(
        self,
        manifest: CollectorPackageManifest,
        *,
        licensed: bool = False,
        optional_dependencies: Mapping[str, Sequence[str]] | None = None,
    ) -> str:
        """Render a buildable collector project without application entrypoints."""
        dependencies = json.dumps(list(manifest.required_dependencies))
        licence = 'license = {file = "LICENSE"}\n' if licensed else ""
        extras = ""
        if optional_dependencies:
            extras = "\n[project.optional-dependencies]\n" + "".join(
                f"{json.dumps(name)} = {json.dumps(list(values))}\n" for name, values in sorted(optional_dependencies.items())
            )
        return (
            "[build-system]\n"
            'requires = ["setuptools>=68", "wheel"]\n'
            'build-backend = "setuptools.build_meta"\n\n'
            "[project]\n"
            'name = "unio-collector"\n'
            f'version = "{manifest.version}"\n'
            'description = "Standalone read-only AWS evidence collector"\n'
            'readme = "README.md"\n'
            'requires-python = ">=3.12"\n'
            f"dependencies = {dependencies}\n"
            f"{licence}\n"
            "[project.scripts]\n"
            'unio-collector = "unio_collector.collector_cli.app:main"\n\n'
            "[tool.setuptools.packages.find]\n"
            'include = ["unio_collector*"]\n'
            f"{extras}"
        )
