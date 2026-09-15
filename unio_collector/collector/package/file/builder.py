from __future__ import annotations  # noqa: D100

from dataclasses import replace
from pathlib import Path

from unio_collector.collector.package.file.plan import CollectorPackageFilePlan
from unio_collector.collector.package.imports.closure import CollectorImportClosure
from unio_collector.collector.package.manifest import (
    CollectorPackageManifest,
    build_collector_package_manifest,
)


class CollectorPackageFilePlanBuilder:
    """Build the validated source closure for a collector-only artifact."""

    def build(  # noqa: D102
        self,
        *,
        root: Path | None = None,
        manifest: CollectorPackageManifest | None = None,
    ) -> CollectorPackageFilePlan:
        resolved_root = root or Path()
        if not (resolved_root / "unio_collector").is_dir():
            resolved_root = Path(__file__).resolve().parents[4]
        resolved_manifest = manifest or build_collector_package_manifest(
            root=resolved_root,
        )
        closure = CollectorImportClosure().build(
            root=resolved_root,
            manifest=resolved_manifest,
        )
        if manifest is None:
            required = set(closure.required_distributions)
            resolved_manifest = replace(
                resolved_manifest,
                required_dependencies=tuple(dependency for dependency in resolved_manifest.required_dependencies if _dependency_name(dependency) in required),
            )
        source_files = sorted(set(closure.source_files) | set(resolved_manifest.typing_source_files))
        for name in resolved_manifest.typing_source_files:
            path = resolved_root / name
            if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(resolved_root.resolve()):
                message = f"Collector typing contract is missing or unsafe: {name}"
                raise ValueError(message)
        excluded_files: list[str] = []
        for path in sorted((resolved_root / "unio_collector").rglob("*.py")):
            relative_path = path.relative_to(resolved_root).as_posix()
            if relative_path == "unio_collector/__init__.py":
                continue
            module = self._module_name(path.relative_to(resolved_root))
            if self._is_excluded(module, resolved_manifest):
                excluded_files.append(relative_path)
                continue
            if relative_path in source_files:
                continue
            if self._is_included(module, resolved_manifest):
                excluded_files.append(relative_path)
        metadata_files = [path for path in resolved_manifest.metadata_files if (resolved_root / path).exists()]
        return CollectorPackageFilePlan(
            manifest=resolved_manifest,
            source_files=tuple(source_files),
            metadata_files=tuple(metadata_files),
            excluded_source_files=tuple(excluded_files),
            import_closure=closure,
        )

    def _module_name(self, path: Path) -> str:
        return path.with_suffix("").as_posix().replace("/", ".")

    def _is_included(
        self,
        module: str,
        manifest: CollectorPackageManifest,
    ) -> bool:
        return any(module == prefix or module.startswith(f"{prefix}.") for prefix in manifest.include_package_prefixes)

    def _is_excluded(
        self,
        module: str,
        manifest: CollectorPackageManifest,
    ) -> bool:
        return any(module == prefix or module.startswith(f"{prefix}.") for prefix in manifest.exclude_package_prefixes)


def _dependency_name(requirement: str) -> str:
    return requirement.split("[", maxsplit=1)[0].split(">", maxsplit=1)[0].split("=", maxsplit=1)[0].strip()
