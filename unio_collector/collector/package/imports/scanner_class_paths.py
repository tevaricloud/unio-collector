from __future__ import annotations  # noqa: D100

import ast
from dataclasses import dataclass
from typing import TYPE_CHECKING

from unio_collector.scanners.collection.class_paths import COLLECTOR_SCANNER_CLASS_PATHS

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path


@dataclass(frozen=True)
class CollectorScannerClassPathClosure:
    """Validated scanner class-path modules required by the collector wheel."""

    modules: tuple[str, ...]
    source_files: tuple[str, ...]
    errors: tuple[str, ...]


def build_scanner_class_path_closure(
    *,
    root: Path,
    module_index: Mapping[str, Path],
    exclude_package_prefixes: tuple[str, ...],
    scanner_class_paths: Mapping[str, str] | None = None,
) -> CollectorScannerClassPathClosure:
    """Validate collector scanner class paths and return required modules."""
    paths = COLLECTOR_SCANNER_CLASS_PATHS if scanner_class_paths is None else scanner_class_paths
    modules: set[str] = set()
    errors: list[str] = []
    for scanner_id, class_path in sorted(paths.items()):
        if not scanner_id:
            errors.append("Collector scanner class path has an empty scanner id.")
        module_name, separator, attribute_name = class_path.partition(":")
        if not separator or not module_name or not attribute_name:
            errors.append(
                f"Collector scanner class path for {scanner_id!r} must use module:attribute shape: {class_path!r}.",
            )
            continue
        if _is_forbidden(module_name, exclude_package_prefixes):
            errors.append(
                f"Collector scanner class path for {scanner_id!r} references forbidden module: {module_name}.",
            )
            continue
        path = module_index.get(module_name)
        if path is None:
            errors.append(
                f"Collector scanner class path for {scanner_id!r} references missing module: {module_name}.",
            )
            continue
        if not _module_defines_attribute(path, attribute_name):
            errors.append(
                f"Collector scanner class path for {scanner_id!r} references missing attribute: {class_path}.",
            )
        modules.add(module_name)
    source_files = tuple(
        sorted(module_index[module].relative_to(root).as_posix() for module in modules),
    )
    return CollectorScannerClassPathClosure(
        modules=tuple(sorted(modules)),
        source_files=source_files,
        errors=tuple(errors),
    )


def _is_forbidden(
    module_name: str,
    exclude_package_prefixes: tuple[str, ...],
) -> bool:
    return any(module_name == prefix or module_name.startswith(f"{prefix}.") for prefix in exclude_package_prefixes)


def _module_defines_attribute(path: Path, attribute_name: str) -> bool:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return any(isinstance(node, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef) and node.name == attribute_name for node in tree.body)
