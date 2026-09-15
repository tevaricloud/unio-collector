from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.collector.package.imports.forbidden_import import (
        CollectorForbiddenImport,
    )


@dataclass(frozen=True)
class CollectorImportClosureResult:
    """Resolved source and dependency closure for the collector artifact."""

    modules: tuple[str, ...]
    source_files: tuple[str, ...]
    external_imports: tuple[str, ...]
    required_distributions: tuple[str, ...]
    unresolved_imports: tuple[str, ...]
    forbidden_imports: tuple[str, ...]
    forbidden_import_details: tuple[CollectorForbiddenImport, ...]
    non_permitted_imports: tuple[str, ...]
    non_permitted_import_details: tuple[CollectorForbiddenImport, ...]
    missing_dependencies: tuple[str, ...]
    dynamic_factory_errors: tuple[str, ...]
    scanner_class_path_modules: tuple[str, ...]
    scanner_class_path_source_files: tuple[str, ...]
    scanner_class_path_errors: tuple[str, ...]

    @property
    def validation_errors(self) -> tuple[str, ...]:
        """Return all import-closure failures."""
        return (
            *(f"Unresolved internal import: {item}" for item in self.unresolved_imports),
            *(detail.format_message() for detail in self.forbidden_import_details),
            *(self._format_non_permitted_import(detail) for detail in self.non_permitted_import_details),
            *(f"Missing collector dependency: {item}" for item in self.missing_dependencies),
            *self.dynamic_factory_errors,
            *self.scanner_class_path_errors,
        )

    def _format_non_permitted_import(
        self,
        detail: CollectorForbiddenImport,
    ) -> str:
        chain = " -> ".join(detail.import_chain)
        return (
            "Non-permitted collector import: "
            f"{detail.importing_module} ({detail.importing_file}) imports "
            f"{detail.prohibited_module}; allowed prefixes are "
            f"{detail.prohibited_prefix}; chain: {chain}"
        )
