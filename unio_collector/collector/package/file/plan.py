from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.collector.package.imports.result import CollectorImportClosureResult
    from unio_collector.collector.package.manifest import CollectorPackageManifest

from unio_collector.collector.package.provider_boundary import CollectorProviderBoundary


@dataclass(frozen=True)
class CollectorPackageFilePlan:
    """Deterministic source and dependency closure for the collector artifact."""

    manifest: CollectorPackageManifest
    source_files: tuple[str, ...]
    metadata_files: tuple[str, ...]
    excluded_source_files: tuple[str, ...]
    import_closure: CollectorImportClosureResult

    def convert_to_dict(self) -> dict[str, Any]:  # noqa: D102
        manifest_payload = self.manifest.convert_to_dict()
        validation_errors = self.validate()
        provider_violations = self.provider_implementation_violations()
        return {
            "artifact_name": self.manifest.artifact_name,
            "collector_package_name": self.manifest.artifact_name,
            "version": self.manifest.version,
            "manifest": manifest_payload,
            "supported_commands": manifest_payload["supported_commands"],
            "entrypoints": manifest_payload["entrypoints"],
            "optional_dependencies": manifest_payload["optional_dependencies"],
            "required_dependencies": manifest_payload["required_dependencies"],
            "expected_commands": manifest_payload["expected_commands"],
            "included_provider_implementations": manifest_payload["included_provider_implementations"],
            "included_data_files": manifest_payload["included_data_files"],
            "included_schema_files": manifest_payload["included_schema_files"],
            "platform_considerations": manifest_payload["platform_considerations"],
            "warnings": manifest_payload["warnings"],
            "known_limitations": manifest_payload["known_limitations"],
            "source_files": list(self.source_files),
            "metadata_files": list(self.metadata_files),
            "excluded_source_files": list(self.excluded_source_files),
            "permitted_package_prefixes": list(
                self.manifest.include_package_prefixes,
            ),
            "validation_status": "valid" if not validation_errors else "invalid",
            "validation_checks": {
                "manifest": "passed" if not self.manifest.validate() else "failed",
                "package_content": "passed" if not validation_errors else "failed",
                "import_closure": ("passed" if not self.import_closure.validation_errors else "failed"),
                "dynamic_factories": ("passed" if not self.import_closure.dynamic_factory_errors else "failed"),
                "scanner_class_paths": ("passed" if not self.import_closure.scanner_class_path_errors else "failed"),
                "provider_implementations": ("passed" if not provider_violations else "failed"),
            },
            "validation_errors": validation_errors,
            "missing_dependencies": list(self.import_closure.missing_dependencies),
            "unresolved_imports": list(self.import_closure.unresolved_imports),
            "forbidden_imports": list(self.import_closure.forbidden_imports),
            "forbidden_import_details": [item.convert_to_dict() for item in self.import_closure.forbidden_import_details],
            "non_permitted_imports": list(self.import_closure.non_permitted_imports),
            "non_permitted_import_details": [item.convert_to_dict() for item in self.import_closure.non_permitted_import_details],
            "external_imports": list(self.import_closure.external_imports),
            "resolved_modules": list(self.import_closure.modules),
            "scanner_class_path_modules": list(
                self.import_closure.scanner_class_path_modules,
            ),
            "scanner_class_path_source_files": list(
                self.import_closure.scanner_class_path_source_files,
            ),
            "scanner_class_path_errors": list(
                self.import_closure.scanner_class_path_errors,
            ),
            "provider_implementation_violations": list(provider_violations),
        }

    def validate(self) -> list[str]:  # noqa: D102
        errors = self.manifest.validate()
        errors.extend(self.import_closure.validation_errors)
        for path in self.source_files:
            module = self._module_name_from_path(path)
            for prefix in self.manifest.exclude_package_prefixes:
                if module == prefix or module.startswith(f"{prefix}."):
                    errors.append(
                        f"Collector package file plan includes excluded module: {module}",
                    )
            if module != "unio_collector" and not self._is_permitted_module(module):
                errors.append(
                    f"Collector package file plan includes non-permitted module: {module}",
                )
        errors.extend(
            f"Collector package file plan includes provider implementation outside included_provider_implementations: {module}"
            for module in self.provider_implementation_violations()
        )
        for required in ("unio_collector/collector/__init__.py", "unio_collector/__init__.py"):
            if required not in self.source_files:
                errors.append(f"Collector package file plan is missing {required}.")
        missing_scanner_files = sorted(
            set(self.import_closure.scanner_class_path_source_files) - set(self.source_files),
        )
        errors.extend(f"Collector package file plan is missing scanner implementation file: {path}." for path in missing_scanner_files)
        errors.extend(
            f"Collector package file plan is missing typing contract: {path}."
            for path in sorted(set(self.manifest.typing_source_files) - set(self.source_files))
        )
        return errors

    def provider_implementation_violations(self) -> tuple[str, ...]:
        """Return planned provider modules outside the manifest allow-list."""
        modules = tuple(self._module_name_from_path(path) for path in self.source_files)
        return CollectorProviderBoundary.from_manifest(
            self.manifest,
        ).module_violations(modules)

    def _module_name_from_path(self, path: str) -> str:
        if not path.endswith(".py"):
            return ""
        module = path[:-3].replace("/", ".")
        if module.endswith(".__init__"):
            return module.removesuffix(".__init__")
        return module

    def _is_permitted_module(self, module: str) -> bool:
        return any(module == prefix or module.startswith(f"{prefix}.") for prefix in self.manifest.include_package_prefixes)
