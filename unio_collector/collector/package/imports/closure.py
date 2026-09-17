from __future__ import annotations  # noqa: D100

import ast
import sys
from collections import deque
from typing import TYPE_CHECKING

from unio_collector.collector.package.imports.forbidden_import import CollectorForbiddenImport
from unio_collector.collector.package.imports.result import CollectorImportClosureResult
from unio_collector.collector.package.imports.scanner_class_paths import (
    build_scanner_class_path_closure,
)
from unio_collector.collector.package.provider_boundary import CollectorProviderBoundary

if TYPE_CHECKING:
    from pathlib import Path

    from unio_collector.collector.package.manifest import CollectorPackageManifest

ENTRY_MODULES = (
    "unio_collector",
    "unio_collector.collector_cli.app",
    "unio_collector.collector_cli.parser",
    "unio_collector.collector.bundle.collection_writer",
    "unio_collector.collector.bundle.validator",
    "unio_collector.collector.execution.service",
    "unio_collector.collector.package.manifest",
    "unio_collector.scanners.analysis.boundary.builder",
)

IMPORT_TO_DISTRIBUTION = {
    "argon2": "argon2-cffi",
    "boto3": "boto3",
    "botocore": "boto3",
    "cryptography": "cryptography",
    "pydantic": "pydantic",
    "yaml": "PyYAML",
    "rich": "rich",
}


class CollectorImportClosure:
    """Calculate and validate the collector distribution import closure."""

    def build(  # noqa: C901
        self,
        *,
        root: Path,
        manifest: CollectorPackageManifest,
        entry_modules: tuple[str, ...] | None = None,
        scanner_class_paths: dict[str, str] | None = None,
    ) -> CollectorImportClosureResult:
        """Resolve collector runtime imports and declared dynamic factories."""
        module_index = self._build_module_index(root)
        roots: set[str] = set(ENTRY_MODULES if entry_modules is None else entry_modules)
        dynamic_errors: list[str] = []
        for factory_path in manifest.dynamic_factory_paths:
            module_name, separator, attribute_name = factory_path.partition(":")
            if not separator or not module_name or not attribute_name:
                dynamic_errors.append(
                    f"Dynamic factory path {factory_path!r} must use module:attribute shape.",
                )
                continue
            if module_name not in module_index:
                dynamic_errors.append(
                    f"Dynamic factory module is missing: {module_name}.",
                )
                continue
            if not self._module_defines_attribute(
                module_index[module_name],
                attribute_name,
            ):
                dynamic_errors.append(
                    f"Dynamic factory attribute is missing: {factory_path}.",
                )
            roots.add(module_name)
        scanner_paths = build_scanner_class_path_closure(
            root=root,
            module_index=module_index,
            exclude_package_prefixes=manifest.exclude_package_prefixes,
            scanner_class_paths=scanner_class_paths,
        )
        roots.update(scanner_paths.modules)
        queue: deque[tuple[str, tuple[str, ...]]] = deque((module, (module,)) for module in sorted(roots))
        visited: set[str] = set()
        requested_exports: dict[str, set[str]] = {}
        processed_requested_exports: dict[str, set[str]] = {}
        external: set[str] = set()
        unresolved: set[str] = set()
        forbidden_details: set[CollectorForbiddenImport] = set()
        non_permitted_details: set[CollectorForbiddenImport] = set()
        while queue:
            module_name, import_chain = queue.popleft()
            requested_names = set(requested_exports.get(module_name, set()))
            processed_names = processed_requested_exports.get(module_name, set())
            if module_name in visited and requested_names <= processed_names:
                continue
            path = module_index.get(module_name)
            if path is None:
                unresolved.add(module_name)
                continue
            prohibited_prefix = self._matched_forbidden_prefix(module_name, manifest)
            if prohibited_prefix:
                forbidden_details.add(
                    self._forbidden_detail(
                        root=root,
                        module_index=module_index,
                        importing_module=import_chain[-2] if len(import_chain) > 1 else module_name,
                        prohibited_module=module_name,
                        prohibited_prefix=prohibited_prefix,
                        import_chain=import_chain,
                    ),
                )
                continue
            permitted_prefix = self._matched_permitted_prefix(module_name, manifest)
            if not permitted_prefix:
                non_permitted_details.add(
                    self._non_permitted_detail(
                        root=root,
                        module_index=module_index,
                        importing_module=import_chain[-2] if len(import_chain) > 1 else module_name,
                        prohibited_module=module_name,
                        manifest=manifest,
                        import_chain=import_chain,
                    ),
                )
                continue
            visited.add(module_name)
            dynamic_exports = self._dynamic_export_modules(
                path,
                requested_names,
            )
            dynamic_imports = self._literal_dynamic_import_modules(path)
            for imported in self._runtime_imports(path, module_name) | dynamic_exports | dynamic_imports:
                if imported.startswith("unio_collector"):
                    resolved = self._resolve_internal(imported, module_index)
                    if resolved is None:
                        unresolved.add(imported)
                    elif prohibited_prefix := self._matched_forbidden_prefix(
                        resolved,
                        manifest,
                    ):
                        forbidden_details.add(
                            self._forbidden_detail(
                                root=root,
                                module_index=module_index,
                                importing_module=module_name,
                                prohibited_module=resolved,
                                prohibited_prefix=prohibited_prefix,
                                import_chain=(*import_chain, resolved),
                            ),
                        )
                    elif not self._matched_permitted_prefix(resolved, manifest):
                        non_permitted_details.add(
                            self._non_permitted_detail(
                                root=root,
                                module_index=module_index,
                                importing_module=module_name,
                                prohibited_module=resolved,
                                manifest=manifest,
                                import_chain=(*import_chain, resolved),
                            ),
                        )
                    else:
                        added_export_request = self._record_requested_export(
                            requested_exports,
                            imported=imported,
                            resolved=resolved,
                        )
                        if resolved not in visited or added_export_request:
                            queue.append((resolved, (*import_chain, resolved)))
                    continue
                top_level = imported.split(".", maxsplit=1)[0]
                if top_level and top_level not in sys.stdlib_module_names:
                    external.add(top_level)
            processed_requested_exports[module_name] = requested_names
            for parent in self._parent_packages(module_name, module_index):
                if parent not in visited:
                    queue.append((parent, (*import_chain, parent)))
        declared = {self._dependency_name(value) for value in manifest.required_dependencies}
        required_distributions = {IMPORT_TO_DISTRIBUTION.get(name, name) for name in external}
        missing_dependencies = sorted(required_distributions - declared)
        source_files = tuple(
            sorted(module_index[module].relative_to(root).as_posix() for module in visited),
        )
        forbidden_import_details = tuple(
            sorted(
                forbidden_details,
                key=lambda item: (
                    item.importing_module,
                    item.prohibited_module,
                    item.import_chain,
                ),
            ),
        )
        non_permitted_import_details = tuple(
            sorted(
                non_permitted_details,
                key=lambda item: (
                    item.importing_module,
                    item.prohibited_module,
                    item.import_chain,
                ),
            ),
        )
        return CollectorImportClosureResult(
            modules=tuple(sorted(visited)),
            source_files=source_files,
            external_imports=tuple(sorted(external)),
            required_distributions=tuple(sorted(required_distributions)),
            unresolved_imports=tuple(sorted(unresolved)),
            forbidden_imports=tuple(sorted({item.prohibited_module for item in forbidden_import_details})),
            forbidden_import_details=forbidden_import_details,
            non_permitted_imports=tuple(sorted({item.prohibited_module for item in non_permitted_import_details})),
            non_permitted_import_details=non_permitted_import_details,
            missing_dependencies=tuple(missing_dependencies),
            dynamic_factory_errors=tuple(dynamic_errors),
            scanner_class_path_modules=scanner_paths.modules,
            scanner_class_path_source_files=scanner_paths.source_files,
            scanner_class_path_errors=scanner_paths.errors,
        )

    def _build_module_index(self, root: Path) -> dict[str, Path]:
        index: dict[str, Path] = {}
        for path in sorted((root / "unio_collector").rglob("*.py")):
            relative = path.relative_to(root).with_suffix("")
            parts = list(relative.parts)
            if parts[-1] == "__init__":
                parts.pop()
            module_name = ".".join(parts)
            existing = index.get(module_name)
            if existing is not None and existing.name == "__init__.py":
                continue
            if existing is None or path.name == "__init__.py":
                index[module_name] = path
        return index

    def _runtime_imports(self, path: Path, module_name: str) -> set[str]:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        imports: set[str] = set()
        for node in self._walk_runtime_nodes(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                base = self._resolve_relative_module(
                    module_name,
                    node.module,
                    node.level,
                    path,
                )
                if not base:
                    continue
                imports.add(base)
                imports.update(f"{base}.{alias.name}" for alias in node.names)
        return imports

    def _dynamic_export_modules(
        self,
        path: Path,
        requested_names: set[str],
    ) -> set[str]:
        if not requested_names:
            return set()
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        modules: set[str] = set()
        for node in tree.body:
            value = self._assignment_value(node, "_EXPORTS")
            if value is None:
                value = self._assignment_value(node, "_EXPORT_MODULES")
            if not isinstance(value, ast.Dict):
                continue
            for key, item in zip(value.keys, value.values, strict=True):
                if not self._is_requested_export_key(key, requested_names):
                    continue
                module_name = self._module_string_value(item)
                if module_name:
                    modules.add(module_name)
        return modules

    def _literal_dynamic_import_modules(self, path: Path) -> set[str]:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        modules: set[str] = set()
        stack = list(getattr(tree, "body", ()))
        while stack:
            node = stack.pop()
            if isinstance(node, ast.If) and self._is_type_checking_test(node.test):
                stack.extend(node.orelse)
                continue
            if self._is_package_getattr_function(path, node):
                continue
            if not isinstance(node, ast.Call) or not node.args:
                stack.extend(ast.iter_child_nodes(node))
                continue
            if not self._is_dynamic_import_call(node.func):
                stack.extend(ast.iter_child_nodes(node))
                continue
            module_name = self._module_string_value(node.args[0])
            if module_name:
                modules.add(module_name)
            stack.extend(ast.iter_child_nodes(node))
        return modules

    def _is_package_getattr_function(self, path: Path, node: ast.AST) -> bool:
        return path.name == "__init__.py" and isinstance(node, ast.FunctionDef) and node.name == "__getattr__"

    def _is_dynamic_import_call(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in {
                "__import__",
                "_load_symbol",
                "import_module",
            }
        return isinstance(node, ast.Attribute) and node.attr == "import_module"

    def _module_string_value(self, node: ast.AST) -> str:
        module_item = node.elts[0] if isinstance(node, ast.Tuple) and node.elts else node
        if isinstance(module_item, ast.Constant) and isinstance(module_item.value, str) and module_item.value.startswith("unio_collector."):
            return module_item.value
        return ""

    def _assignment_value(self, node: ast.AST, name: str) -> ast.AST | None:
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == name for target in node.targets):
            return node.value
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == name:
            return node.value
        return None

    def _is_requested_export_key(
        self,
        node: ast.AST | None,
        requested_names: set[str],
    ) -> bool:
        return isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value in requested_names

    def _record_requested_export(
        self,
        requested_exports: dict[str, set[str]],
        *,
        imported: str,
        resolved: str,
    ) -> bool:
        if imported == resolved or not imported.startswith(f"{resolved}."):
            return False
        attribute_name = imported[len(resolved) + 1 :].split(".", maxsplit=1)[0]
        if not attribute_name:
            return False
        requested_names = requested_exports.setdefault(resolved, set())
        if attribute_name in requested_names:
            return False
        requested_names.add(attribute_name)
        return True

    def _walk_runtime_nodes(self, tree: ast.AST) -> list[ast.AST]:
        nodes: list[ast.AST] = []
        stack = list(getattr(tree, "body", ()))
        while stack:
            node = stack.pop()
            if isinstance(node, ast.If) and self._is_type_checking_test(node.test):
                stack.extend(node.orelse)
                continue
            nodes.append(node)
            stack.extend(ast.iter_child_nodes(node))
        return nodes

    def _resolve_internal(
        self,
        imported: str,
        module_index: dict[str, Path],
    ) -> str | None:
        candidate = imported
        while candidate.startswith("unio_collector"):
            if candidate in module_index:
                return candidate
            if "." not in candidate:
                break
            candidate = candidate.rsplit(".", maxsplit=1)[0]
        return None

    def _resolve_relative_module(
        self,
        current_module: str,
        imported_module: str | None,
        level: int,
        current_path: Path,
    ) -> str:
        if level == 0:
            return imported_module or ""
        package_parts = current_module.split(".")
        if current_path.name != "__init__.py":
            package_parts = package_parts[:-1]
        keep = max(0, len(package_parts) - level + 1)
        base = package_parts[:keep]
        if imported_module:
            base.extend(imported_module.split("."))
        return ".".join(base)

    def _parent_packages(
        self,
        module_name: str,
        module_index: dict[str, Path],
    ) -> tuple[str, ...]:
        parts = module_name.split(".")
        return tuple(parent for index in range(1, len(parts)) if (parent := ".".join(parts[:index])) in module_index)

    def _is_forbidden(
        self,
        module_name: str,
        manifest: CollectorPackageManifest,
    ) -> bool:
        return bool(self._matched_forbidden_prefix(module_name, manifest))

    def _matched_forbidden_prefix(
        self,
        module_name: str,
        manifest: CollectorPackageManifest,
    ) -> str:
        for prefix in manifest.exclude_package_prefixes:
            if module_name == prefix or module_name.startswith(f"{prefix}."):
                return prefix
        return ""

    def _matched_permitted_prefix(
        self,
        module_name: str,
        manifest: CollectorPackageManifest,
    ) -> str:
        if module_name == "unio_collector":
            return module_name
        if not CollectorProviderBoundary.from_manifest(manifest).is_module_allowed(
            module_name,
        ):
            return ""
        for prefix in manifest.include_package_prefixes:
            if module_name == prefix or module_name.startswith(f"{prefix}."):
                return prefix
        return ""

    def _forbidden_detail(
        self,
        *,
        root: Path,
        module_index: dict[str, Path],
        importing_module: str,
        prohibited_module: str,
        prohibited_prefix: str,
        import_chain: tuple[str, ...],
    ) -> CollectorForbiddenImport:
        importing_path = module_index.get(importing_module)
        importing_file = importing_path.relative_to(root).as_posix() if importing_path is not None else ""
        return CollectorForbiddenImport(
            importing_module=importing_module,
            importing_file=importing_file,
            prohibited_module=prohibited_module,
            prohibited_prefix=prohibited_prefix,
            import_chain=import_chain,
        )

    def _non_permitted_detail(
        self,
        *,
        root: Path,
        module_index: dict[str, Path],
        importing_module: str,
        prohibited_module: str,
        manifest: CollectorPackageManifest,
        import_chain: tuple[str, ...],
    ) -> CollectorForbiddenImport:
        importing_path = module_index.get(importing_module)
        importing_file = importing_path.relative_to(root).as_posix() if importing_path is not None else ""
        allowed = ", ".join(manifest.include_package_prefixes)
        return CollectorForbiddenImport(
            importing_module=importing_module,
            importing_file=importing_file,
            prohibited_module=prohibited_module,
            prohibited_prefix=allowed,
            import_chain=import_chain,
        )

    def _is_type_checking_test(self, node: ast.AST) -> bool:
        return isinstance(node, ast.Name) and node.id == "TYPE_CHECKING"

    def _module_defines_attribute(self, path: Path, attribute_name: str) -> bool:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        return any(isinstance(node, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef) and node.name == attribute_name for node in tree.body)

    def _dependency_name(self, requirement: str) -> str:
        return requirement.split("[", maxsplit=1)[0].split(">", maxsplit=1)[0].split("=", maxsplit=1)[0].strip()
