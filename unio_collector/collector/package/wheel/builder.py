from __future__ import annotations  # noqa: D100

import os
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import TYPE_CHECKING
from zipfile import ZipFile

from unio_collector.collector.package.file.materializer import (
    CollectorPackageSourceMaterializer,
)
from unio_collector.collector.package.manifest import (
    COLLECTOR_FORBIDDEN_PREFIXES,
    build_collector_package_file_plan,
)
from unio_collector.collector.package.provider_boundary import CollectorProviderBoundary
from unio_collector.collector.package.wheel.inspection import CollectorWheelInspectionResult
from unio_collector.collector.package.wheel.metadata import CollectorProjectMetadata
from unio_collector.collector.package.wheel.result import CollectorWheelBuildResult
from unio_collector.scanners.collection.class_paths import COLLECTOR_SCANNER_CLASS_PATHS

if TYPE_CHECKING:
    from collections.abc import Mapping

    from unio_collector.collector.package.file.plan import CollectorPackageFilePlan
    from unio_collector.collector.package.manifest import CollectorPackageManifest


class CollectorWheelBuilder:
    """Stage, build, and inspect the collector-only Python wheel."""

    def build(
        self,
        *,
        root: Path,
        output_dir: Path,
        plan: CollectorPackageFilePlan | None = None,
    ) -> CollectorWheelBuildResult:
        """Build the wheel from the validated collector package plan."""
        root = root.resolve()
        output_dir = output_dir.resolve()
        plan = plan or build_collector_package_file_plan(root=root)
        errors = plan.validate()
        if errors:
            msg = "Collector package plan is invalid: " + "; ".join(errors)
            raise RuntimeError(msg)
        output_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="unio-collector-build-") as raw:
            stage = Path(raw)
            CollectorPackageSourceMaterializer().materialize(
                root=root,
                destination=stage,
                plan=plan,
            )
            process_temp = stage / "process-temp"
            pip_cache = stage / "pip-cache"
            process_temp.mkdir()
            pip_cache.mkdir()
            standalone_readme = root / "tools" / "collector_export" / "assets" / "README.md"
            shutil.copy2(standalone_readme if standalone_readme.is_file() else root / "README.md", stage / "README.md")
            project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
            licensed = project.get("name") == "unio-collector" and project.get("license") == {"file": "LICENSE"}
            extras = project.get("optional-dependencies") if project.get("name") == "unio-collector" else None
            if licensed:
                shutil.copy2(root / "LICENSE", stage / "LICENSE")
            (stage / "pyproject.toml").write_text(
                CollectorProjectMetadata().render(plan.manifest, licensed=licensed, optional_dependencies=extras),
                encoding="utf-8",
            )
            environment = os.environ.copy()

            environment.pop("_PYPROJECT_HOOKS_BACKEND_PATH", None)
            environment.pop("_PYPROJECT_HOOKS_BUILD_BACKEND", None)
            environment.update(
                PIP_CACHE_DIR=str(pip_cache),
                TEMP=str(process_temp),
                TMP=str(process_temp),
                TMPDIR=str(process_temp),
            )
            subprocess.run(  # noqa: S603
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "wheel",
                    "--no-deps",
                    "--no-build-isolation",
                    "--wheel-dir",
                    str(output_dir),
                    str(stage),
                ],
                check=True,
                cwd=root,
                env=environment,
            )
        wheel_path = self._find_wheel(output_dir, plan.manifest.version)
        members = self.validate_existing_wheel(
            wheel_path=wheel_path,
            planned_source_files=plan.source_files,
            manifest=plan.manifest,
            scanner_class_paths=COLLECTOR_SCANNER_CLASS_PATHS,
        )
        return CollectorWheelBuildResult(
            wheel_path=wheel_path,
            source_file_count=len(plan.source_files),
            wheel_member_count=len(members),
            validation_status="valid",
        )

    def _build_pyproject(self, manifest: CollectorPackageManifest) -> str:

        return CollectorProjectMetadata().render(manifest)

    def _find_wheel(self, output_dir: Path, version: str) -> Path:
        matches = sorted(output_dir.glob(f"unio_collector-{version}-*.whl"))
        if len(matches) != 1:
            msg = f"Expected one collector wheel for version {version}, found {len(matches)}."
            raise RuntimeError(msg)
        return matches[0]

    def validate_existing_wheel(
        self,
        *,
        wheel_path: Path,
        planned_source_files: tuple[str, ...],
        manifest: CollectorPackageManifest,
        scanner_class_paths: Mapping[str, str] | None = None,
    ) -> tuple[str, ...]:
        """Validate an existing collector wheel against the package plan."""
        inspection = self.inspect_existing_wheel(
            wheel_path=wheel_path,
            planned_source_files=planned_source_files,
            manifest=manifest,
            scanner_class_paths=scanner_class_paths,
        )
        if inspection.missing_required_members:
            planned_missing = sorted(set(planned_source_files) & set(inspection.missing_required_members))
            scanner_missing = sorted(
                self._scanner_module_members(scanner_class_paths, planned_source_files=planned_source_files) & set(inspection.missing_required_members)
            )
            if planned_missing:
                msg = "Collector wheel is missing planned source files: " + ", ".join(
                    planned_missing[:10],
                )
                raise RuntimeError(msg)
            if scanner_missing:
                msg = "Collector wheel is missing scanner implementation modules: " + ", ".join(
                    scanner_missing[:10],
                )
                raise RuntimeError(msg)
            msg = "Collector wheel is missing required members: " + ", ".join(
                inspection.missing_required_members[:10],
            )
            raise RuntimeError(msg)
        if inspection.provider_implementation_members:
            msg = "Collector wheel contains provider implementations outside the manifest allow-list: " + ", ".join(
                inspection.provider_implementation_members[:10],
            )
            raise RuntimeError(msg)
        if inspection.unexpected_application_members:
            msg = "Collector wheel contains unplanned application modules: " + ", ".join(
                inspection.unexpected_application_members[:10],
            )
            raise RuntimeError(msg)
        if inspection.unexpected_wheel_members:
            msg = "Collector wheel contains unexpected wheel members: " + ", ".join(
                inspection.unexpected_wheel_members[:10],
            )
            raise RuntimeError(msg)
        if inspection.prohibited_members:
            msg = "Collector wheel contains forbidden modules: " + ", ".join(
                inspection.prohibited_members[:10],
            )
            raise RuntimeError(msg)
        if inspection.entrypoint_errors:
            msg = "Collector wheel entry-point inventory is invalid: " + "; ".join(
                inspection.entrypoint_errors,
            )
            raise RuntimeError(msg)
        if inspection.metadata_errors:
            msg = "; ".join(inspection.metadata_errors)
            raise RuntimeError(msg)
        return inspection.members

    def inspect_existing_wheel(
        self,
        *,
        wheel_path: Path,
        planned_source_files: tuple[str, ...],
        manifest: CollectorPackageManifest,
        scanner_class_paths: Mapping[str, str] | None = None,
    ) -> CollectorWheelInspectionResult:
        """Inspect an existing collector wheel and return structured diagnostics."""
        with ZipFile(wheel_path, "r") as archive:
            members = tuple(sorted(archive.namelist()))
        member_set = set(members)
        scanner_members = self._scanner_module_members(
            scanner_class_paths,
            planned_source_files=planned_source_files,
        )
        metadata_members = self._required_metadata_members(members, manifest)
        allowed_metadata_members = self._allowed_metadata_members(members, manifest)
        required_members = tuple(sorted(set(planned_source_files) | scanner_members | metadata_members))
        approved_members = set(planned_source_files) | scanner_members | allowed_metadata_members
        missing_required_members = tuple(sorted(set(required_members) - member_set))
        unexpected_wheel_members = tuple(sorted(member_set - approved_members))
        extra_application_members = tuple(member for member in unexpected_wheel_members if member.startswith("unio_collector/") and member.endswith(".py"))
        prohibited_members = tuple(
            member
            for member in members
            if any(member == f"{prefix.replace('.', '/')}.py" or member.startswith(f"{prefix.replace('.', '/')}/") for prefix in COLLECTOR_FORBIDDEN_PREFIXES)
        )
        provider_implementation_members = CollectorProviderBoundary.from_manifest(
            manifest,
        ).wheel_member_violations(members)
        entry_points = next(
            (member for member in members if member.endswith(".dist-info/entry_points.txt")),
            None,
        )
        entrypoint_errors: list[str] = []
        metadata_errors: list[str] = []
        with ZipFile(wheel_path, "r") as archive:
            if entry_points is not None:
                entrypoint_text = archive.read(entry_points).decode("utf-8")
                entrypoint_errors.extend(
                    self._entrypoint_errors(entrypoint_text, manifest),
                )
            metadata = next(
                (member for member in members if member.endswith(".dist-info/METADATA")),
                None,
            )
            if metadata is not None:
                metadata_errors.extend(
                    self._metadata_errors(
                        archive.read(metadata).decode("utf-8"),
                        manifest,
                    ),
                )
        return CollectorWheelInspectionResult(
            members=members,
            required_members=required_members,
            missing_required_members=missing_required_members,
            unexpected_wheel_members=unexpected_wheel_members,
            unexpected_application_members=tuple(extra_application_members),
            prohibited_members=prohibited_members,
            provider_implementation_members=provider_implementation_members,
            metadata_errors=tuple(metadata_errors),
            entrypoint_errors=tuple(entrypoint_errors),
        )

    def _allowed_metadata_members(
        self,
        members: tuple[str, ...],
        manifest: CollectorPackageManifest,
    ) -> set[str]:
        dist_info = self._dist_info_prefix(manifest)
        matched_dist_info = {member.split("/", maxsplit=1)[0] for member in members if member.endswith(".dist-info/METADATA")}
        if len(matched_dist_info) == 1:
            dist_info = next(iter(matched_dist_info))
        allowed_names = {
            "INSTALLER",
            "METADATA",
            "RECORD",
            "REQUESTED",
            "WHEEL",
            "direct_url.json",
            "entry_points.txt",
            "licenses/LICENSE",
            "top_level.txt",
        }
        return {member for member in members if member.startswith(f"{dist_info}/") and member.removeprefix(f"{dist_info}/") in allowed_names}

    def _required_metadata_members(
        self,
        members: tuple[str, ...],
        manifest: CollectorPackageManifest,
    ) -> set[str]:
        dist_info = self._dist_info_prefix(manifest)
        matched_dist_info = {member.split("/", maxsplit=1)[0] for member in members if member.endswith(".dist-info/METADATA")}
        if len(matched_dist_info) == 1:
            dist_info = next(iter(matched_dist_info))
        return {
            f"{dist_info}/METADATA",
            f"{dist_info}/WHEEL",
            f"{dist_info}/entry_points.txt",
        }

    def _dist_info_prefix(self, manifest: CollectorPackageManifest) -> str:
        normalized_name = manifest.artifact_name.replace("-", "_")
        return f"{normalized_name}-{manifest.version}.dist-info"

    def _scanner_module_members(
        self,
        scanner_class_paths: Mapping[str, str] | None,
        *,
        planned_source_files: tuple[str, ...],
    ) -> set[str]:
        paths = COLLECTOR_SCANNER_CLASS_PATHS if scanner_class_paths is None else scanner_class_paths
        planned = set(planned_source_files)
        members: set[str] = set()
        for class_path in paths.values():
            module_name, separator, _ = class_path.partition(":")
            if separator and module_name:
                module_path = module_name.replace(".", "/")
                source_file = f"{module_path}.py"
                package_file = f"{module_path}/__init__.py"
                if source_file in planned:
                    members.add(source_file)
                elif package_file in planned:
                    members.add(package_file)
                else:
                    members.add(source_file)
        return members

    def _read_metadata(self, archive: ZipFile, members: tuple[str, ...]) -> str:
        metadata = next(
            (member for member in members if member.endswith(".dist-info/METADATA")),
            None,
        )
        if metadata is None:
            msg = "Collector wheel is missing METADATA."
            raise RuntimeError(msg)
        return archive.read(metadata).decode("utf-8")

    def _validate_metadata(
        self,
        metadata_text: str,
        manifest: CollectorPackageManifest,
    ) -> None:
        errors = self._metadata_errors(metadata_text, manifest)
        if errors:
            raise RuntimeError("; ".join(errors))

    def _metadata_errors(
        self,
        metadata_text: str,
        manifest: CollectorPackageManifest,
    ) -> list[str]:
        headers = self._metadata_headers(metadata_text)
        errors: list[str] = []
        if headers.get("name", [""])[0] != manifest.artifact_name:
            errors.append("Collector wheel metadata package name is invalid.")
        if headers.get("version", [""])[0] != manifest.version:
            errors.append("Collector wheel metadata version is invalid.")
        required = {self._dependency_name(value).lower() for value in manifest.required_dependencies}
        declared = {self._dependency_name(value).lower() for value in headers.get("requires-dist", [])}
        missing = sorted(required - declared)
        if missing:
            errors.append("Collector wheel metadata is missing dependencies: " + ", ".join(missing))
        return errors

    def _entrypoint_errors(
        self,
        entrypoint_text: str,
        manifest: CollectorPackageManifest,
    ) -> list[str]:
        expected_entrypoints = manifest.entrypoints or {
            "unio-collector": "unio_collector.collector_cli.app:main",
        }
        errors: list[str] = []
        for name, target in sorted(expected_entrypoints.items()):
            if f"{name} = {target}" not in entrypoint_text:
                errors.append(f"missing {name} console script")
        if "unio =" in entrypoint_text:
            errors.append("full Unio console script is present")
        return errors

    def _metadata_headers(self, metadata_text: str) -> dict[str, list[str]]:
        headers: dict[str, list[str]] = {}
        for line in metadata_text.splitlines():
            if ":" not in line:
                continue
            name, value = line.split(":", maxsplit=1)
            headers.setdefault(name.strip().lower(), []).append(value.strip())
        return headers

    def _dependency_name(self, requirement: str) -> str:
        requirement = requirement.split(";", maxsplit=1)[0].strip()
        for separator in ("[", "<", ">", "=", "!", "~", " "):
            requirement = requirement.split(separator, maxsplit=1)[0].strip()
        return requirement
