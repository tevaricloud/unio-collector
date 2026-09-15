"""Build and inspect a wheel-first PyInstaller collector distribution."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import venv
from importlib import import_module
from pathlib import Path
from time import monotonic
from zipfile import ZIP_DEFLATED, ZipFile

try:
    from tools.native_locks import lock_sha256, validate_lock
except ModuleNotFoundError:
    from native_locks import lock_sha256, validate_lock

NATIVE_SUMMARY_SCHEMA_VERSION = "2026-08-native-build-v1"
TCL_TK_MARKERS = ("_tcl_data", "_tk_data", "tcl8", "tk8", "tcl86", "tk86", "_tkinter")


def main() -> int:
    """Build a native collector artifact from a validated wheel."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--wheelhouse", type=Path, default=None)
    parser.add_argument("--skip-second-build", action="store_true")
    parser.add_argument("--require-hash-lock", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = _approved_output(args.output, root)
    summary = NativeCollectorBuilder(root).build(
        wheel=args.wheel.resolve(),
        output=output,
        wheelhouse=args.wheelhouse.resolve() if args.wheelhouse else None,
        verify_reproducibility=not args.skip_second_build,
        require_hash_lock=args.require_hash_lock,
    )
    print(json.dumps(summary, indent=2, sort_keys=True))  # noqa: T201
    return 0


class NativeCollectorBuilder:
    """Create a frozen collector exclusively from the validated collector wheel."""

    def __init__(self, root: Path) -> None:
        """Store repository metadata used only for build validation."""
        self.root = root.resolve()

    def build(
        self,
        *,
        wheel: Path,
        output: Path,
        wheelhouse: Path | None,
        verify_reproducibility: bool,
        require_hash_lock: bool = False,
    ) -> dict[str, object]:
        """Build, smoke, inventory, and archive the native payload."""
        started = monotonic()
        source_commit = _source_commit(self.root)
        output.mkdir(parents=True, exist_ok=True)
        wheel_sha256 = _sha256(wheel)
        package_module = import_module("unio_collector.collector.package.manifest")
        inventory_module = import_module("unio_collector.collector.package.native.inventory")
        native_module = import_module("unio_collector.collector.package.native.manifest")
        wheel_builder_type = import_module("unio_collector.collector.package.wheel.builder").CollectorWheelBuilder
        plan = package_module.build_collector_package_file_plan(root=self.root)
        wheel_builder_type().validate_existing_wheel(
            wheel_path=wheel,
            planned_source_files=plan.source_files,
            manifest=plan.manifest,
        )
        native_manifest = native_module.build_native_collector_manifest(plan.manifest)
        errors = native_manifest.validate()
        if errors:
            message = "; ".join(errors)
            raise RuntimeError(message)
        operating_system, architecture = native_module.current_native_target()
        if (operating_system, architecture) not in {(item.operating_system, item.architecture) for item in native_manifest.targets}:
            message = f"Unsupported native collector target: {operating_system}/{architecture}."
            raise RuntimeError(message)
        with tempfile.TemporaryDirectory(prefix="unio-collector-native-build-") as raw:
            workspace = Path(raw)
            environment_python, lock_evidence = self._create_environment(
                workspace,
                wheel,
                wheelhouse,
                operating_system=operating_system,
                architecture=architecture,
                require_hash_lock=require_hash_lock,
            )
            modules = _wheel_modules(wheel)
            forbidden = _forbidden_modules(modules, tuple(package_module.COLLECTOR_FORBIDDEN_PREFIXES))
            if forbidden:
                message = "Collector wheel contains forbidden native build modules: " + ", ".join(forbidden[:10])
                raise RuntimeError(message)
            first = self._freeze(environment_python, workspace / "first", modules)
            first_inventory = inventory_module.build_native_payload_inventory(first)
            reproducibility = {"checked": verify_reproducibility, "normalized_match": None, "native_binary_differences": []}
            if verify_reproducibility:
                second = self._freeze(environment_python, workspace / "second", modules)
                second_inventory = inventory_module.build_native_payload_inventory(second)
                reproducibility = _compare_inventories(first_inventory, second_inventory)
                if not bool(reproducibility["normalized_match"]):
                    message = "Normalized native payloads differ across repeated builds: " + ", ".join(
                        reproducibility["normalized_differences"][:10],  # type: ignore[index]
                    )
                    raise RuntimeError(message)
            payload = output / "payload"
            if payload.exists():
                message = f"Native output already exists: {payload}"
                raise RuntimeError(message)
            shutil.copytree(first, payload)
            inventory_path = output / "native-payload-manifest.json"
            retained_inventory = inventory_module.write_native_payload_inventory(payload, inventory_path)
            smoke = self._smoke(payload, workspace / "smoke")
            tcl_tk = _tcl_tk_inventory(payload)
            if not tcl_tk:
                message = "Frozen launcher payload does not contain Tcl/Tk runtime resources."
                raise RuntimeError(message)
            sbom_paths = _write_sboms(output, environment_python, native_manifest.convert_to_dict())
            notices_path = _write_licence_notices(output, environment_python)
            lock_evidence_path = output / "native-hash-lock-evidence.json"
            lock_evidence.update(
                {
                    "collector_wheel_sha256": wheel_sha256,
                    "pip_check": "passed",
                    "resolved_packages": _installed_packages(environment_python),
                },
            )
            lock_evidence_path.write_text(
                json.dumps(lock_evidence, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            archive = _write_portable_archive(output, payload, native_manifest.version, operating_system, architecture)
            release_manifest_path = _write_release_manifest(
                output,
                native_manifest=native_manifest.convert_to_dict(),
                wheel_sha256=wheel_sha256,
                operating_system=operating_system,
                architecture=architecture,
                normalized_payload_sha256=str(retained_inventory["normalized_payload_sha256"]),
                artifacts=(archive, inventory_path, *sbom_paths, notices_path, lock_evidence_path),
                source_commit=source_commit,
            )
            checksums = _write_checksums(
                output,
                (archive, inventory_path, *sbom_paths, notices_path, lock_evidence_path, release_manifest_path),
            )
            summary = {
                "architecture": architecture,
                "artifact_name": native_manifest.artifact_name,
                "automatic_update_enabled": False,
                "build_duration_seconds": round(monotonic() - started, 3),
                "checksums": checksums,
                "collector_wheel": str(wheel),
                "collector_wheel_sha256": wheel_sha256,
                "forbidden_modules": forbidden,
                "installer_status": "separate_platform_packaging_required",
                "native_manifest": native_manifest.convert_to_dict(),
                "normalized_payload_sha256": retained_inventory["normalized_payload_sha256"],
                "operating_system": operating_system,
                "payload": str(payload),
                "portable_artifact": str(archive),
                "release_manifest": str(release_manifest_path),
                "reproducibility": reproducibility,
                "runtime_source_checkout_required": False,
                "schema_version": NATIVE_SUMMARY_SCHEMA_VERSION,
                "signing_status": "unsigned",
                "smoke": smoke,
                "tcl_tk_inventory": tcl_tk,
                "validation_status": "valid",
            }
            (output / "native-build-summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return summary

    def _create_environment(
        self,
        workspace: Path,
        wheel: Path,
        wheelhouse: Path | None,
        *,
        operating_system: str,
        architecture: str,
        require_hash_lock: bool,
    ) -> tuple[Path, dict[str, object]]:
        environment = workspace / "build-environment"
        lock_file = self.root / "requirements" / f"native-{operating_system}-{architecture}.lock"
        if require_hash_lock and not lock_file.is_file():
            message = f"Protected native build requires repository hash lock: {lock_file.name}"
            raise RuntimeError(message)
        if require_hash_lock:
            validate_lock(lock_file)
        venv.EnvBuilder(with_pip=True, clear=True).create(environment)
        python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        if require_hash_lock:
            dependency_command = [
                str(python),
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--require-hashes",
                "--only-binary=:all:",
                "--requirement",
                str(lock_file),
            ]
            if wheelhouse is not None:
                dependency_command.extend(("--no-index", "--find-links", str(wheelhouse)))
            subprocess.run(dependency_command, check=True, cwd=workspace)  # noqa: S603
            wheel_command = [
                str(python),
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--no-deps",
                str(wheel),
            ]
            if wheelhouse is not None:
                wheel_command.extend(("--no-index", "--find-links", str(wheelhouse)))
            subprocess.run(wheel_command, check=True, cwd=workspace)  # noqa: S603
            subprocess.run((str(python), "-m", "pip", "check"), check=True, cwd=workspace)  # noqa: S603
            return python, {
                "lock_filename": lock_file.name,
                "lock_sha256": lock_sha256(lock_file),
                "protected_mode": True,
                "schema_version": "2026-08-native-hash-lock-v1",
                "target": f"{operating_system}-{architecture}",
                "wheelhouse_mode": wheelhouse is not None,
            }
        command = [
            str(python),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--constraint",
            str(self.root / "requirements" / "dev-constraints.txt"),
            "--constraint",
            str(self.root / "requirements" / "native-constraints.txt"),
        ]
        if wheelhouse is not None:
            command.extend(("--no-index", "--find-links", str(wheelhouse)))
        command.extend((str(wheel), "PyInstaller==6.22.2"))
        subprocess.run(command, check=True, cwd=workspace)  # noqa: S603
        subprocess.run((str(python), "-m", "pip", "check"), check=True, cwd=workspace)  # noqa: S603
        return python, {
            "lock_filename": None,
            "lock_sha256": None,
            "protected_mode": False,
            "schema_version": "2026-08-native-hash-lock-v1",
            "target": f"{operating_system}-{architecture}",
            "wheelhouse_mode": wheelhouse is not None,
        }

    def _freeze(self, python: Path, workspace: Path, modules: tuple[str, ...]) -> Path:
        workspace.mkdir(parents=True)
        cli = workspace / "collector_entry.py"
        launcher = workspace / "launcher_entry.py"
        cli.write_text("from unio_collector.collector_cli.app import main\nraise SystemExit(main())\n", encoding="utf-8")
        launcher.write_text("from unio_collector.collector_launcher.app import main\nraise SystemExit(main())\n", encoding="utf-8")
        spec = workspace / "collector-native.spec"
        spec.write_text(_spec_text(cli, launcher, modules), encoding="utf-8")
        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        environment["PYINSTALLER_CONFIG_DIR"] = str(workspace / "pyinstaller-config")
        subprocess.run(  # noqa: S603
            [
                str(python),
                "-P",
                "-m",
                "PyInstaller",
                "--clean",
                "--noconfirm",
                "--distpath",
                str(workspace / "dist"),
                "--workpath",
                str(workspace / "work"),
                str(spec),
            ],
            check=True,
            cwd=self.root,
            env=environment,
        )
        payload = workspace / "dist" / "unio-collector"
        if not payload.is_dir():
            message = "PyInstaller did not create the expected one-directory payload."
            raise RuntimeError(message)
        return payload

    def _smoke(self, payload: Path, workspace: Path) -> dict[str, object]:
        workspace.mkdir()
        suffix = ".exe" if os.name == "nt" else ""
        cli = payload / f"unio-collector{suffix}"
        launcher = payload / f"Unio Collector{suffix}"
        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        environment["UNIO_COLLECTOR_LAUNCHER_SMOKE_TEST"] = "1"
        checks: dict[str, int] = {}
        for name, command in {
            "version": (str(cli), "version"),
            "profiles": (str(cli), "profiles", "--json"),
            "scanners": (str(cli), "scanners", "--json"),
            "launcher": (str(launcher),),
        }.items():
            completed = subprocess.run(command, check=False, cwd=workspace, env=environment, capture_output=True, text=True)  # noqa: S603
            checks[name] = completed.returncode
            if completed.returncode != 0:
                message = f"Native {name} smoke failed: {completed.stdout} {completed.stderr}"
                raise RuntimeError(message)
        return {"checks": checks, "source_checkout": False, "system_python_required": False}


def _spec_text(cli: Path, launcher: Path, modules: tuple[str, ...]) -> str:
    return f"""
a_cli = Analysis([{str(cli)!r}], pathex=[], binaries=[], datas=[], hiddenimports={list(modules)!r}, noarchive=False)
a_gui = Analysis([{str(launcher)!r}], pathex=[], binaries=[], datas=[], hiddenimports={list(modules)!r}, noarchive=False)
pyz_cli = PYZ(a_cli.pure)
pyz_gui = PYZ(a_gui.pure)
exe_cli = EXE(
    pyz_cli, a_cli.scripts, [], exclude_binaries=True, name='unio-collector',
    debug=False, bootloader_ignore_signals=False, strip=False, upx=False, console=True,
)
exe_gui = EXE(
    pyz_gui, a_gui.scripts, [], exclude_binaries=True, name='Unio Collector',
    debug=False, bootloader_ignore_signals=False, strip=False, upx=False, console=False,
)
coll = COLLECT(exe_cli, exe_gui, a_cli.binaries, a_cli.datas, a_gui.binaries, a_gui.datas, strip=False, upx=False, name='unio-collector')
""".lstrip()


def _wheel_modules(wheel: Path) -> tuple[str, ...]:
    with ZipFile(wheel) as archive:
        names = archive.namelist()
    modules: set[str] = set()
    for name in names:
        if not name.startswith("unio_collector/") or not name.endswith(".py"):
            continue
        module = name.removesuffix("/__init__.py").removesuffix(".py").replace("/", ".")
        modules.add(module)
    return tuple(sorted(modules))


def _forbidden_modules(modules: tuple[str, ...], forbidden_prefixes: tuple[str, ...]) -> list[str]:
    return [module for module in modules if any(module == prefix or module.startswith(prefix + ".") for prefix in forbidden_prefixes)]


def _tcl_tk_inventory(payload: Path) -> list[str]:
    return sorted(
        path.relative_to(payload).as_posix()
        for path in payload.rglob("*")
        if path.is_file() and any(marker in path.as_posix().casefold() for marker in TCL_TK_MARKERS)
    )


def _compare_inventories(first: dict[str, object], second: dict[str, object]) -> dict[str, object]:
    first_files = {str(item["path"]): item for item in first["files"] if isinstance(item, dict)}  # type: ignore[index]
    second_files = {str(item["path"]): item for item in second["files"] if isinstance(item, dict)}  # type: ignore[index]
    native_differences = sorted(
        path
        for path in first_files.keys() & second_files.keys()
        if first_files[path].get("native_binary") and first_files[path].get("sha256") != second_files[path].get("sha256")
    )
    normalized_differences = sorted(
        path for path in first_files.keys() | second_files.keys() if _normalized_record(first_files.get(path)) != _normalized_record(second_files.get(path))
    )
    return {
        "checked": True,
        "native_binary_differences": native_differences,
        "normalized_match": first["normalized_payload_sha256"] == second["normalized_payload_sha256"],
        "normalized_differences": normalized_differences,
    }


def _normalized_record(record: dict[str, object] | None) -> dict[str, object] | None:
    if record is None:
        return None
    normalized = dict(record)
    if bool(normalized.get("native_binary")):
        normalized["sha256"] = None
        normalized["size"] = None
    return normalized


def _write_sboms(output: Path, python: Path, native_manifest: dict[str, object]) -> tuple[Path, Path]:
    completed = subprocess.run([str(python), "-m", "pip", "list", "--format", "json"], check=True, capture_output=True, text=True)  # noqa: S603
    packages = json.loads(completed.stdout)
    cyclone_components = [
        {"name": item["name"], "type": "library", "version": item["version"]} for item in sorted(packages, key=lambda value: value["name"].casefold())
    ]
    cyclone = {
        "bomFormat": "CycloneDX",
        "components": cyclone_components,
        "metadata": {"component": {"name": native_manifest["artifact_name"], "type": "application", "version": native_manifest["version"]}},
        "specVersion": "1.6",
        "version": 1,
    }
    spdx = {
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {"creators": ["Tool: Unio Collector native collector builder"]},
        "dataLicense": "CC0-1.0",
        "name": f"{native_manifest['artifact_name']}-{native_manifest['version']}",
        "packages": [
            {"SPDXID": f"SPDXRef-Package-{index}", "name": item["name"], "versionInfo": item["version"]}
            for index, item in enumerate(cyclone_components, start=1)
        ],
        "spdxVersion": "SPDX-2.3",
    }
    cyclone_path = output / "sbom.cyclonedx.json"
    spdx_path = output / "sbom.spdx.json"
    cyclone_path.write_text(json.dumps(cyclone, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    spdx_path.write_text(json.dumps(spdx, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return cyclone_path, spdx_path


def _write_licence_notices(output: Path, python: Path) -> Path:
    script = """
import importlib.metadata as metadata
import json
values = []
for dist in metadata.distributions():
    declared = dist.metadata.get('License-Expression') or dist.metadata.get('License') or 'not-declared'
    values.append({'name': dist.metadata.get('Name', ''), 'version': dist.version, 'license': declared})
print(json.dumps(sorted(values, key=lambda item: item['name'].casefold())))
"""
    completed = subprocess.run([str(python), "-B", "-c", script], check=True, capture_output=True, text=True)  # noqa: S603
    path = output / "dependency-licences.json"
    path.write_text(json.dumps(json.loads(completed.stdout), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _installed_packages(python: Path) -> list[dict[str, str]]:
    completed = subprocess.run(  # noqa: S603
        (str(python), "-m", "pip", "list", "--format=json"),
        check=True,
        capture_output=True,
        text=True,
    )
    return sorted(json.loads(completed.stdout), key=lambda item: item["name"].casefold())


def _write_portable_archive(output: Path, payload: Path, version: str, operating_system: str, architecture: str) -> Path:
    name = f"unio-collector-{version}-{operating_system}-{architecture}"
    if operating_system == "windows":
        archive = output / f"{name}.zip"
        with ZipFile(archive, "w", ZIP_DEFLATED) as target:
            for path in sorted(payload.rglob("*")):
                if path.is_file():
                    target.write(path, (Path(name) / path.relative_to(payload)).as_posix())
        return archive
    archive_base = output / name
    return Path(shutil.make_archive(str(archive_base), "gztar", root_dir=payload.parent, base_dir=payload.name))


def _write_checksums(output: Path, paths: tuple[Path, ...]) -> dict[str, str]:
    checksums = {path.name: _sha256(path) for path in paths}
    (output / "SHA256SUMS").write_text("".join(f"{digest}  {name}\n" for name, digest in sorted(checksums.items())), encoding="utf-8")
    return checksums


def _write_release_manifest(
    output: Path,
    *,
    native_manifest: dict[str, object],
    wheel_sha256: str,
    operating_system: str,
    architecture: str,
    normalized_payload_sha256: str,
    artifacts: tuple[Path, ...],
    source_commit: str,
) -> Path:
    manifest = {
        "architecture": architecture,
        "artifact_hashes": {path.name: _sha256(path) for path in artifacts},
        "automatic_update_enabled": False,
        "collector_wheel_sha256": wheel_sha256,
        "entrypoints": native_manifest["entrypoints"],
        "native_manifest_schema_version": native_manifest["schema_version"],
        "normalized_payload_sha256": normalized_payload_sha256,
        "operating_system": operating_system,
        "release_manifest_contract": "2026-08-native-release-v1",
        "schema_version": 1,
        "signing_status": "unsigned",
        "source_commit": source_commit,
        "version": native_manifest["version"],
        "version_check_policy": "manual_signed_metadata_only",
    }
    path = output / "native-release-manifest.json"
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _source_commit(root: Path) -> str:
    if (root / "export-provenance.json").is_file():
        verifier = import_module("tools.collector_repository.identity").RepositoryIdentity()
        return str(verifier.verify(root)["source_sha"])
    git = shutil.which("git")
    if git is None:
        message = "Git is required to bind the native release manifest to its source commit."
        raise RuntimeError(message)
    completed = subprocess.run(  # noqa: S603
        (git, "rev-parse", "HEAD"),
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _approved_output(output: Path, root: Path) -> Path:
    if not output.is_absolute():
        message = "--output must be an absolute external or managed validation path."
        raise SystemExit(message)
    resolved = output.resolve()
    if resolved == root or (resolved.is_relative_to(root) and "reports-dev" not in resolved.parts):
        message = "--output must not use an ordinary path inside the checkout."
        raise SystemExit(message)
    return resolved


if __name__ == "__main__":
    raise SystemExit(main())
