"""Build and inspect a wheel-first PyInstaller collector distribution."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import venv
from importlib import import_module
from pathlib import Path
from time import monotonic
from zipfile import ZIP_DEFLATED, ZipFile

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

try:
    from tools.native_locks import lock_sha256, validate_lock
    from tools.native_release.abi import LinuxBaselineValidator
except ModuleNotFoundError:
    from native_locks import lock_sha256, validate_lock
    from native_release.abi import LinuxBaselineValidator

try:
    from tools.windows_installer.identity import WindowsInstallerIdentity
    from tools.windows_installer.smoke import verify_launched_identity
except ModuleNotFoundError as exc:
    if exc.name != "tools":
        raise
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from tools.windows_installer.identity import WindowsInstallerIdentity
    from tools.windows_installer.smoke import verify_launched_identity

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
            planned_source_files=plan.package_files,
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
        installer_identity = WindowsInstallerIdentity.for_repository(self.root, native_manifest.version)
        build_identity = {
            "application_version": native_manifest.version,
            "source_commit": source_commit,
            "wheel_sha256": wheel_sha256,
            "installer_revision": installer_identity.revision,
            "installer_version": installer_identity.installer_version,
            "channel": installer_identity.channel,
            "schema_version": 1,
        }
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
            first = self._freeze(environment_python, workspace / "first", modules, build_identity=build_identity)
            first_inventory = inventory_module.build_native_payload_inventory(first)
            reproducibility = {"checked": verify_reproducibility, "normalized_match": None, "native_binary_differences": []}
            if verify_reproducibility:
                second = self._freeze(environment_python, workspace / "second", modules, build_identity=build_identity)
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
            if operating_system == "linux":
                LinuxBaselineValidator().validate(payload, output / "native-abi-evidence.json")
            smoke = self._smoke(payload, workspace / "smoke", version=native_manifest.version)
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

    def _freeze(self, python: Path, workspace: Path, modules: tuple[str, ...], *, build_identity: dict[str, object] | None = None) -> Path:
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
        if build_identity is not None:
            (payload / "collector-build.json").write_text(json.dumps(build_identity, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return payload

    def _smoke(self, payload: Path, workspace: Path, *, version: str) -> dict[str, object]:
        workspace.mkdir()
        build_identity = json.loads((payload / "collector-build.json").read_text(encoding="utf-8"))
        suffix = ".exe" if os.name == "nt" else ""
        cli = payload / f"unio-collector{suffix}"
        launcher = payload / f"Unio Collector{suffix}"
        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        environment["UNIO_LAUNCHER_IDENTITY_OUTPUT"] = str(workspace / "gui-build-identity.json")
        environment["UNIO_COLLECTOR_LAUNCHER_SMOKE_TEST"] = "1"
        for key in tuple(environment):
            if key.startswith("AWS_"):
                environment.pop(key)
        environment["AWS_EC2_METADATA_DISABLED"] = "true"
        environment["AWS_CONFIG_FILE"] = str(workspace / "unused-config")
        environment["AWS_SHARED_CREDENTIALS_FILE"] = str(workspace / "unused-credentials")
        fixture = workspace / "cost.json"
        shutil.copyfile(self.root / "tests/standalone/fixtures/cost.json", fixture)
        bundle = workspace / "evidence.zip"
        checks: dict[str, int] = {}
        for name, command in {
            "version": (str(cli), "version"),
            "version_flag": (str(cli), "--version"),
            "build_identity": (str(cli), "version", "--build-info"),
            "profiles": (str(cli), "profiles", "--json"),
            "scanners": (str(cli), "scanners", "--json"),
            "launcher": (str(launcher),),
            "collect_fixture": (str(cli), "collect", "--fixture", str(fixture), "--output", str(bundle), "--quiet"),
            "validate_bundle": (str(cli), "validate-bundle", str(bundle)),
            "validate_unknown_bundle": (str(cli), "validate-bundle", str(workspace / "unknown.zip")),
            **{
                name: command
                for profile in ("standard", "strict")
                for name, command in (
                    (
                        f"protect_{profile}",
                        (
                            str(cli),
                            "privacy",
                            "protect",
                            "--bundle",
                            str(bundle),
                            "--output",
                            str(workspace / f"protected-{profile}.zip"),
                            "--vault",
                            str(workspace / f"private-{profile}" / "vault.json"),
                            "--profile",
                            profile,
                            "--passphrase-stdin",
                            "--acknowledge-vault-loss-risk",
                        ),
                    ),
                    (f"validate_protected_{profile}", (str(cli), "validate-bundle", str(workspace / f"protected-{profile}.zip"))),
                )
            },
            **{
                f"protect_unknown_{profile}": (
                    str(cli),
                    "privacy",
                    "protect",
                    "--bundle",
                    str(workspace / "unknown.zip"),
                    "--output",
                    str(workspace / f"unknown-{profile}.zip"),
                    "--vault",
                    str(workspace / f"private-unknown-{profile}" / "vault.json"),
                    "--profile",
                    profile,
                    "--passphrase-stdin",
                    "--acknowledge-vault-loss-risk",
                )
                for profile in ("standard", "strict")
            },
        }.items():
            completed = subprocess.run(  # noqa: S603
                command,
                check=False,
                cwd=workspace,
                env=environment,
                capture_output=True,
                text=True,
                input="synthetic-native-smoke-only\n" if name.startswith("protect_") else None,
            )
            if name == "build_identity" and completed.returncode == 0:
                verify_launched_identity(json.loads(completed.stdout), build_identity, cli)
            if name == "launcher" and completed.returncode == 0:
                verify_launched_identity(json.loads((workspace / "gui-build-identity.json").read_text(encoding="utf-8")), build_identity, launcher)
            if name == "collect_fixture" and completed.returncode == 0:
                ledger_namespace = _add_synthetic_region_scope(bundle, self.root / "tests/standalone/fixtures/region-scope.json")
                shutil.copyfile(bundle, workspace / "unknown.zip")
                _add_synthetic_region_scope(workspace / "unknown.zip", self.root / "tests/standalone/fixtures/region-scope.json", unknown_ledger_field=True)
                unknown_digest = hashlib.sha256((workspace / "unknown.zip").read_bytes()).hexdigest()
            checks[name] = completed.returncode
            expected = 1 if name.startswith("protect_unknown_") else 0
            if completed.returncode != expected:
                message = f"Native {name} smoke failed: {completed.stdout} {completed.stderr}"
                raise RuntimeError(message)
            if name.startswith("protect_unknown_"):
                profile = name.removeprefix("protect_unknown_")
                _verify_unknown_smoke(workspace, profile, completed, unknown_digest, ledger_namespace)
            if name in {"version", "version_flag"} and completed.stdout.strip() != f"unio-collector {version}":
                message = f"Native {name} reports {completed.stdout.strip()!r}, expected collector version {version}."
                raise RuntimeError(message)
        return {
            "build_identity": build_identity,
            "checks": checks,
            "expected_version": version,
            "version_verified": True,
            "source_checkout": False,
            "system_python_required": False,
            "expected_exit_codes": {name: 1 if name.startswith("protect_unknown_") else 0 for name in checks},
            "producer_fixture_sha256": hashlib.sha256((self.root / "tests/standalone/fixtures/protection-producers.json").read_bytes()).hexdigest(),
            "ledger_namespace": ledger_namespace,
        }


def _verify_unknown_smoke(workspace: Path, profile: str, completed: subprocess.CompletedProcess[str], input_digest: str, ledger_namespace: str) -> None:
    """Require the negative smoke to reject the unknown field without publication."""
    if any(
        path not in completed.stdout + completed.stderr
        for path in (
            f"collection-log.jsonl.{ledger_namespace}.unknown_synthetic_field",
            "collection-summary.json.api_runtime_summary.records[].unknown_synthetic_field",
        )
    ):
        raise RuntimeError("Native negative smoke failed for an unrelated reason.")  # noqa: EM101, TRY003
    if any(
        (workspace / candidate).exists()
        for candidate in (f"unknown-{profile}.zip", f"unknown-{profile}.zip.receipt.json", f"private-unknown-{profile}/vault.json")
    ):
        raise RuntimeError("Native rejected protection published an artifact.")  # noqa: EM101, TRY003
    if list(workspace.rglob("*.tmp")) or hashlib.sha256((workspace / "unknown.zip").read_bytes()).hexdigest() != input_digest:
        raise RuntimeError("Native rejection changed input or left staging files.")  # noqa: EM101, TRY003


def _add_synthetic_region_scope(bundle: Path, fixture: Path, *, unknown_ledger_field: bool = False) -> str:
    """Enrich only the smoke-created fixture ZIP with producer-shaped metadata."""
    scope = json.loads(fixture.read_text(encoding="utf-8"))
    with ZipFile(bundle) as archive:
        files = {name: archive.read(name) for name in archive.namelist()}
    for member in ("account-scope.json", "collection-summary.json", "manifest.json"):
        payload = json.loads(files[member])
        payload["region_scope"] = scope
        files[member] = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
    provenance = json.loads(fixture.with_name("protection-producers.json").read_text(encoding="utf-8"))
    ledger_namespace = json.loads(files["bundle-schema.json"])["format"].removesuffix("-result-evidence-bundle")
    if ledger_namespace not in provenance["collection_log"]:
        message = "Synthetic ledger fixture must retain the wire-protocol envelope, not the Python import namespace."
        raise ValueError(message)
    if unknown_ledger_field:
        provenance["collection_log"][ledger_namespace]["unknown_synthetic_field"] = None
    for member, field in (("account-scope.json", "scan_period"), ("analysis-readiness.json", "pricing_replay")):
        payload = json.loads(files[member])
        payload[field] = provenance[field]
        files[member] = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
    summary = json.loads(files["collection-summary.json"])
    summary["api_runtime_summary"] = provenance["api_runtime_summary"]["populated"]
    if unknown_ledger_field:
        summary["api_runtime_summary"]["records"][0]["unknown_synthetic_field"] = None
    summary["billing_region_scope_derivation"] = provenance["billing_region_scope_derivation"]
    summary["billing_region_coverage"] = provenance["billing_region_coverage"]
    summary["stable_limitation_details"] = provenance["stable_limitation_details"]
    summary["collection_runtime_summary"] = provenance["collection_runtime_summary"]
    files["scan-result/api-runtime-summary.json"] = json.dumps(summary["api_runtime_summary"], indent=2, sort_keys=True).encode("utf-8")
    files["collection-summary.json"] = json.dumps(summary, indent=2, sort_keys=True).encode("utf-8")
    files["collection-log.jsonl"] = (json.dumps(provenance["collection_log"], sort_keys=True) + "\n").encode("utf-8")
    files["scan-result/pricing-context.json"] = json.dumps(provenance["pricing_context"], indent=2, sort_keys=True).encode("utf-8")
    checksums = {name: hashlib.sha256(data).hexdigest() for name, data in sorted(files.items()) if name not in {"manifest.json", "checksums.json"}}
    manifest = json.loads(files["manifest.json"])
    manifest["product_execution"] = provenance["product_execution"]
    manifest["checksums"] = checksums
    files["manifest.json"] = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
    files["checksums.json"] = json.dumps({"algorithm": "sha256", "checksums": checksums}, indent=2, sort_keys=True).encode("utf-8")
    with ZipFile(bundle, "w", compression=ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            archive.writestr(name, data)
    return ledger_namespace


def _spec_text(cli: Path, launcher: Path, modules: tuple[str, ...]) -> str:
    return f"""
from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files, copy_metadata
collector_metadata = [
    (str(Path(source) / 'METADATA'), destination)
    for source, destination in copy_metadata('unio-collector')
]
collector_data = collect_data_files('unio_collector', include_py_files=False)
a_cli = Analysis([{str(cli)!r}], pathex=[], binaries=[], datas=collector_metadata + collector_data, hiddenimports={list(modules)!r}, noarchive=False)
a_gui = Analysis([{str(launcher)!r}], pathex=[], binaries=[], datas=collector_metadata + collector_data, hiddenimports={list(modules)!r}, noarchive=False)
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
    completed = subprocess.run(  # noqa: S603
        [str(python), "-m", "pip", "inspect", "--local"],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
    )
    inspection = json.loads(completed.stdout)
    packages = _runtime_packages(inspection, native_manifest["runtime_dependencies"])
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


def _runtime_packages(inspection: dict[str, object], roots: object) -> list[dict[str, str]]:  # noqa: C901
    """Select the installed runtime dependency closure, excluding build tools."""
    installed = inspection.get("installed")
    environment = inspection.get("environment")
    if not isinstance(installed, list) or not isinstance(environment, dict) or not isinstance(roots, (list, tuple)):
        message = "Installed native dependency metadata is incomplete."
        raise ValueError(message)
    by_name = {}
    for item in installed:
        if not isinstance(item, dict) or not isinstance(item.get("metadata"), dict):
            message = "Installed native dependency metadata is malformed."
            raise ValueError(message)
        metadata = item["metadata"]
        name = metadata.get("name")
        if not isinstance(name, str) or canonicalize_name(name) in by_name:
            message = "Installed native dependency names are ambiguous."
            raise ValueError(message)
        by_name[canonicalize_name(name)] = metadata
    pending = [Requirement(str(value)) for value in roots]
    selected: set[str] = set()
    while pending:
        requirement = pending.pop()
        if requirement.marker is not None and not requirement.marker.evaluate({**environment, "extra": ""}):
            continue
        name = canonicalize_name(requirement.name)
        metadata = by_name.get(name)
        if metadata is None or not isinstance(metadata.get("version"), str) or metadata["version"] not in requirement.specifier:
            message = f"Native runtime dependency is missing or mismatched: {name}"
            raise ValueError(message)
        if name in selected:
            continue
        selected.add(name)
        for raw in metadata.get("requires_dist") or []:
            dependency = Requirement(str(raw))
            extras = requirement.extras or {""}
            if dependency.marker is None or any(dependency.marker.evaluate({**environment, "extra": extra}) for extra in extras):
                pending.append(dependency)
    return [{"name": str(by_name[name]["name"]), "version": str(by_name[name]["version"])} for name in sorted(selected)]


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

        with ZipFile(archive, "w", ZIP_DEFLATED, strict_timestamps=False) as target:
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
