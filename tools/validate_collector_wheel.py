from __future__ import annotations  # noqa: D100

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
import tomllib
import venv
from importlib import import_module
from pathlib import Path
from zipfile import ZipFile

from packaging.markers import Marker
from packaging.requirements import Requirement

VALIDATION_SCHEMA_VERSION = "2026-08-collector-wheel-installed-validation-v1"
OPTIONAL_NON_AWS_SDK_IMPORTS = (
    "azure.identity",
    "azure.mgmt.storage",
    "google.auth",
    "google.cloud.resourcemanager_v3",
    "google.cloud.storage",
)
OPTIONAL_NON_AWS_SDK_DISTRIBUTIONS = (
    "azure-identity",
    "azure-mgmt-storage",
    "google-auth",
    "google-cloud-resource-manager",
    "google-cloud-storage",
)


def main() -> int:
    """Install and smoke a collector wheel in a clean virtual environment."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheel", required=True)
    parser.add_argument(
        "--fixture",
        default="tests/fixtures/sample_cost_data.json",
    )
    parser.add_argument("--pip-no-index", action="store_true")
    parser.add_argument("--pip-find-links")
    parser.add_argument("--summary-output")
    parser.add_argument("--cli-snapshot", default="tests/collector/snapshots/collector_cli_contract.json")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    wheel = Path(args.wheel).resolve()
    fixture = (root / args.fixture).resolve()
    summary_output = Path(args.summary_output).resolve() if args.summary_output else None
    payload: dict[str, object] = {
        "schema_version": VALIDATION_SCHEMA_VERSION,
        "status": "failed",
        "wheel": {
            "path": str(wheel),
            "filename": wheel.name,
            "sha256": _sha256(wheel),
        },
        "repository_root": str(root),
    }
    exit_code = 1
    external_temp_root = _external_temp_root(root)
    with tempfile.TemporaryDirectory(
        prefix="unio-collector-smoke-",
        dir=external_temp_root,
    ) as raw:
        environment = Path(raw)
        try:
            venv.EnvBuilder(with_pip=True, clear=True).create(environment)
            scripts = environment / ("Scripts" if os.name == "nt" else "bin")
            python = scripts / ("python.exe" if os.name == "nt" else "python")
            collector = scripts / ("unio-collector.exe" if os.name == "nt" else "unio-collector")
            unio_collector = scripts / ("unio_collector.exe" if os.name == "nt" else "unio_collector")
            payload["environment"] = {
                "venv_path": str(environment),
                "cwd": str(environment),
                "source_repo_on_pythonpath": False,
                "python_no_user_site": True,
                "system_site_packages": False,
            }
            wheel_inspection = _inspect_wheel(root=root, wheel=wheel)
            payload["wheel_members"] = wheel_inspection
            install_command = [str(python), "-m", "pip", "install"]
            if args.pip_no_index:
                install_command.append("--no-index")
            if args.pip_find_links:
                install_command.extend(["--find-links", str(Path(args.pip_find_links).resolve())])
            install_command.append(str(wheel))
            install_result = _run(install_command, cwd=environment)
            _write_private_smoke_secret(environment / "private" / "existing-passphrase.txt", "test-passphrase")
            _write_private_smoke_secret(environment / "private" / "new-passphrase.txt", "replacement-test-passphrase")
            live_scan_period_smoke = _write_live_scan_period_smoke(environment)
            commands = _collector_command_matrix(
                collector=collector,
                python=python,
                fixture=fixture,
                environment=environment,
                live_scan_period_smoke=live_scan_period_smoke,
            )
            command_results = {
                name: _command_summary(
                    _run(
                        command,
                        cwd=environment,
                        stdin_text=_privacy_stdin(name),
                    ),
                )
                for name, command in commands.items()
            }
            cli_contract = _run_cli_contract_check(
                collector=collector,
                python=python,
                environment=environment,
                snapshot_path=(root / args.cli_snapshot).resolve(),
            )
            restore_package = _write_unsigned_restore_package(environment)
            restore_result = _command_summary(
                _run(
                    [
                        str(collector),
                        "privacy",
                        "restore-report",
                        "--package",
                        str(restore_package),
                        "--vault",
                        str(environment / "private" / "identity-vault.json"),
                        "--output-dir",
                        str(environment / "restored-report"),
                        "--passphrase-stdin",
                        "--allow-unsigned",
                        "--overwrite",
                    ],
                    cwd=environment,
                    stdin_text="test-passphrase\n",
                ),
            )
            scanner_construction = _run_scanner_construction_check(
                python=python,
                environment=environment,
            )
            package_plan = json.loads(
                (environment / "package-plan.json").read_text(encoding="utf-8"),
            )
            doctor = json.loads(
                (environment / "doctor.json").read_text(encoding="utf-8"),
            )
            restored_report = json.loads(
                (environment / "restored-report" / "restored-report.json").read_text(
                    encoding="utf-8",
                ),
            )
            restoration_audit = json.loads(
                (environment / "restored-report" / "restoration-audit.json").read_text(
                    encoding="utf-8",
                ),
            )
            metadata = _run_metadata_check(
                python=python,
                environment=environment,
                expected_version=package_plan["manifest"]["version"],
                expected_dependencies=_metadata_requirements(root, package_plan["manifest"]["required_dependencies"]),
            )
            source_isolation = _run_source_isolation_check(
                python=python,
                environment=environment,
                root=root,
            )
            provider_boundary = _run_provider_boundary_check(
                python=python,
                environment=environment,
                root=root,
            )
            payload.update(
                {
                    "install": _command_summary(install_result),
                    "commands": command_results,
                    "cli_contract": cli_contract,
                    "restore_report": restore_result,
                    "package_plan": {
                        "status": package_plan.get("validation_status"),
                        "source_file_count": len(package_plan.get("source_files", [])),
                        "scanner_class_path_module_count": len(package_plan.get("scanner_class_path_modules", [])),
                    },
                    "doctor": {"status": doctor.get("status")},
                    "scanner_registry": scanner_construction,
                    "metadata": metadata,
                    "source_isolation": source_isolation,
                    "provider_boundary": provider_boundary,
                    "entrypoints": {
                        "collector_entrypoint_installed": collector.is_file(),
                        "full_entrypoint_installed": unio_collector.exists(),
                    },
                    "artifacts": {
                        "fixture_bundle_created": (environment / "fixture-bundle.zip").is_file(),
                        "live_scan_period_bundle_created": (environment / "live-shaped-bundle.zip").is_file(),
                        "protected_bundle_created": (environment / "protected-fixture-bundle.zip").is_file(),
                        "protected_receipt_created": (environment / "protected-fixture-bundle.zip.receipt.json").is_file(),
                        "vault_created": (environment / "private" / "identity-vault.json").is_file(),
                        "extended_vault_created": (environment / "private" / "identity-vault-v2.json").is_file(),
                        "rekeyed_vault_created": (environment / "private" / "identity-vault-rekeyed.json").is_file(),
                        "restored_report_created": (environment / "restored-report" / "restored-report.json").is_file(),
                        "restoration_completion_created": (environment / "restored-report" / "restoration-complete.json").is_file(),
                    },
                    "privacy": {
                        "restored_account_reference": restored_report.get("source", {}).get(
                            "account_reference",
                        ),
                        "restoration_audit_omits_restored_values": ("123456789012" not in json.dumps(restoration_audit, sort_keys=True)),
                    },
                },
            )
            valid = _payload_passed(payload)
            payload["status"] = "passed" if valid else "failed"
            exit_code = 0 if valid else 1
        except Exception as exc:  # noqa: BLE001
            payload["status"] = "failed"
            payload["error"] = f"{type(exc).__name__}: {exc}"
            exit_code = 1
        finally:
            _write_summary(payload, summary_output)
            print(json.dumps(payload, indent=2, sort_keys=True))  # noqa: T201
    return exit_code


def _external_temp_root(repository_root: Path) -> Path:
    """Resolve the labelled smoke environment outside the source checkout."""
    configured = os.environ.get("UNIO_COLLECTOR_EXTERNAL_TEMP_ROOT")
    candidate = Path(configured or tempfile.gettempdir()).resolve()
    if candidate == repository_root or candidate.is_relative_to(repository_root):
        message = "Collector source-isolation smoke requires an OS temporary root outside the repository."
        raise RuntimeError(message)
    candidate.mkdir(parents=True, exist_ok=True)
    return candidate


def _collector_command_matrix(
    *,
    collector: Path,
    python: Path,
    fixture: Path,
    environment: Path,
    live_scan_period_smoke: Path,
) -> dict[str, list[str]]:
    return {
        "version_flag": [str(collector), "--version"],
        "version_command": [str(collector), "version"],
        "package_plan": [
            str(collector),
            "package-plan",
            "--output",
            str(environment / "package-plan.json"),
        ],
        "policy_aws": [
            str(collector),
            "policy",
            "aws",
            "--fixture",
            str(fixture),
            "--only-scanner",
            "root-account-recovery-advisory",
            "--format",
            "json",
            "--output",
            str(environment / "policy-plan.json"),
        ],
        "permission_preview": [
            str(collector),
            "permission-preview",
            "--fixture",
            str(fixture),
            "--only-scanner",
            "root-account-recovery-advisory",
            "--output",
            str(environment / "permission-preview.json"),
        ],
        "doctor": [
            str(collector),
            "doctor",
            "--fixture",
            str(fixture),
            "--output",
            str(environment / "doctor-bundle.zip"),
            "--json-output",
            str(environment / "doctor.json"),
            "--quiet",
        ],
        "runtime_evidence_import": [
            str(python),
            "-c",
            "import unio_collector.scan_workflow.evidence.cloudwatch",
        ],
        "bedrock_operation_limitation": [
            str(python),
            "-c",
            (
                "from dataclasses import asdict; "
                "from unio_collector.aws.bedrock.operation_limitation import "
                "BedrockOperationLimitation; "
                "value = BedrockOperationLimitation("
                "'bedrock:ListCustomModels', "
                "'unsupported_endpoint_operation', "
                "'unsupported_operation', "
                "'UnknownOperationException'); "
                "assert asdict(value)['error_code'] == "
                "'UnknownOperationException'"
            ),
        ],
        "live_scan_period_bundle": [
            str(python),
            str(live_scan_period_smoke),
            str(environment),
        ],
        "collect": [
            str(collector),
            "collect",
            "--fixture",
            str(fixture),
            "--output",
            str(environment / "fixture-bundle.zip"),
            "--quiet",
        ],
        "validate_bundle": [
            str(collector),
            "validate-bundle",
            str(environment / "fixture-bundle.zip"),
        ],
        "privacy_preview": [
            str(collector),
            "privacy",
            "preview",
            "--bundle",
            str(environment / "fixture-bundle.zip"),
            "--json",
        ],
        "privacy_protect": [
            str(collector),
            "privacy",
            "protect",
            "--bundle",
            str(environment / "fixture-bundle.zip"),
            "--output",
            str(environment / "protected-fixture-bundle.zip"),
            "--vault",
            str(environment / "private" / "identity-vault.json"),
            "--passphrase-stdin",
            "--acknowledge-vault-loss-risk",
            "--overwrite",
        ],
        "privacy_protect_reusable": [
            str(collector),
            "privacy",
            "protect",
            "--bundle",
            str(environment / "fixture-bundle.zip"),
            "--output",
            str(environment / "protected-fixture-bundle-v2.zip"),
            "--vault",
            str(environment / "private" / "identity-vault-v2.json"),
            "--existing-vault",
            str(environment / "private" / "identity-vault.json"),
            "--passphrase-stdin",
            "--acknowledge-vault-loss-risk",
            "--overwrite",
        ],
        "privacy_rekey_vault": [
            str(collector),
            "privacy",
            "rekey-vault",
            "--vault",
            str(environment / "private" / "identity-vault-v2.json"),
            "--output-vault",
            str(environment / "private" / "identity-vault-rekeyed.json"),
            "--passphrase-file",
            str(environment / "private" / "existing-passphrase.txt"),
            "--new-passphrase-file",
            str(environment / "private" / "new-passphrase.txt"),
        ],
        "privacy_inspect": [
            str(collector),
            "privacy",
            "inspect",
            "--bundle",
            str(environment / "protected-fixture-bundle.zip"),
            "--json",
        ],
    }


def _run_cli_contract_check(
    *,
    collector: Path,
    python: Path,
    environment: Path,
    snapshot_path: Path,
) -> dict[str, object]:
    """Compare installed parser topology and help with the source contract."""
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    columns = str(snapshot["columns"])
    errors: list[str] = []
    help_routes: dict[str, dict[str, object]] = {}
    for route in snapshot["routes"]:
        route_id = str(route["id"])
        completed = _run(
            [str(collector), *route["argv"], "--help"],
            cwd=environment,
            env_overrides={"COLUMNS": columns},
        )
        digest = hashlib.sha256(completed.stdout.encode("utf-8")).hexdigest()
        matches = digest == route["help_sha256"]
        help_routes[route_id] = {
            "returncode": completed.returncode,
            "help_sha256": digest,
            "matches_snapshot": matches,
        }
        if not matches:
            errors.append(f"installed help differs from snapshot: {route_id}")

    expected_commands = [route["id"] for route in snapshot["routes"] if len(route["argv"]) == 1]
    expected_subcommands: dict[str, list[str]] = {}
    for route in snapshot["routes"]:
        if len(route["argv"]) == 2:  # noqa: PLR2004
            expected_subcommands.setdefault(route["argv"][0], []).append(
                route["argv"][1],
            )
    topology_script = """
import argparse
import json

from unio_collector.collector.package.manifest import build_collector_package_manifest
from unio_collector.collector_cli.catalogue import COLLECTOR_COMMAND_CATALOGUE
from unio_collector.collector_cli.parser import build_parser

parser = build_parser()
top_level = next(
    action
    for action in parser._actions
    if isinstance(action, argparse._SubParsersAction)
)
subcommands = {}
for name, command_parser in top_level.choices.items():
    nested = next(
        (
            action
            for action in command_parser._actions
            if isinstance(action, argparse._SubParsersAction)
        ),
        None,
    )
    if nested is not None:
        subcommands[name] = list(nested.choices)
print(json.dumps({
    "catalogue_commands": [item.name for item in COLLECTOR_COMMAND_CATALOGUE],
    "catalogue_subcommands": {
        item.name: list(item.subcommands)
        for item in COLLECTOR_COMMAND_CATALOGUE
        if item.subcommands
    },
    "manifest_commands": list(build_collector_package_manifest().supported_commands),
    "parser_commands": list(top_level.choices),
    "parser_subcommands": subcommands,
}, sort_keys=True))
""".lstrip()
    topology_result = _run(
        [str(python), "-B", "-c", topology_script],
        cwd=environment,
    )
    topology = json.loads(topology_result.stdout)
    errors.extend(
        f"installed {field} differs from snapshot"
        for field in (
            "catalogue_commands",
            "manifest_commands",
            "parser_commands",
        )
        if topology[field] != expected_commands
    )
    errors.extend(
        f"installed {field} differs from snapshot" for field in ("catalogue_subcommands", "parser_subcommands") if topology[field] != expected_subcommands
    )
    return {
        "status": "ok" if not errors else "failed",
        "errors": errors,
        "help_routes": help_routes,
        **topology,
    }


def _inspect_wheel(*, root: Path, wheel: Path) -> dict[str, object]:
    manifest_module = import_module("unio_collector.collector.package.manifest")
    builder_module = import_module("unio_collector.collector.package.wheel.builder")
    scanner_path_module = import_module("unio_collector.scanners.collection.class_paths")
    scanner_class_paths = scanner_path_module.COLLECTOR_SCANNER_CLASS_PATHS
    plan = manifest_module.build_collector_package_file_plan(root=root)
    inspection = builder_module.CollectorWheelBuilder().inspect_existing_wheel(
        wheel_path=wheel,
        planned_source_files=plan.source_files,
        manifest=plan.manifest,
        scanner_class_paths=scanner_class_paths,
    )
    return {
        "status": inspection.status,
        "member_count": len(inspection.members),
        "required_member_count": len(inspection.required_members),
        "missing_required_members": list(inspection.missing_required_members),
        "unexpected_wheel_members": list(inspection.unexpected_wheel_members),
        "unexpected_application_members": list(inspection.unexpected_application_members),
        "prohibited_members": list(inspection.prohibited_members),
        "provider_implementation_members": list(
            inspection.provider_implementation_members,
        ),
        "metadata_errors": list(inspection.metadata_errors),
        "entrypoint_errors": list(inspection.entrypoint_errors),
    }


def _metadata_requirements(root: Path, required: list[str]) -> list[str]:
    """Keep runtime requirements exact and guard reviewed standalone extras."""
    result = [str(Requirement(value)).lower() for value in required]
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    if project.get("name") != "unio-collector":
        return sorted(result)
    optional = project.get("optional-dependencies", {})
    if not isinstance(optional, dict) or set(optional) - {"dev", "native-build"}:
        message = "Unexpected standalone optional dependency groups."
        raise ValueError(message)
    for extra, dependencies in optional.items():
        if not isinstance(dependencies, list) or not all(isinstance(value, str) for value in dependencies):
            message = "Invalid standalone optional dependencies."
            raise ValueError(message)
        for value in dependencies:
            requirement = Requirement(value)
            guard = f'extra == "{extra}"'
            if requirement.marker:
                guard = f"({requirement.marker}) and {guard}"
            requirement.marker = Marker(guard)
            result.append(str(requirement).lower())
    return sorted(result)


def _run_metadata_check(
    *,
    python: Path,
    environment: Path,
    expected_version: str,
    expected_dependencies: list[str],
) -> dict[str, object]:
    script = environment / "metadata-check.py"
    script.write_text(
        f"""
from __future__ import annotations

import importlib.metadata as metadata
import json
import subprocess
import sys

import unio_collector

expected_version = {expected_version!r}
expected_dependencies = {expected_dependencies!r}
dist = metadata.distribution("unio-collector")
console_scripts = {{
    entry_point.name: entry_point.value
    for entry_point in metadata.entry_points().select(group="console_scripts")
}}
metadata_version = metadata.version("unio-collector")
version_flag = subprocess.run(
    ["unio-collector", "--version"],
    check=False,
    capture_output=True,
    text=True,
)
version_command = subprocess.run(
    ["unio-collector", "version"],
    check=False,
    capture_output=True,
    text=True,
)
expected_output = f"unio-collector {{expected_version}}"
required = sorted(value.strip().lower() for value in expected_dependencies)
declared_with_markers = sorted(value.strip().lower() for value in (dist.requires or ()))
declared = sorted(value.split(";", maxsplit=1)[0].strip().lower() for value in (dist.requires or ()))
prohibited_optional_dependencies = {OPTIONAL_NON_AWS_SDK_DISTRIBUTIONS!r}
declared_names = {{value.split("[", maxsplit=1)[0].split(">", maxsplit=1)[0].split("=", maxsplit=1)[0].strip().lower() for value in declared}}
unexpected_optional_dependencies = sorted(declared_names & set(prohibited_optional_dependencies))
errors = []
if dist.metadata["Name"] != "unio-collector":
    errors.append("metadata name mismatch")
if metadata_version != expected_version:
    errors.append("metadata version mismatch")
if unio_collector.__version__ != expected_version:
    errors.append("unio_collector.__version__ mismatch")
if version_flag.stdout.strip() != expected_output:
    errors.append("--version output mismatch")
if version_command.stdout.strip() != expected_output:
    errors.append("version command output mismatch")
if console_scripts.get("unio-collector") != "unio_collector.collector_cli.app:main":
    errors.append("collector console script mismatch")
if "unio" in console_scripts:
    errors.append("full Unio console script present")
if required != declared_with_markers:
    errors.append("dependency metadata mismatch")
if unexpected_optional_dependencies:
    errors.append("optional non-AWS SDK dependencies present")
payload = {{
    "status": "ok" if not errors else "failed",
    "errors": errors,
    "distribution_name": dist.metadata["Name"],
    "metadata_version": metadata_version,
    "unio_collector_version": unio_collector.__version__,
    "version_flag_output": version_flag.stdout.strip(),
    "version_command_output": version_command.stdout.strip(),
    "collector_console_script": console_scripts.get("unio-collector"),
    "full_console_script_present": "unio" in console_scripts,
    "requires_dist": declared,
    "unexpected_optional_dependencies": unexpected_optional_dependencies,
}}
print(json.dumps(payload, sort_keys=True))  # noqa: T201
raise SystemExit(0 if payload["status"] == "ok" else 1)
""".lstrip(),
        encoding="utf-8",
    )
    result = _run([str(python), str(script)], cwd=environment)
    return json.loads(result.stdout)


def _run_provider_boundary_check(
    *,
    python: Path,
    environment: Path,
    root: Path,
) -> dict[str, object]:
    policy_module = import_module(
        "unio_collector.collector.package.provider_boundary",
    )
    manifest_module = import_module("unio_collector.collector.package.manifest")
    manifest = manifest_module.build_collector_package_manifest(root=root)
    boundary = policy_module.CollectorProviderBoundary.from_manifest(manifest)
    provider_root = root / "unio_collector" / "providers"
    repository_provider_modules = tuple(
        f"unio_collector.providers.{path.stem if path.is_file() else path.name}"
        for path in sorted(provider_root.iterdir())
        if path.name != "__pycache__" and (path.is_dir() or path.suffix == ".py") and path.name != "__init__.py"
    )
    disallowed_providers = boundary.module_violations(
        repository_provider_modules,
    )
    allowed_imports = (
        "unio_collector.providers.aws.runtime",
        "unio_collector.providers.runtime.contract",
    )
    script = environment / "provider-boundary-check.py"
    script.write_text(
        _provider_boundary_script(
            allowed_imports=allowed_imports,
            disallowed_providers=disallowed_providers,
        ),
        encoding="utf-8",
    )
    result = _run([str(python), str(script)], cwd=environment)
    return json.loads(result.stdout)


def _provider_boundary_script(
    *,
    allowed_imports: tuple[str, ...],
    disallowed_providers: tuple[str, ...],
) -> str:
    """Build the installed-environment provider importability check."""
    return f"""
from __future__ import annotations

import importlib
import importlib.util
import json

allowed_imports = {allowed_imports!r}
disallowed_providers = {disallowed_providers!r}
optional_sdk_imports = {OPTIONAL_NON_AWS_SDK_IMPORTS!r}
errors = []
imported = []
for module_name in allowed_imports:
    try:
        importlib.import_module(module_name)
        imported.append(module_name)
    except Exception as exc:
        errors.append(f"allowed provider import failed: {{module_name}}: {{type(exc).__name__}}: {{exc}}")
unexpected_provider_imports = []
for module_name in disallowed_providers:
    try:
        spec = importlib.util.find_spec(module_name)
    except ModuleNotFoundError:
        spec = None
    if spec is not None:
        unexpected_provider_imports.append(module_name)
unexpected_sdk_imports = []
for module_name in optional_sdk_imports:
    try:
        spec = importlib.util.find_spec(module_name)
    except ModuleNotFoundError:
        spec = None
    if spec is not None:
        unexpected_sdk_imports.append(module_name)
if unexpected_provider_imports:
    errors.append("disallowed provider implementations are importable")
if unexpected_sdk_imports:
    errors.append("optional non-AWS SDKs are importable")
payload = {{
    "status": "ok" if not errors else "failed",
    "errors": errors,
    "allowed_imports": list(allowed_imports),
    "imported": imported,
    "disallowed_providers": list(disallowed_providers),
    "unexpected_provider_imports": unexpected_provider_imports,
    "optional_sdk_imports": list(optional_sdk_imports),
    "unexpected_sdk_imports": unexpected_sdk_imports,
}}
print(json.dumps(payload, sort_keys=True))  # noqa: T201
raise SystemExit(0 if payload["status"] == "ok" else 1)
""".lstrip()


def _run_source_isolation_check(
    *,
    python: Path,
    environment: Path,
    root: Path,
) -> dict[str, object]:
    script = environment / "source-isolation-check.py"
    script.write_text(
        f"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

import unio_collector
from unio_collector.collector.package.manifest import COLLECTOR_FORBIDDEN_PREFIXES

root = Path({str(root)!r}).resolve()
origin = Path(unio_collector.__file__).resolve()
sys_path_under_root = sorted(
    str(Path(value).resolve())
    for value in sys.path
    if value and (Path(value).resolve() == root or root in Path(value).resolve().parents)
)
prohibited_importable = []
for prefix in COLLECTOR_FORBIDDEN_PREFIXES:
    try:
        spec = importlib.util.find_spec(prefix)
    except ModuleNotFoundError:
        spec = None
    if spec is not None:
        prohibited_importable.append(prefix)
payload = {{
    "status": "ok" if not sys_path_under_root and root not in origin.parents and not prohibited_importable else "failed",
    "unio_collector_origin": str(origin),
    "origin_under_source_root": root in origin.parents,
    "source_paths_on_sys_path": sys_path_under_root,
    "prohibited_importable": prohibited_importable,
    "pythonpath": os.environ.get("PYTHONPATH"),
    "python_no_user_site": True,
}}
print(json.dumps(payload, sort_keys=True))  # noqa: T201
raise SystemExit(0 if payload["status"] == "ok" else 1)
""".lstrip(),
        encoding="utf-8",
    )
    result = _run([str(python), str(script)], cwd=environment)
    return json.loads(result.stdout)


def _payload_passed(payload: dict[str, object]) -> bool:
    commands = payload.get("commands", {})
    command_results = commands.values() if isinstance(commands, dict) else ()
    entrypoints = payload.get("entrypoints", {})
    artifacts = payload.get("artifacts", {})
    privacy = payload.get("privacy", {})
    wheel_members = payload.get("wheel_members", {})
    scanner_registry = payload.get("scanner_registry", {})
    package_plan = payload.get("package_plan", {})
    doctor = payload.get("doctor", {})
    metadata = payload.get("metadata", {})
    source_isolation = payload.get("source_isolation", {})
    provider_boundary = payload.get("provider_boundary", {})
    cli_contract = payload.get("cli_contract", {})
    return (
        _section_status(payload.get("install")) == "passed"
        and all(_section_status(result) == "passed" for result in command_results)
        and _section_status(payload.get("restore_report")) == "passed"
        and isinstance(package_plan, dict)
        and package_plan.get("status") == "valid"
        and isinstance(doctor, dict)
        and doctor.get("status") == "ok"
        and isinstance(scanner_registry, dict)
        and scanner_registry.get("status") == "ok"
        and scanner_registry.get("constructed_count") == scanner_registry.get("expected_count")
        and scanner_registry.get("installed_registry_count") == scanner_registry.get("expected_count")
        and scanner_registry.get("missing_installed_registry_ids") == []
        and scanner_registry.get("unexpected_installed_registry_ids") == []
        and scanner_registry.get("missing_scanner_definitions") == []
        and scanner_registry.get("forbidden_module_count") == 0
        and isinstance(metadata, dict)
        and metadata.get("status") == "ok"
        and isinstance(source_isolation, dict)
        and source_isolation.get("status") == "ok"
        and isinstance(provider_boundary, dict)
        and provider_boundary.get("status") == "ok"
        and isinstance(cli_contract, dict)
        and cli_contract.get("status") == "ok"
        and isinstance(wheel_members, dict)
        and wheel_members.get("status") == "valid"
        and isinstance(entrypoints, dict)
        and entrypoints.get("collector_entrypoint_installed") is True
        and entrypoints.get("full_entrypoint_installed") is False
        and isinstance(artifacts, dict)
        and artifacts.get("fixture_bundle_created") is True
        and artifacts.get("live_scan_period_bundle_created") is True
        and artifacts.get("protected_bundle_created") is True
        and artifacts.get("protected_receipt_created") is True
        and artifacts.get("vault_created") is True
        and artifacts.get("extended_vault_created") is True
        and artifacts.get("rekeyed_vault_created") is True
        and artifacts.get("restored_report_created") is True
        and artifacts.get("restoration_completion_created") is True
        and isinstance(privacy, dict)
        and privacy.get("restored_account_reference") == "123456789012"
        and privacy.get("restoration_audit_omits_restored_values") is True
    )


def _section_status(value: object) -> str | None:
    if isinstance(value, dict):
        return str(value.get("status"))
    return None


def _privacy_stdin(command_name: str) -> str | None:
    if command_name.startswith("privacy_protect"):
        return "test-passphrase\n"
    return None


def _write_private_smoke_secret(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value + "\n", encoding="utf-8")
    if os.name != "nt":
        path.chmod(0o600)


def _command_summary(completed: subprocess.CompletedProcess[str]) -> dict[str, object]:
    return {
        "status": "passed" if completed.returncode == 0 else "failed",
        "returncode": completed.returncode,
        "stdout": completed.stdout.strip(),
        "stderr": completed.stderr.strip(),
    }


def _write_summary(payload: dict[str, object], summary_output: Path | None) -> None:
    if summary_output is None:
        return
    summary_output.parent.mkdir(parents=True, exist_ok=True)
    summary_output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run(
    command: list[str],
    *,
    cwd: Path,
    stdin_text: str | None = None,
    env_overrides: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env["PYTHONNOUSERSITE"] = "1"
    env.setdefault("PIP_DISABLE_PIP_VERSION_CHECK", "1")
    env.setdefault("PIP_NO_INPUT", "1")
    env.setdefault("PIP_CACHE_DIR", str(cwd / "pip-cache"))
    env.update(env_overrides or {})
    script_dir = cwd / ("Scripts" if os.name == "nt" else "bin")
    env["PATH"] = f"{script_dir}{os.pathsep}{env.get('PATH', '')}"
    completed = subprocess.run(  # noqa: S603
        command,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        input=stdin_text,
        env=env,
    )
    if completed.returncode != 0:
        msg = f"Collector wheel validation command failed: {command}\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        raise RuntimeError(msg)
    return completed


def _run_scanner_construction_check(
    *,
    python: Path,
    environment: Path,
) -> dict[str, object]:
    scanner_path_module = import_module("unio_collector.scanners.collection.class_paths")
    scanner_class_paths = scanner_path_module.COLLECTOR_SCANNER_CLASS_PATHS
    script = environment / "scanner-construction-smoke.py"
    script_template = """
from __future__ import annotations

import importlib
import io
import json
import sys
from types import SimpleNamespace
from unittest.mock import patch

from unio_collector.collector.package.manifest import COLLECTOR_FORBIDDEN_PREFIXES
from unio_collector.core.scan.period_resolver import ScanPeriodResolver
from unio_collector.scanners.collection.class_paths import COLLECTOR_SCANNER_CLASS_PATHS
from unio_collector.scanners.collection.path_factory import build_scanner_from_collector_factory_path
from unio_collector.scanners.registry import list_scanners
from unio_collector.scanners.scanner.evidence_serializer import build_scanner_evidence_payload

EXPECTED_COLLECTOR_SCANNER_CLASS_PATHS = __EXPECTED_COLLECTOR_SCANNER_CLASS_PATHS__

errors: list[str] = []
if COLLECTOR_SCANNER_CLASS_PATHS != EXPECTED_COLLECTOR_SCANNER_CLASS_PATHS:
    errors.append("installed collector scanner class-path registry differs from approved registry")
definitions = {definition.scanner_id: definition for definition in list_scanners()}
constructed: list[str] = []
for scanner_id, class_path in sorted(EXPECTED_COLLECTOR_SCANNER_CLASS_PATHS.items()):
    module_name, separator, attribute_name = class_path.partition(":")
    if not scanner_id:
        errors.append("empty scanner id")
        continue
    if not separator or not module_name or not attribute_name:
        errors.append(f"{scanner_id}: malformed class path {class_path!r}")
        continue
    try:
        module = importlib.import_module(module_name)
        getattr(module, attribute_name)
        definition = definitions[scanner_id]
        build_scanner_from_collector_factory_path(scanner_id, definition)
    except Exception as exc:  # noqa: BLE001
        errors.append(f"{scanner_id}: {type(exc).__name__}: {exc}")
        continue
    constructed.append(scanner_id)
installed_ids = set(COLLECTOR_SCANNER_CLASS_PATHS)
approved_ids = set(EXPECTED_COLLECTOR_SCANNER_CLASS_PATHS)
registry_ids = set(definitions)
missing_installed_registry_ids = sorted(approved_ids - installed_ids)
unexpected_installed_registry_ids = sorted(installed_ids - approved_ids)
missing_scanner_definitions = sorted(approved_ids - registry_ids)
cur_calls = []
def read_billing_object(*, Bucket, Key):
    cur_calls.append([Bucket, Key])
    return {"Body": io.BytesIO(
        b"usage_start_date,cost,currency,service,region,resource_id,resourceTags/user:Project\\n"
        b"2026-05-01,0.004,USD,Amazon EC2,eu-west-2,resource-1,Example"
    )}
cur_config = SimpleNamespace(
    cur_paths=("s3://billing-bucket/cur/billing.csv",),
    scan_period=ScanPeriodResolver().resolve(date_from="2026-05-01", date_to="2026-05-31"),
    cost_grouping_tags=("Project",),
)
cur_context = SimpleNamespace(
    options=SimpleNamespace(get_config=lambda: cur_config),
    security=SimpleNamespace(
        create_client=lambda *args, **kwargs: SimpleNamespace(get_object=read_billing_object),
        session=SimpleNamespace(get_region_name=lambda: "eu-west-2"),
    ),
)
with (
    patch("boto3.session.Session.__init__", side_effect=AssertionError("AWS session forbidden")),
    patch("botocore.session.Session.create_client", side_effect=AssertionError("AWS client forbidden")),
):
    cur_scanner = build_scanner_from_collector_factory_path("cur-data-export-attribution", definitions["cur-data-export-attribution"])
    cur_evidence = cur_scanner.collect(cur_context)
    json.dumps(build_scanner_evidence_payload(scanner_id="cur-data-export-attribution", evidence=cur_evidence))
    assert cur_calls == [["billing-bucket", "cur/billing.csv"]]
    assert cur_evidence.collection_evidence_version == 1
    assert cur_evidence.findings == [] and cur_evidence.summary == {}
    assert cur_evidence.billing_facts["rows_matched"] == 1
    assert cur_evidence.billing_facts["total_cost"] == "0.004"
    assert cur_evidence.billing_facts["collection_status"] == "complete"
    assert set(cur_evidence.billing_facts["tag_groups"][0]) == {"group_key", "group_value", "estimated_cost"}
forbidden_modules = sorted(
    name
    for name in sys.modules
    if any(
        name == prefix or name.startswith(f"{prefix}.")
        for prefix in COLLECTOR_FORBIDDEN_PREFIXES
    )
)
payload = {
            "status": "ok" if not errors and not forbidden_modules else "failed",
    "constructed_count": len(constructed),
    "expected_count": len(EXPECTED_COLLECTOR_SCANNER_CLASS_PATHS),
    "installed_registry_count": len(COLLECTOR_SCANNER_CLASS_PATHS),
    "missing_installed_registry_ids": missing_installed_registry_ids,
    "unexpected_installed_registry_ids": unexpected_installed_registry_ids,
    "missing_scanner_definitions": missing_scanner_definitions,
    "cur_collection": {"status": "passed", "read_count": len(cur_calls), "rows_matched": cur_evidence.billing_facts["rows_matched"], "aws_runtime": "blocked"},
    "errors": errors,
    "forbidden_module_count": len(forbidden_modules),
    "forbidden_modules": forbidden_modules,
}
if missing_installed_registry_ids or unexpected_installed_registry_ids or missing_scanner_definitions:
    payload["status"] = "failed"
print(json.dumps(payload, sort_keys=True))  # noqa: T201
raise SystemExit(0 if payload["status"] == "ok" else 1)
""".lstrip()
    script.write_text(
        script_template.replace(
            "__EXPECTED_COLLECTOR_SCANNER_CLASS_PATHS__",
            repr(scanner_class_paths),
        ),
        encoding="utf-8",
    )
    result = _run([str(python), str(script)], cwd=environment)
    return json.loads(result.stdout)


def _write_live_scan_period_smoke(environment: Path) -> Path:
    script = environment / "live-scan-period-smoke.py"
    script.write_text(
        """
from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from zipfile import ZipFile

from unio_collector.collector.bundle.collection_writer import CollectorEvidenceBundleWriter
from unio_collector.collector.bundle.validator import EvidenceBundleValidator
from unio_collector.collector.execution.result import CollectorExecutionResult
from unio_collector.collector.config.factory import CollectorConfigFactory
from unio_collector.collector.config.input import CollectorConfigInput
from unio_collector.evidence.collection_store import CollectionEvidenceStore
from unio_collector.providers.runtime.ledger import EmptyProviderApiCallLedger
from unio_collector.scanners.scanner.result import ScannerExecutionResult

environment = Path(sys.argv[1])
config = CollectorConfigFactory().build(CollectorConfigInput(
    profile=None,
    date_from="2026-01-01",
    date_to="2026-01-31",
    output=environment / "live-reports",
    fixture=None,
    regions=["eu-west-2"],
))
assert config.absolute_threshold is None and config.percent_threshold is None
assert config.required_tags == () and config.analysis_defaults_deferred is True
assert "unio_collector.config.runtime" not in sys.modules
if hasattr(config.scan_period, "model_dump"):
    raise AssertionError("live-shaped ScanPeriod unexpectedly exposes model_dump")
now = datetime(2026, 2, 1, 12, 0, tzinfo=UTC)
result = CollectorExecutionResult(
    provider_id="aws",
    generated_at=now,
    account_context={
        "account_id": "123456789012",
        "arn": "arn:aws:iam::123456789012:root",
    },
    scan_period=config.scan_period,
    scanner_results=[
        ScannerExecutionResult(
            scanner_id="live-shape-smoke",
            status="completed",
            started_at=now,
            completed_at=now,
            regions_scanned=["eu-west-2"],
            aws_api_calls=["sts:GetCallerIdentity"],
            evidence_count=1,
            implementation_type="live_smoke",
        ),
    ],
    ledger=EmptyProviderApiCallLedger(),
    evidence_store=CollectionEvidenceStore(),
    config=config,
    scanner_evidence_payloads=[
        {
            "scanner_id": "live-shape-smoke",
            "serialization_status": "serialized",
            "evidence_type": "LiveShapeSmokeEvidence",
            "provider_id": "aws",
            "payload": {},
            "limitations": [],
        },
    ],
    collection_summary={
        "source": "live",
        "region_scope": {
            "scope_version": "2026-07",
            "selection_mode": "account_enabled",
            "explicit_region_scope": False,
            "discovery_status": "succeeded",
            "selected_regions": ["eu-west-2"],
            "enabled_regions": ["eu-west-2"],
            "excluded_regions": [
                {
                    "region_name": "ap-east-1",
                    "opt_in_status": "not-opted-in",
                    "status": "excluded",
                    "reason": "account_region_not_enabled",
                },
            ],
            "excluded_region_count": 1,
            "limitations": [
                (
                    "Regional AWS collection was limited to account-enabled regions; "
                    "regions that were disabled, not opted in, unsupported, or unknown were excluded."
                ),
            ],
        },
    },
)
bundle = environment / "live-shaped-bundle.zip"
CollectorEvidenceBundleWriter().write(path=bundle, result=result)
validation = EvidenceBundleValidator().validate(bundle)
if not validation.passed:
    raise AssertionError(validation.errors)
with ZipFile(bundle, "r") as archive:
    account_scope = json.loads(archive.read("account-scope.json").decode("utf-8"))
    manifest = json.loads(archive.read("manifest.json").decode("utf-8"))
    report_bundle = json.loads(
        archive.read("scan-result/report-bundle.json").decode("utf-8"),
    )
expected = {
    "kind": "date_range",
    "raw_input": {"date_from": "2026-01-01", "date_to": "2026-01-31"},
    "current_start_date": "2026-01-01",
    "current_end_date": "2026-01-31",
    "previous_start_date": "2025-12-01",
    "previous_end_date": "2025-12-31",
    "duration_days": 31,
    "selected_duration": "explicit date range",
}
if account_scope["scan_period"] != expected:
    raise AssertionError(account_scope["scan_period"])
if report_bundle["scan_period"] != expected:
    raise AssertionError(report_bundle["scan_period"])
if manifest["region_scope"]["excluded_region_count"] != 1:
    raise AssertionError(manifest["region_scope"])
print(json.dumps({"status": "ok", "bundle": str(bundle)}, sort_keys=True))  # noqa: T201
""".lstrip(),
        encoding="utf-8",
    )
    return script


def _write_unsigned_restore_package(environment: Path) -> Path:
    protected_bundle = environment / "protected-fixture-bundle.zip"
    with ZipFile(protected_bundle, "r") as archive:
        manifest = json.loads(archive.read("manifest.json").decode("utf-8"))
        account_scope = json.loads(archive.read("account-scope.json").decode("utf-8"))
    privacy = manifest["privacy_protection"]
    account_reference = account_scope["account_id"]
    package = {
        "package_schema_version": "2026-03-protected-report-package-json-v1",
        "package_type": "unio_protected_report_package_json_v1",
        "package_format": "signed_structured_json_v1",
        "signature": {
            "status": "unsigned",
            "signature_algorithm": None,
            "key_id": None,
            "created_at": None,
            "signed_payload": None,
        },
        "source": {
            "run_id": manifest.get("run_id"),
            "provider": manifest.get("provider") or "aws",
            "account_reference": account_reference,
            "protected_bundle_id": privacy.get("protected_bundle_id"),
            "engagement_id": privacy.get("engagement_id"),
            "token_scope": privacy.get("token_scope"),
        },
        "privacy": privacy,
        "restoration": {
            "status": "supported_by_collector_restore_report",
            "local_restore_report_command_available": True,
            "restoration_material_required": True,
        },
        "scan_period": {},
        "summary": {
            "finding_count": 0,
            "services": [],
            "total_cost": "0.00",
            "currency": "USD",
        },
        "findings": [],
        "limitations": [],
    }
    path = environment / "protected-report-package.json"
    path.write_text(json.dumps(package, indent=2, sort_keys=True), encoding="utf-8")
    return path


if __name__ == "__main__":
    raise SystemExit(main())
