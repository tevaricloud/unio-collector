from __future__ import annotations  # noqa: D100

import tomllib
from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from typing import TYPE_CHECKING, Any

from unio_collector import __version__
from unio_collector.collector.package.provider_boundary import CollectorProviderBoundary
from unio_collector.collector_cli.catalogue import collector_command_names

if TYPE_CHECKING:
    from unio_collector.collector.package.file.plan import CollectorPackageFilePlan


COLLECTOR_FORBIDDEN_PREFIXES = (
    "unio_collector.analyzers",
    "unio_collector.reports",
    "unio_collector.report_workflow",
    "unio_collector.llm",
    "unio_collector.framework_readiness",
    "unio_collector.offline_analyzer",
    "unio_collector.commercial",
    "unio_collector.consultancy",
    "unio_collector.compliance_readiness",
    "unio_collector.cleanup",
    "unio_collector.automation",
    "unio_collector.baseline",
    "unio_collector.attack_paths",
    "unio_collector.control_mapping",
    "unio_collector.cli_app",
    "unio_collector.devtools",
    "unio_collector.mcp",
    "unio_collector.static_analysis",
    "unio_collector.tickets",
    "unio_collector.topology.diagram",
    "unio_collector.topology.diagrams",
    "unio_collector.topology.exports",
    "unio_collector.topology.graph_builder",
    "unio_collector.topology.limitations",
    "unio_collector.topology.payload_builder",
    "unio_collector.topology.provider_metadata",
    "unio_collector.topology.record_values",
    "unio_collector.topology.relationship_adapter",
    "unio_collector.config.file",
    "unio_collector.config.llm",
    "unio_collector.config.loader",
    "unio_collector.config.reference",
    "unio_collector.config.scan.file",
    "unio_collector.config.scan.file_loader",
)


REQUIRED_COLLECTOR_EXCLUDE_PREFIXES = COLLECTOR_FORBIDDEN_PREFIXES


@dataclass(frozen=True)
class CollectorPackageManifest:
    """Machine-readable contract for the collector-only Python distribution."""

    artifact_name: str = "unio-collector"
    version: str = __version__
    schema_version: str = "2026-02"
    distribution_model: str = "collector_only_python_wheel"
    supported_commands: tuple[str, ...] = collector_command_names()
    include_package_prefixes: tuple[str, ...] = (
        "unio_collector.collector",
        "unio_collector.collector_cli",
        "unio_collector.collector_launcher",
        "unio_collector.privacy",
        "unio_collector.protected_reports",
        "unio_collector.aws",
        "unio_collector.aws_native_recommendations",
        "unio_collector.billing",
        "unio_collector.config",
        "unio_collector.commitments",
        "unio_collector.core",
        "unio_collector.evidence",
        "unio_collector.findings",
        "unio_collector.pricing",
        "unio_collector.providers",
        "unio_collector.products",
        "unio_collector.runtime_diagnostics",
        "unio_collector.scan_workflow",
        "unio_collector.scanners",
        "unio_collector.topology",
    )
    exclude_package_prefixes: tuple[str, ...] = REQUIRED_COLLECTOR_EXCLUDE_PREFIXES
    planned_artifacts: tuple[str, ...] = ("unio_collector-{version}-py3-none-any.whl",)
    metadata_files: tuple[str, ...] = (
        "README.md",
        "docs/collector-workflow.md",
        "docs/evidence-bundles.md",
        "docs/offline-aws-development.md",
        "docs/package-layout.md",
        "pyproject.toml",
    )
    entrypoints: dict[str, str] | None = None
    optional_dependencies: dict[str, tuple[str, ...]] | None = None
    required_dependencies: tuple[str, ...] = (
        "argon2-cffi>=23.1",
        "boto3>=1.34",
        "cryptography>=42.0",
        "pydantic>=2.7",
        "PyYAML>=6.0",
    )
    included_provider_implementations: tuple[str, ...] = ("unio_collector.providers.aws",)
    dynamic_factory_paths: tuple[str, ...] = (
        "unio_collector.providers.aws.collection.executor:AwsProviderCollectionExecutor",
        "unio_collector.providers.aws.runtime:AwsProviderRuntime",
        "unio_collector.scan_workflow.runner:ScannerRunner",
        "unio_collector.scan_workflow.scanner.collection.dependency_factory:ScannerCollectionDependencyFactory",
        "unio_collector.scan_workflow.scanner.collection.run_service:ScannerCollectionRunService",
        "unio_collector.scan_workflow.scanner.collection.service:ScannerCollectionService",
        "unio_collector.scanners.collection.path_factory:build_scanner_from_collector_factory_path",
        "unio_collector.scanners.collection.factory:build_collector_scanner",
        "unio_collector.collector.config.factory:CollectorConfigFactory",
        "unio_collector.evidence.permission.planning.builder:PermissionPlanBuilder",
        "unio_collector.collector_cli.services.privacy:CollectorPrivacyService",
        "unio_collector.collector_launcher.app:main",
        "unio_collector.collector.package.native.manifest:build_native_collector_manifest",
    )
    included_data_files: tuple[str, ...] = ()
    included_schema_files: tuple[str, ...] = ("unio_collector.collector.bundle.schema",)
    platform_considerations: tuple[str, ...] = (
        "The initial collector artifact is a Python 3.12 platform-neutral wheel.",
        "The AWS SDK is installed as a required dependency.",
        "Full and collector-only distributions must be installed in separate environments.",
    )
    warnings: tuple[str, ...] = (
        "The collector build produces a Python wheel, not a signed native binary.",
        "Analyzer, report, LLM, commercial, and internal report-generation modules are excluded.",
        "Chargeable scanners remain blocked unless explicitly enabled.",
    )
    known_limitations: tuple[str, ...] = (
        "The initial standalone collector distribution supports AWS only.",
        "Azure, Entra, and GCP remain available only in the full application.",
        "No SaaS upload capability is included in this distribution.",
        "Protected report-package creation, signing verification, and local restoration are JSON/Markdown/HTML only; PDF remains out of scope.",
    )

    typing_source_files: tuple[str, ...] = (
        "unio_collector/billing/service_spend.py",
        "unio_collector/collector/config/protocol.py",
        "unio_collector/core/attempt.py",
        "unio_collector/core/console_like.py",
        "unio_collector/evidence/permission/planning/rendering/policy_status.py",
        "unio_collector/evidence/permission/planning/resolved_scope.py",
        "unio_collector/providers/finding_source.py",
        "unio_collector/scan_workflow/aws/scan/contracts.py",
        "unio_collector/scan_workflow/evidence/adapter_target.py",
        "unio_collector/scan_workflow/runner/evidence_gateway/protocols/__init__.py",
        "unio_collector/scan_workflow/runner/evidence_gateway/protocols/cloudwatch.py",
        "unio_collector/scan_workflow/runner/evidence_gateway/protocols/cost.py",
        "unio_collector/scan_workflow/runner/evidence_gateway/protocols/lambda_inventory.py",
        "unio_collector/scan_workflow/runner/evidence_gateway/protocols/notes.py",
        "unio_collector/scan_workflow/runner/evidence_gateway/protocols/prefetch.py",
        "unio_collector/scan_workflow/runner/evidence_gateway/protocols/regional.py",
        "unio_collector/scan_workflow/runner/evidence_gateway/protocols/s3.py",
        "unio_collector/scan_workflow/runner/evidence_gateway/protocols/source.py",
        "unio_collector/scan_workflow/runner/evidence_gateway/protocols/tagging.py",
        "unio_collector/scan_workflow/runner/merge_contract.py",
        "unio_collector/scan_workflow/runner/summary_contract.py",
        "unio_collector/scan_workflow/scanner/entrypoint_contract.py",
        "unio_collector/scan_workflow/scanner/executor_contract.py",
        "unio_collector/scan_workflow/scanner/helper_contract.py",
        "unio_collector/scan_workflow/scanner/operation.py",
        "unio_collector/scan_workflow/scanner/orchestration_contract.py",
        "unio_collector/scan_workflow/scanner/payload_storage_target.py",
        "unio_collector/scan_workflow/scanner/precheck_contract.py",
        "unio_collector/scan_workflow/scanner/runner_parent_contract.py",
        "unio_collector/scan_workflow/scanner/runtime/adapter_contract.py",
        "unio_collector/scan_workflow/scanner/runtime/execution_contract.py",
        "unio_collector/scan_workflow/scanner/scan_note_target.py",
        "unio_collector/scanners/scanner/collection_protocol.py",
        "unio_collector/scanners/scanner/gateway/protocols/__init__.py",
        "unio_collector/scanners/scanner/gateway/protocols/analysis.py",
        "unio_collector/scanners/scanner/gateway/protocols/cloudwatch.py",
        "unio_collector/scanners/scanner/gateway/protocols/cost.py",
        "unio_collector/scanners/scanner/gateway/protocols/data.py",
        "unio_collector/scanners/scanner/gateway/protocols/ec2.py",
        "unio_collector/scanners/scanner/gateway/protocols/finding.py",
        "unio_collector/scanners/scanner/gateway/protocols/lambda_.py",
        "unio_collector/scanners/scanner/gateway/protocols/network.py",
        "unio_collector/scanners/scanner/gateway/protocols/options.py",
        "unio_collector/scanners/scanner/gateway/protocols/s3.py",
        "unio_collector/scanners/scanner/gateway/protocols/security.py",
        "unio_collector/scanners/scanner/gateway/protocols/tagging.py",
        "unio_collector/scanners/scanner/gateway/protocols/warning.py",
        "unio_collector/scanners/scanner/hooks.py",
        "unio_collector/scanners/scanner/runtime_protocol.py",
    )

    def convert_to_dict(self) -> dict[str, Any]:  # noqa: D102
        entrypoints = self.entrypoints or {
            "unio-collector": "unio_collector.collector_cli.app:main",
        }
        optional_dependencies = self.optional_dependencies or {}
        return {
            "artifact_name": self.artifact_name,
            "collector_package_name": self.artifact_name,
            "version": self.version,
            "schema_version": self.schema_version,
            "distribution_model": self.distribution_model,
            "supported_commands": list(self.supported_commands),
            "expected_commands": list(self.supported_commands),
            "entrypoints": dict(entrypoints),
            "include_package_prefixes": list(self.include_package_prefixes),
            "exclude_package_prefixes": list(self.exclude_package_prefixes),
            "optional_dependencies": {name: list(values) for name, values in sorted(optional_dependencies.items())},
            "required_dependencies": list(self.required_dependencies),
            "included_provider_implementations": list(
                self.included_provider_implementations,
            ),
            "dynamic_factory_paths": list(self.dynamic_factory_paths),
            "included_data_files": list(self.included_data_files),
            "included_schema_files": list(self.included_schema_files),
            "platform_considerations": list(self.platform_considerations),
            "planned_artifacts": [artifact.format(version=self.version) for artifact in self.planned_artifacts],
            "metadata_files": list(self.metadata_files),
            "typing_source_files": list(self.typing_source_files),
            "warnings": list(self.warnings),
            "known_limitations": list(self.known_limitations),
        }

    def validate(self) -> list[str]:  # noqa: D102
        errors: list[str] = []
        if tuple(sorted(set(self.typing_source_files))) != self.typing_source_files:
            errors.append("Collector typing contract paths must be sorted and unique.")
        errors.extend(
            f"Collector typing contract path is unsafe: {name}."
            for name in self.typing_source_files
            if not name.startswith("unio_collector/")
            or not name.endswith(".py")
            or not all(part.isidentifier() for part in name.removesuffix(".py").split("/"))
        )
        if not self.artifact_name:
            errors.append("Collector artifact name is required.")
        if not self.version:
            errors.append("Collector artifact version is required.")
        if "collect" not in self.supported_commands:
            errors.append("Collector artifact must support evidence collection.")
        if "validate-bundle" not in self.supported_commands:
            errors.append("Collector artifact must support bundle validation.")
        if "doctor" not in self.supported_commands:
            errors.append("Collector artifact must support collector preflight checks.")
        if "privacy" not in self.supported_commands:
            errors.append("Collector artifact must support privacy protection commands.")
        errors.extend(
            f"Package prefix is both included and excluded: {prefix}" for prefix in self.exclude_package_prefixes if prefix in self.include_package_prefixes
        )
        errors.extend(
            f"Collector artifact must exclude {forbidden}." for forbidden in COLLECTOR_FORBIDDEN_PREFIXES if forbidden not in self.exclude_package_prefixes
        )
        errors.extend(
            CollectorProviderBoundary.from_manifest(self).manifest_errors(),
        )
        return errors


def build_collector_package_manifest(
    *,
    root: Path | None = None,
) -> CollectorPackageManifest:
    """Build collector metadata from the repository project contract."""
    project_path = (root or Path()) / "pyproject.toml"
    if not project_path.is_file():
        return CollectorPackageManifest()
    project = tomllib.loads(project_path.read_text(encoding="utf-8"))
    dependencies = tuple(str(value) for value in project.get("project", {}).get("dependencies", []))
    requires_python = str(
        project.get("project", {}).get("requires-python", ">=3.12"),
    )
    return CollectorPackageManifest(
        required_dependencies=dependencies,
        platform_considerations=(
            f"The initial collector artifact uses the repository Python contract ({requires_python}).",
            "The AWS SDK is installed as a required dependency.",
            "Full and collector-only distributions must be installed in separate environments.",
        ),
    )


def build_collector_package_file_plan(  # noqa: D103
    *,
    root: Path | None = None,
    manifest: CollectorPackageManifest | None = None,
) -> CollectorPackageFilePlan:
    builder = import_module(
        "unio_collector.collector.package.file.builder",
    )

    return builder.CollectorPackageFilePlanBuilder().build(root=root, manifest=manifest)
