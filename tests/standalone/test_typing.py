"""Public typing interfaces remain precise and separate from private implementations."""

from __future__ import annotations

import ast
import tomllib
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from unio_collector.collector.package.manifest import build_collector_package_file_plan

if TYPE_CHECKING:
    from typing import assert_type

    from unio_collector.scan_workflow.organization.attempt.request import OrganizationAttemptRequest
    from unio_collector.scan_workflow.scanner.runtime.dependencies import ScannerRuntimeDependencies
    from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
    from unio_collector.scanners.network.vpc_endpoint.evidence import VpcEndpointOpportunityEvidence
    from unio_collector.scanners.scanner.context import ScannerContext
    from unio_collector.scanners.scanner.definition import ScannerDefinition

    class _NumericScanner(BaseUnioScanner):
        def analyze(self, evidence: object, context: ScannerContext) -> int:
            del evidence, context
            return 1

    def _check_inference(scanner: _NumericScanner, context: ScannerContext, request: OrganizationAttemptRequest[int], definition: ScannerDefinition) -> None:
        assert_type(scanner.run(context), int)
        assert_type(request.report_request, int | None)
        assert_type(VpcEndpointOpportunityEvidence(records=[1]).records, list[int])

        def factory(scanner_id: str, metadata: ScannerDefinition) -> _NumericScanner:
            del scanner_id, metadata
            return scanner

        dependencies = ScannerRuntimeDependencies(factory, None, None)
        assert_type(dependencies.scanner_factory("synthetic", definition), _NumericScanner)


pytestmark = [pytest.mark.offline, pytest.mark.repository_scan]
ROOT = Path(__file__).resolve().parents[2]


def test_public_interfaces_do_not_hide_implementation_modules() -> None:
    """Only forwarding packages have alternate interfaces; no unknown fallback exists."""
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    standalone = project["project"]["name"] == "unio-collector"
    interface_root = ROOT if standalone else ROOT / "tools/collector_export/typing"
    interfaces = sorted(interface_root.rglob("*.pyi"))
    assert interfaces
    plan = build_collector_package_file_plan(root=ROOT)
    excluded = []
    for interface in interfaces:
        source = interface.relative_to(interface_root).with_suffix(".py").as_posix()
        assert source in plan.source_files
        excluded.append(source)
        for node in ast.parse((ROOT / source).read_bytes()).body:
            assert not isinstance(node, ast.ClassDef)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                assert node.name in {"__getattr__", "__dir__"}
        for node in ast.parse(interface.read_bytes()).body:
            if isinstance(node, ast.Expr):
                assert isinstance(node.value, ast.Constant)
                assert isinstance(node.value.value, str)
                continue
            assert isinstance(node, ast.ImportFrom)
            assert node.module is not None
            assert all(alias.name == alias.asname and alias.name not in {"Any", "__getattr__"} for alias in node.names)
            target = node.module.replace(".", "/")
            assert target + ".py" in plan.source_files or target + "/__init__.py" in plan.source_files
    if standalone:
        configuration = project["tool"]["pyright"]
        assert sorted(configuration["exclude"]) == sorted(excluded)
        assert "unio_collector" in configuration["include"]
        assert not {"ignore", "reportMissingImports", "reportMissingModuleSource"}.intersection(configuration)


def test_typing_contracts_do_not_widen_runtime_discovery() -> None:
    """Additional declarations are explicit; runtime and typing source sets stay distinct."""
    plan = build_collector_package_file_plan(root=ROOT)
    runtime = set(plan.import_closure.source_files)
    contracts = set(plan.manifest.typing_source_files)
    assert runtime.isdisjoint(contracts)
    assert set(plan.source_files) == runtime | contracts
    for name in contracts:
        tree = ast.parse((ROOT / name).read_bytes())
        assert not any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) for node in tree.body)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                assert all(
                    isinstance(item, ast.Expr) and isinstance(item.value, ast.Constant) and (isinstance(item.value.value, str) or item.value.value is Ellipsis)
                    for item in node.body
                )
