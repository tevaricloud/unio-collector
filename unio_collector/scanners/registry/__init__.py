from __future__ import annotations  # noqa: D104

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.scanners.registry.boundary_summary import build_scanner_analysis_boundary_summary
    from unio_collector.scanners.registry.catalog import get_scanner, list_scanners, validate_scanner_ids
    from unio_collector.scanners.registry.definitions import SCANNERS
    from unio_collector.scanners.registry.explanation_lookup import build_scanner_explanations, get_no_finding_scanner_summary, get_scanner_explanation
    from unio_collector.scanners.registry.explanations import NO_FINDING_SCANNER_SUMMARIES, SCANNER_EXPLANATIONS, NoFindingScannerSummary
    from unio_collector.scanners.scanner.definition import ScannerDefinition
    from unio_collector.scanners.scanner.pack import ScannerPack
    from unio_collector.scanners.scanner.types import Maturity, RequiredPermissionLevel, ScannerExecutionPhase, ScannerRiskLevel
    from unio_collector.scanners.scanner.version import SCANNER_REGISTRY_VERSION

_EXPORTS = {
    "NO_FINDING_SCANNER_SUMMARIES": ("unio_collector.scanners.registry.explanations", "NO_FINDING_SCANNER_SUMMARIES"),
    "SCANNERS": ("unio_collector.scanners.registry.definitions", "SCANNERS"),
    "SCANNER_EXPLANATIONS": ("unio_collector.scanners.registry.explanations", "SCANNER_EXPLANATIONS"),
    "SCANNER_REGISTRY_VERSION": ("unio_collector.scanners.scanner.version", "SCANNER_REGISTRY_VERSION"),
    "Maturity": ("unio_collector.scanners.scanner.types", "Maturity"),
    "NoFindingScannerSummary": ("unio_collector.scanners.registry.explanations", "NoFindingScannerSummary"),
    "RequiredPermissionLevel": ("unio_collector.scanners.scanner.types", "RequiredPermissionLevel"),
    "ScannerDefinition": ("unio_collector.scanners.scanner.definition", "ScannerDefinition"),
    "ScannerExecutionPhase": ("unio_collector.scanners.scanner.types", "ScannerExecutionPhase"),
    "ScannerPack": ("unio_collector.scanners.scanner.pack", "ScannerPack"),
    "ScannerRiskLevel": ("unio_collector.scanners.scanner.types", "ScannerRiskLevel"),
    "build_scanner_analysis_boundary_summary": ("unio_collector.scanners.registry.boundary_summary", "build_scanner_analysis_boundary_summary"),
    "build_scanner_explanations": ("unio_collector.scanners.registry.explanation_lookup", "build_scanner_explanations"),
    "get_no_finding_scanner_summary": ("unio_collector.scanners.registry.explanation_lookup", "get_no_finding_scanner_summary"),
    "get_scanner": ("unio_collector.scanners.registry.catalog", "get_scanner"),
    "get_scanner_explanation": ("unio_collector.scanners.registry.explanation_lookup", "get_scanner_explanation"),
    "list_scanners": ("unio_collector.scanners.registry.catalog", "list_scanners"),
    "validate_scanner_ids": ("unio_collector.scanners.registry.catalog", "validate_scanner_ids"),
}

__all__ = [
    "NO_FINDING_SCANNER_SUMMARIES",
    "SCANNERS",
    "SCANNER_EXPLANATIONS",
    "SCANNER_REGISTRY_VERSION",
    "Maturity",
    "NoFindingScannerSummary",
    "RequiredPermissionLevel",
    "ScannerDefinition",
    "ScannerExecutionPhase",
    "ScannerPack",
    "ScannerRiskLevel",
    "build_scanner_analysis_boundary_summary",
    "build_scanner_explanations",
    "get_no_finding_scanner_summary",
    "get_scanner",
    "get_scanner_explanation",
    "list_scanners",
    "validate_scanner_ids",
]


def __getattr__(name: str) -> Any:  # noqa: ANN401
    """Retain public registry exports; internal callers use their canonical owners."""
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as exc:
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg) from exc
    return getattr(import_module(module_name), attribute_name)
