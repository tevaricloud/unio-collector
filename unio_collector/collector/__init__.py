"""Collector package wayfinding.

owns: versioned evidence-bundle schema, manifest, checksums, reader/writer/validator, minimisation metadata, and package planning.
must not import: analyzer, report, redaction, framework report writer, consultancy report, or LLM modules.
protects: collector-only artifact boundaries, POSIX bundle paths, and read-only evidence export.
start here: docs/collector-workflow.md, docs/evidence-bundles.md, bundle/, and package/.
focused tests: collector/bundle tests and tests/architecture/test_import_report_collector_boundaries.py.
"""

from __future__ import annotations

# pyright: reportUnsupportedDunderAll=false
from importlib import import_module
from typing import Any

_EXPORTS = {
    "CollectorPackageFilePlan": (
        "unio_collector.collector.package.file.plan",
        "CollectorPackageFilePlan",
    ),
    "CollectorPackageFilePlanBuilder": (
        "unio_collector.collector.package.file.builder",
        "CollectorPackageFilePlanBuilder",
    ),
    "CollectorPackageManifest": (
        "unio_collector.collector.package.manifest",
        "CollectorPackageManifest",
    ),
    "EvidenceBundleReader": (
        "unio_collector.collector.bundle.reader",
        "EvidenceBundleReader",
    ),
    "EvidenceBundleValidator": (
        "unio_collector.collector.bundle.validator",
        "EvidenceBundleValidator",
    ),
    "EvidenceBundleWriter": (
        "unio_collector.collector.bundle.writer",
        "EvidenceBundleWriter",
    ),
    "build_collector_package_file_plan": (
        "unio_collector.collector.package.manifest",
        "build_collector_package_file_plan",
    ),
    "build_collector_package_manifest": (
        "unio_collector.collector.package.manifest",
        "build_collector_package_manifest",
    ),
}

__all__ = tuple(_EXPORTS)


def __getattr__(name: str) -> Any:  # noqa: ANN401
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as exc:
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg) from exc
    module = import_module(module_name)
    return getattr(module, attribute_name)
