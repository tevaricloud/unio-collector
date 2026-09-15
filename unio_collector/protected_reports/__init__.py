from __future__ import annotations  # noqa: D104

from importlib import import_module
from typing import TYPE_CHECKING, Any

from unio_collector.protected_reports.restoration import (
    ProtectedReportRestoreOptions,
    ProtectedReportRestorer,
    ProtectedReportRestoreResult,
)
from unio_collector.protected_reports.validation import ProtectedReportPackageValidator
from unio_collector.protected_reports.verifier import ProtectedReportPackageVerifier

if TYPE_CHECKING:
    from unio_collector.protected_reports.package import ProtectedReportPackageBuilder
    from unio_collector.protected_reports.signing import ProtectedReportPackageSigner
    from unio_collector.protected_reports.writer import ProtectedReportPackageWriter

__all__ = [
    "ProtectedReportPackageBuilder",
    "ProtectedReportPackageSigner",
    "ProtectedReportPackageValidator",
    "ProtectedReportPackageVerifier",
    "ProtectedReportPackageWriter",
    "ProtectedReportRestoreOptions",
    "ProtectedReportRestoreResult",
    "ProtectedReportRestorer",
]


_EXPORTS: dict[str, tuple[str, str]] = {
    "ProtectedReportPackageBuilder": ("unio_collector.protected_reports.package", "ProtectedReportPackageBuilder"),
    "ProtectedReportPackageSigner": ("unio_collector.protected_reports.signing", "ProtectedReportPackageSigner"),
    "ProtectedReportPackageWriter": ("unio_collector.protected_reports.writer", "ProtectedReportPackageWriter"),
}


def __getattr__(name: str) -> Any:  # noqa: ANN401
    """Resolve a historical application export from its canonical module."""
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as exc:
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg) from exc
    return getattr(import_module(module_name), attribute_name)
