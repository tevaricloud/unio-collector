from __future__ import annotations  # noqa: D104

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.scanners.rds.packs import RDS_SCANNER_MODULE_REGISTRATION, RDS_SCANNER_PACKS, RDS_SCANNER_TYPES
    from unio_collector.scanners.rds.snapshot_retention_scanner import RdsSnapshotRetentionReviewScanner
    from unio_collector.scanners.rds.utilization_scanner import RdsUtilizationReviewScanner

_EXPORTS = {
    "RDS_SCANNER_MODULE_REGISTRATION": ("unio_collector.scanners.rds.packs", "RDS_SCANNER_MODULE_REGISTRATION"),
    "RDS_SCANNER_PACKS": ("unio_collector.scanners.rds.packs", "RDS_SCANNER_PACKS"),
    "RDS_SCANNER_TYPES": ("unio_collector.scanners.rds.packs", "RDS_SCANNER_TYPES"),
    "RdsSnapshotRetentionReviewScanner": ("unio_collector.scanners.rds.snapshot_retention_scanner", "RdsSnapshotRetentionReviewScanner"),
    "RdsUtilizationReviewScanner": ("unio_collector.scanners.rds.utilization_scanner", "RdsUtilizationReviewScanner"),
}

__all__ = ["RDS_SCANNER_MODULE_REGISTRATION", "RDS_SCANNER_PACKS", "RDS_SCANNER_TYPES", "RdsSnapshotRetentionReviewScanner", "RdsUtilizationReviewScanner"]


def __getattr__(name: str) -> Any:  # noqa: ANN401
    """Resolve retained public exports without importing private analysis eagerly."""
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as exc:
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg) from exc
    return getattr(import_module(module_name), attribute_name)
