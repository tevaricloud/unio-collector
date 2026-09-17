from __future__ import annotations  # noqa: D104

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.scanners.cur_data_export.attribution_scanner import CurDataExportAttributionScanner
    from unio_collector.scanners.cur_data_export.evidence import CurDataExportEvidence
    from unio_collector.scanners.cur_data_export.helpers import collect_cur_data_export_evidence
    from unio_collector.scanners.cur_data_export.packs import (
        CUR_DATA_EXPORT_SCANNER_MODULE_REGISTRATION,
        CUR_DATA_EXPORT_SCANNER_PACKS,
        CUR_DATA_EXPORT_SCANNER_TYPES,
    )
    from unio_collector.scanners.cur_data_export.source import S3ObjectFetcher, build_cur_s3_object_fetcher

_EXPORTS = {
    "CUR_DATA_EXPORT_SCANNER_MODULE_REGISTRATION": ("unio_collector.scanners.cur_data_export.packs", "CUR_DATA_EXPORT_SCANNER_MODULE_REGISTRATION"),
    "CUR_DATA_EXPORT_SCANNER_PACKS": ("unio_collector.scanners.cur_data_export.packs", "CUR_DATA_EXPORT_SCANNER_PACKS"),
    "CUR_DATA_EXPORT_SCANNER_TYPES": ("unio_collector.scanners.cur_data_export.packs", "CUR_DATA_EXPORT_SCANNER_TYPES"),
    "CurDataExportAttributionScanner": ("unio_collector.scanners.cur_data_export.attribution_scanner", "CurDataExportAttributionScanner"),
    "CurDataExportEvidence": ("unio_collector.scanners.cur_data_export.evidence", "CurDataExportEvidence"),
    "S3ObjectFetcher": ("unio_collector.scanners.cur_data_export.source", "S3ObjectFetcher"),
    "build_cur_s3_object_fetcher": ("unio_collector.scanners.cur_data_export.source", "build_cur_s3_object_fetcher"),
    "collect_cur_data_export_evidence": ("unio_collector.scanners.cur_data_export.helpers", "collect_cur_data_export_evidence"),
}

__all__ = [
    "CUR_DATA_EXPORT_SCANNER_MODULE_REGISTRATION",
    "CUR_DATA_EXPORT_SCANNER_PACKS",
    "CUR_DATA_EXPORT_SCANNER_TYPES",
    "CurDataExportAttributionScanner",
    "CurDataExportEvidence",
    "S3ObjectFetcher",
    "build_cur_s3_object_fetcher",
    "collect_cur_data_export_evidence",
]


def __getattr__(name: str) -> Any:  # noqa: ANN401
    """Resolve retained public exports without importing private analysis eagerly."""
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as exc:
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg) from exc
    return getattr(import_module(module_name), attribute_name)
