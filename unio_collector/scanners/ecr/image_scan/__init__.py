from __future__ import annotations  # noqa: D104

# pyright: reportUnsupportedDunderAll=false
from importlib import import_module
from typing import Any

_EXPORTS = {
    "EcrImageScanPostureEvidence": (
        "unio_collector.scanners.ecr.image_scan.evidence",
        "EcrImageScanPostureEvidence",
    ),
    "EcrRegistryScanRecord": (
        "unio_collector.scanners.ecr.image_scan.registry_record",
        "EcrRegistryScanRecord",
    ),
    "EcrRepositoryScanRecord": (
        "unio_collector.scanners.ecr.image_scan.repository_record",
        "EcrRepositoryScanRecord",
    ),
    "EcrImageScanPostureReviewScanner": (
        "unio_collector.scanners.ecr.image_scan.scanner",
        "EcrImageScanPostureReviewScanner",
    ),
}

__all__ = (
    "EcrImageScanPostureEvidence",
    "EcrImageScanPostureReviewScanner",
    "EcrRegistryScanRecord",
    "EcrRepositoryScanRecord",
)


def __getattr__(name: str) -> Any:  # noqa: ANN401
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as exc:
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg) from exc
    module = import_module(module_name)
    return getattr(module, attribute_name)
