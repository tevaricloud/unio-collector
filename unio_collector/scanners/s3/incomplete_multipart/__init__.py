from __future__ import annotations  # noqa: D104

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.scanners.s3.incomplete_multipart.evidence import S3MultipartEvidence
    from unio_collector.scanners.s3.incomplete_multipart.scanner import S3IncompleteMultipartReviewScanner

_EXPORTS = {
    "S3IncompleteMultipartReviewScanner": ("unio_collector.scanners.s3.incomplete_multipart.scanner", "S3IncompleteMultipartReviewScanner"),
    "S3MultipartEvidence": ("unio_collector.scanners.s3.incomplete_multipart.evidence", "S3MultipartEvidence"),
}

__all__ = ["S3IncompleteMultipartReviewScanner", "S3MultipartEvidence"]


def __getattr__(name: str) -> Any:  # noqa: ANN401
    """Resolve retained public exports without importing private analysis eagerly."""
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as exc:
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg) from exc
    return getattr(import_module(module_name), attribute_name)
