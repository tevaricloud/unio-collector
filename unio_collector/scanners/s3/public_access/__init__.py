from __future__ import annotations  # noqa: D104

# pyright: reportUnsupportedDunderAll=false
from importlib import import_module
from typing import Any

_EXPORTS = {
    "S3PublicAccessBucketRecord": (
        "unio_collector.scanners.s3.public_access.bucket_record",
        "S3PublicAccessBucketRecord",
    ),
    "S3PublicAccessEvidence": (
        "unio_collector.scanners.s3.public_access.evidence",
        "S3PublicAccessEvidence",
    ),
    "S3PublicAccessSecurityReviewScanner": (
        "unio_collector.scanners.s3.public_access.scanner",
        "S3PublicAccessSecurityReviewScanner",
    ),
}

__all__ = (
    "S3PublicAccessBucketRecord",
    "S3PublicAccessEvidence",
    "S3PublicAccessSecurityReviewScanner",
)


def __getattr__(name: str) -> Any:  # noqa: ANN401
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as exc:
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg) from exc
    module = import_module(module_name)
    return getattr(module, attribute_name)
