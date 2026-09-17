from __future__ import annotations  # noqa: D104

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.scanners.s3.versioning_replication.scanner import S3VersioningAndReplicationReviewScanner

_EXPORTS = {"S3VersioningAndReplicationReviewScanner": ("unio_collector.scanners.s3.versioning_replication.scanner", "S3VersioningAndReplicationReviewScanner")}

__all__ = ["S3VersioningAndReplicationReviewScanner"]


def __getattr__(name: str) -> Any:  # noqa: ANN401
    """Resolve retained public exports without importing private analysis eagerly."""
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as exc:
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg) from exc
    return getattr(import_module(module_name), attribute_name)
