"""AWS scan public exports.

The scan entrypoint is loaded lazily so scan result/state DTOs can be imported
without initializing the full scanner runner graph.
"""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

__all__ = [
    "AwsScanBuilder",
    "AwsScanResult",
    "AwsScanState",
    "ScannerRunner",
    "build_report_bundle_from_aws",
]

if TYPE_CHECKING:
    from unio_collector.scan_workflow.aws.scan.entrypoint import (
        AwsScanBuilder,
        ScannerRunner,
        build_report_bundle_from_aws,
    )
    from unio_collector.scan_workflow.aws.scan.result import AwsScanResult
    from unio_collector.scan_workflow.aws.scan.state import AwsScanState


def __getattr__(name: str) -> Any:  # noqa: ANN401
    if name in {"AwsScanResult", "AwsScanState"}:
        module_name = "result" if name == "AwsScanResult" else "state"
        module = __import__(
            f"unio_collector.scan_workflow.aws.scan.{module_name}",
            fromlist=[name],
        )
        return getattr(module, name)
    if name in {"AwsScanBuilder", "ScannerRunner", "build_report_bundle_from_aws"}:
        entrypoint = import_module("unio_collector.scan_workflow.aws.scan.entrypoint")
        return getattr(entrypoint, name)
    msg = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(msg)
