from __future__ import annotations  # noqa: D104

# pyright: reportUnsupportedDunderAll=false
from importlib import import_module
from typing import Any

_EXPORTS = {
    "BaseUnioScanner": (
        "unio_collector.scanners.base.cloud_cost_scanner",
        "BaseUnioScanner",
    ),
    "BaseS3BucketCostScanner": (
        "unio_collector.scanners.base.s3_bucket_scanner",
        "BaseS3BucketCostScanner",
    ),
    "UnioScanner": (
        "unio_collector.scanners.cloud_cost_scanner",
        "UnioScanner",
    ),
    "ScannerCloudWatchGateway": (
        "unio_collector.scanners.scanner.gateway.cloudwatch",
        "ScannerCloudWatchGateway",
    ),
    "ScannerContext": (
        "unio_collector.scanners.scanner.context",
        "ScannerContext",
    ),
    "ScannerCostGateway": (
        "unio_collector.scanners.scanner.gateway.cost",
        "ScannerCostGateway",
    ),
    "ScannerDataGateway": (
        "unio_collector.scanners.scanner.gateway.data",
        "ScannerDataGateway",
    ),
    "ScannerEc2Gateway": (
        "unio_collector.scanners.scanner.gateway.ec2",
        "ScannerEc2Gateway",
    ),
    "ScannerFindingGateway": (
        "unio_collector.scanners.scanner.gateway.finding",
        "ScannerFindingGateway",
    ),
    "ScannerImplementation": (
        "unio_collector.scanners.scanner.implementation",
        "ScannerImplementation",
    ),
    "ScannerLambdaGateway": (
        "unio_collector.scanners.scanner.gateway.lambda_",
        "ScannerLambdaGateway",
    ),
    "ScannerNetworkGateway": (
        "unio_collector.scanners.scanner.gateway.network",
        "ScannerNetworkGateway",
    ),
    "ScannerOptionsGateway": (
        "unio_collector.scanners.scanner.gateway.options",
        "ScannerOptionsGateway",
    ),
    "ScannerRunResult": (
        "unio_collector.scanners.scanner.run_result",
        "ScannerRunResult",
    ),
    "ScannerRuntimeProtocol": (
        "unio_collector.scanners.scanner.runtime_protocol",
        "ScannerRuntimeProtocol",
    ),
    "ScannerS3Gateway": (
        "unio_collector.scanners.scanner.gateway.s3",
        "ScannerS3Gateway",
    ),
    "ScannerSecurityGateway": (
        "unio_collector.scanners.scanner.gateway.security",
        "ScannerSecurityGateway",
    ),
    "ScannerTaggingGateway": (
        "unio_collector.scanners.scanner.gateway.tagging",
        "ScannerTaggingGateway",
    ),
    "ScannerWarningGateway": (
        "unio_collector.scanners.scanner.gateway.warning",
        "ScannerWarningGateway",
    ),
}

__all__ = (
    "BaseS3BucketCostScanner",
    "BaseUnioScanner",
    "ScannerCloudWatchGateway",
    "ScannerContext",
    "ScannerCostGateway",
    "ScannerDataGateway",
    "ScannerEc2Gateway",
    "ScannerFindingGateway",
    "ScannerImplementation",
    "ScannerLambdaGateway",
    "ScannerNetworkGateway",
    "ScannerOptionsGateway",
    "ScannerRunResult",
    "ScannerRuntimeProtocol",
    "ScannerS3Gateway",
    "ScannerSecurityGateway",
    "ScannerTaggingGateway",
    "ScannerWarningGateway",
    "UnioScanner",
)


def __getattr__(name: str) -> Any:  # noqa: ANN401
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as exc:
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg) from exc
    module = import_module(module_name)
    return getattr(module, attribute_name)
