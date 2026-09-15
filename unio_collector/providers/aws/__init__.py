from __future__ import annotations  # noqa: D104

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    AWS_PROVIDER: Any
    AwsProviderAdapter: Any
    AwsProviderRuntime: Any
    AwsProviderScannerCatalog: Any

_EXPORTS = {
    "AWS_PROVIDER": ("unio_collector.providers.aws.identity", "AWS_PROVIDER"),
    "AwsProviderAdapter": ("unio_collector.providers.aws.adapter", "AwsProviderAdapter"),
    "AwsProviderRuntime": ("unio_collector.providers.aws.runtime", "AwsProviderRuntime"),
    "AwsProviderScannerCatalog": (
        "unio_collector.providers.aws.scanner_catalog",
        "AwsProviderScannerCatalog",
    ),
}

__all__ = (
    "AWS_PROVIDER",
    "AwsProviderAdapter",
    "AwsProviderRuntime",
    "AwsProviderScannerCatalog",
)


def __getattr__(name: str) -> Any:  # noqa: ANN401
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as exc:
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg) from exc
    module = import_module(module_name)
    return getattr(module, attribute_name)
