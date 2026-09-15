from __future__ import annotations  # noqa: D104

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.scanners.ec2.elastic_ip.unassociated import UnassociatedElasticIpScanner

_EXPORTS = {"UnassociatedElasticIpScanner": ("unio_collector.scanners.ec2.elastic_ip.unassociated", "UnassociatedElasticIpScanner")}

__all__ = ["UnassociatedElasticIpScanner"]


def __getattr__(name: str) -> Any:  # noqa: ANN401
    """Resolve retained public exports without importing private analysis eagerly."""
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as exc:
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg) from exc
    return getattr(import_module(module_name), attribute_name)
