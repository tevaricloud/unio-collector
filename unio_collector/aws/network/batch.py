"""Inventory and completeness travel together through the shared cache."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.aws.network.coverage import NetworkCollectionCoverage


@dataclass(frozen=True)
class NetworkInventoryBatch:
    """A cached collection with a lossless historical dictionary adapter."""

    account_id: str
    collection_name: str
    items_by_region: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    coverage: tuple[NetworkCollectionCoverage, ...] = ()

    def as_dictionary(self) -> dict[str, list[dict[str, Any]]]:
        """Return the compatibility regional inventory shape."""
        return {region: list(items) for region, items in self.items_by_region.items()}
