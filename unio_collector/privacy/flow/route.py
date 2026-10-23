"""Route fact fields and exact ordered target/association pair contexts."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from unio_collector.privacy.flow.association import FlowAssociationPairContract
from unio_collector.privacy.flow.base import FlowPrivacyBase
from unio_collector.privacy.flow.target import FlowTargetPairContract
from unio_collector.privacy.flow.topology_fields import ASSOCIATION_PAIRS, ROUTE_FIELDS, TARGET_PAIRS

if TYPE_CHECKING:
    from unio_collector.privacy.closed_schema import ClosedProducerContract


class FlowRouteContract(FlowPrivacyBase):
    """Do not pool route fields with interface facts or lose tuple position meaning."""

    fields: ClassVar = ROUTE_FIELDS

    def for_sequence(self, value: list[Any], path: str) -> ClosedProducerContract | None:
        """Admit the exact two-cell source tuples before selecting position contracts."""
        suffix = path.removeprefix(self.prefix + ".")
        if not self._valid(value, "pair", nullable=False):
            return None
        if suffix in TARGET_PAIRS:
            return FlowTargetPairContract(value[0])
        return FlowAssociationPairContract() if suffix in ASSOCIATION_PAIRS else None
