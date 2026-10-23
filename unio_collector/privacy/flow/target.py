"""Actual route target field names versus resource identity values."""

from typing import ClassVar

from unio_collector.privacy.flow.pair import FlowPairContract
from unio_collector.privacy.flow.topology_fields import ROUTE_FIELDS


class FlowTargetPairContract(FlowPairContract):
    """Bind generated local gateway syntax to its actual target discriminator."""

    fields: ClassVar = {path: spec for path, spec in ROUTE_FIELDS.items() if ".targets[]" in path}

    def __init__(self, target: str) -> None:
        """Carry one pair's field kind without pooling unrelated route values."""
        self.target = target

    def is_literal(self, suffix: str, value: object) -> bool:
        """Only GatewayId's exact generated local marker may preserve its value."""
        return super().is_literal(suffix, value) or (suffix in self.fields and suffix.endswith("[1]") and self.target == "GatewayId" and value == "local")
