"""Closed tuple positions shared by the two actual flow route pair contracts."""

from unio_collector.privacy.flow.base import FlowPrivacyBase
from unio_collector.privacy.flow.topology_fields import ASSOCIATION_PAIRS, TARGET_PAIRS


class FlowPairContract(FlowPrivacyBase):
    """Index only exact declared two-cell tuple roles, never arbitrary nested arrays."""

    def sequence_item_path(self, path: str, index: int) -> str:
        """Keep the same indexed role in transformation, preflight, scanning and strict checks."""
        suffix = path.removeprefix(self.prefix + ".")
        return f"{path}[{index}]" if suffix in TARGET_PAIRS | ASSOCIATION_PAIRS else super().sequence_item_path(path, index)
