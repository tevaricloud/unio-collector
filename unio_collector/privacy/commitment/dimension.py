"""Separate finite dimension keys from values and unknown provider attribute data."""

from __future__ import annotations

from unio_collector.privacy.commitment.base import CommitmentPrivacyBase
from unio_collector.privacy.commitment.fields import DIMENSION
from unio_collector.privacy.commitment.vocabulary import DIMENSION_KEYS, GROUPINGS, PUBLIC_ROLES


class CommitmentDimensionContract(CommitmentPrivacyBase):
    """Use the actual typed pair discriminator without conflating key and identifier roles."""

    def __init__(self, key: str) -> None:
        """Carry one pair's key in immutable traversal context."""
        self.key = key

    def sequence_item_path(self, path: str, index: int) -> str:
        """Index only the exact declared two-cell dimension container."""
        return f"{path}[{index}]" if path.removeprefix(self.prefix + ".") == DIMENSION else super().sequence_item_path(path, index)

    def is_literal(self, suffix: str, value: object) -> bool:
        """Unknown attribute keys and every customer value remain scanned."""
        if suffix == DIMENSION + "[0]":
            return isinstance(value, str) and value in DIMENSION_KEYS
        if suffix == DIMENSION + "[1]":
            values = GROUPINGS if self.key == "_grouping" else PUBLIC_ROLES.get(self.key.lower(), frozenset())
            return isinstance(value, str) and value in values
        return super().is_literal(suffix, value)
