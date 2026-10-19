"""Typed regional values inside exact commitment dimension tuple roles."""

from typing import ClassVar

from unio_collector.privacy.commitment.dimension import CommitmentDimensionContract
from unio_collector.privacy.commitment.fields import DIMENSION, FIELDS


class CommitmentLocationDimensionContract(CommitmentDimensionContract):
    """Share declared regional typing across transformation, strict verification and scanning."""

    fields: ClassVar = {**FIELDS, DIMENSION + "[1]": ("string", "region", False)}
