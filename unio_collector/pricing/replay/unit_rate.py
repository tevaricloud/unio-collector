"""Typed serialized pricing unit-rate identity."""

from __future__ import annotations

from decimal import Decimal  # noqa: TC003
from typing import Literal

from unio_collector.core.base_model import UnioBaseModel


class PricingUnitRateRecord(UnioBaseModel):
    """Lossless serialized identity for one pricing unit rate."""

    rate_type: Literal[
        "ebs_volume_gb_month",
        "ebs_snapshot_gb_month",
        "cloudwatch_logs_storage_gb_month",
        "public_ipv4_hour",
    ]
    region: str
    resource_variant: str | None = None
    amount: Decimal
    currency: str
    unit: str
    source: str
