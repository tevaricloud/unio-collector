from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class NetworkEvidenceLabelBuilder:
    """Builds scanner-facing labels for network evidence notes."""

    def build_nat_gateway_records_label(self) -> str:  # noqa: D102
        return "NAT Gateway inventory"

    def build_available_regions_label(self) -> str:  # noqa: D102
        return "EC2 available region discovery"
