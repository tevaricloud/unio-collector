from __future__ import annotations  # noqa: D100

from dataclasses import dataclass

from unio_collector.scan_workflow.cache_labels import (
    format_ec2_inventory_collection_label,
)


@dataclass(frozen=True)
class Ec2EvidenceLabelBuilder:
    """Builds scanner-facing labels for EC2 evidence notes."""

    def build_records_label(self, *, collection_name: str) -> str:  # noqa: D102
        return f"EC2 inventory subset: {format_ec2_inventory_collection_label(collection_name)}"

    def build_available_regions_label(self) -> str:  # noqa: D102
        return "EC2 available region discovery"
