from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class NetworkEvidenceCacheKeyBuilder:
    """Builds stable cache keys for network inventory evidence."""

    account_id: str

    def build_items_by_region_key(  # noqa: D102
        self,
        *,
        collection_name: str,
        regions: list[str],
    ) -> tuple[object, ...]:
        return (
            self.account_id,
            collection_name,
            tuple(regions),
        )

    def build_nat_gateway_records_key(  # noqa: D102
        self,
        *,
        regions: list[str],
    ) -> tuple[object, ...]:
        return (
            self.account_id,
            "nat_gateways",
            tuple(regions),
        )

    def build_available_regions_key(self) -> tuple[object, ...]:  # noqa: D102
        return (self.account_id, "ec2")
