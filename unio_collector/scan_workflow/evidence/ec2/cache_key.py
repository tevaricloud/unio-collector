from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class Ec2EvidenceCacheKeyBuilder:
    """Builds stable cache keys for EC2 inventory subsets."""

    account_id: str

    def build_records_key(  # noqa: D102
        self,
        *,
        collection_name: str,
        regions: list[str],
        period_key: str | None = None,
    ) -> tuple[object, ...]:
        return (
            self.account_id,
            collection_name,
            tuple(regions),
            period_key or "",
        )

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

    def build_available_regions_key(self) -> tuple[object, ...]:  # noqa: D102
        return (self.account_id, "ec2")
