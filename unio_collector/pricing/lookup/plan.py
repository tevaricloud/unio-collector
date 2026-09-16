from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class PricingLookupPlan:  # noqa: D101
    ebs_volume_types_by_region: dict[str, tuple[str, ...]] = field(
        default_factory=dict,
    )
    snapshot_regions: tuple[str, ...] = ()
    logs_storage_regions: tuple[str, ...] = ()
    public_ipv4_regions: tuple[str, ...] = ()

    @classmethod
    def build_from_legacy_inputs(  # noqa: D102
        cls,
        *,
        regions: set[str],
        ebs_volume_types: set[str],
        include_snapshots: bool,
        include_logs_storage: bool,
        include_public_ipv4: bool,
    ) -> PricingLookupPlan:
        ordered_regions = tuple(sorted(regions))
        ordered_volume_types = tuple(sorted(ebs_volume_types))
        return cls(
            ebs_volume_types_by_region={region: ordered_volume_types for region in ordered_regions if ordered_volume_types},
            snapshot_regions=ordered_regions if include_snapshots else (),
            logs_storage_regions=ordered_regions if include_logs_storage else (),
            public_ipv4_regions=ordered_regions if include_public_ipv4 else (),
        )

    def get_regions(self) -> set[str]:  # noqa: D102
        regions = set(self.ebs_volume_types_by_region)
        regions.update(self.snapshot_regions)
        regions.update(self.logs_storage_regions)
        regions.update(self.public_ipv4_regions)
        return regions

    def get_ebs_volume_types(self, region: str) -> tuple[str, ...]:  # noqa: D102
        return self.ebs_volume_types_by_region.get(region, ())

    def count_lookup_requests(self) -> int:  # noqa: D102
        return (
            sum(len(types) for types in self.ebs_volume_types_by_region.values())
            + len(self.snapshot_regions)
            + len(self.logs_storage_regions)
            + len(self.public_ipv4_regions)
        )

    def count_legacy_cross_product_requests(self) -> int:  # noqa: D102
        regions = self.get_regions()
        ebs_volume_types = {volume_type for volume_types in self.ebs_volume_types_by_region.values() for volume_type in volume_types}
        request_types_per_region = len(ebs_volume_types)
        if self.snapshot_regions:
            request_types_per_region += 1
        if self.logs_storage_regions:
            request_types_per_region += 1
        if self.public_ipv4_regions:
            request_types_per_region += 1
        return len(regions) * request_types_per_region

    def convert_to_summary(self) -> dict[str, Any]:  # noqa: D102
        actual_request_count = self.count_lookup_requests()
        legacy_request_count = self.count_legacy_cross_product_requests()
        return {
            "mode": "evidence_targeted",
            "targeted_lookup_request_count": actual_request_count,
            "legacy_cross_product_lookup_request_count": legacy_request_count,
            "legacy_cross_product_lookup_avoided_count": max(
                0,
                legacy_request_count - actual_request_count,
            ),
            "regions_with_pricing_lookups": sorted(self.get_regions()),
            "ebs_volume_rate_lookup_count": sum(len(types) for types in self.ebs_volume_types_by_region.values()),
            "snapshot_rate_lookup_count": len(self.snapshot_regions),
            "logs_storage_rate_lookup_count": len(self.logs_storage_regions),
            "public_ipv4_rate_lookup_count": len(self.public_ipv4_regions),
            "ebs_volume_types_by_region": {
                region: list(volume_types)
                for region, volume_types in sorted(
                    self.ebs_volume_types_by_region.items(),
                )
            },
        }
