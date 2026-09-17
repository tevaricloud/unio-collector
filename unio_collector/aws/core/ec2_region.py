from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.aws.audit import AwsAuditContext


@dataclass(frozen=True)
class AwsEc2RegionDiscoveryHelper:
    """Resolve EC2-region scoped collectors with the EC2 DescribeRegions API."""

    session: Any
    audit_context: AwsAuditContext
    fallback_region: str = "us-east-1"

    def get_available_regions(self, selected_regions: list[str] | None) -> list[str]:  # noqa: D102
        if selected_regions:
            return sorted(selected_regions)
        client = self.session.create_client(
            "ec2",
            region_name=self._get_home_region(),
            audit_context=self.audit_context,
        )
        response = client.describe_regions(AllRegions=False)
        return sorted(region["RegionName"] for region in response.get("Regions", []))

    def _get_home_region(self) -> str:
        get_region_name = getattr(self.session, "get_region_name", None)
        if callable(get_region_name):
            region = get_region_name()
            if isinstance(region, str) and region:
                return region
        return self.fallback_region
