from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.aws.taggable_resource_record import TaggableResourceRecord


@dataclass(frozen=True)
class ResourceGroupsTaggingCollectionResult:  # noqa: D101
    records: list[TaggableResourceRecord] = field(default_factory=list)
    regions_scanned: list[str] = field(default_factory=list)
    status: str = "completed"
    source: str = "resource_groups_tagging_api"
    errors: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def convert_to_summary(self) -> dict[str, Any]:  # noqa: D102
        return {
            "source": self.source,
            "status": self.status,
            "records_returned": len(self.records),
            "regions_scanned": list(self.regions_scanned),
            "errors": list(self.errors),
            "limitations": list(self.limitations),
        }
