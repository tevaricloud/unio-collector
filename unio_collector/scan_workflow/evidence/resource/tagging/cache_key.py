from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class ResourceTaggingEvidenceCacheKeyBuilder:
    """Builds stable cache keys for Resource Groups Tagging API evidence."""

    account_id: str

    def build_taggable_resources_key(  # noqa: D102
        self,
        *,
        regions: list[str],
        resource_type_filters: tuple[str, ...],
    ) -> tuple[object, ...]:
        return (
            self.account_id,
            tuple(sorted(regions)),
            resource_type_filters,
        )
