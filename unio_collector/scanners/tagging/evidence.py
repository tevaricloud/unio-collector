from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.taggable_resource_record import TaggableResourceRecord


@dataclass(frozen=True)
class TaggingEvidence:  # noqa: D101
    regions: list[str] = field(default_factory=list)
    records: list[TaggableResourceRecord] = field(default_factory=list)
    required_tags: list[str] = field(default_factory=list)
    analysis_inputs_version: int = 0
    required_tags_supplied: bool = True
