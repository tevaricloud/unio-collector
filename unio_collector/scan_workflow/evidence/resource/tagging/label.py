from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class ResourceTaggingEvidenceLabelBuilder:
    """Builds scanner-facing labels for Resource Groups Tagging evidence notes."""

    def build_taggable_resources_label(self) -> str:  # noqa: D102
        return "Resource Groups Tagging API tag discovery"
