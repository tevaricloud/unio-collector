from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class AwsInventoryTagHelper:
    """Convert AWS tag payloads into normalized key/value dictionaries."""

    def tags_to_dict(self, tags: Any) -> dict[str, str]:  # noqa: ANN401, D102
        if not isinstance(tags, list):
            return {}
        return {str(tag.get("Key")): str(tag.get("Value")) for tag in tags if isinstance(tag, dict) and tag.get("Key")}
