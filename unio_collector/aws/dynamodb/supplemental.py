from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class DynamoDbRegionSupplementalContext:  # noqa: D101
    tags_by_table: dict[str, dict[str, str]] = field(default_factory=dict)
    scalable_targets: list[dict[str, Any]] = field(default_factory=list)
    scaling_policies: list[dict[str, Any]] = field(default_factory=list)
    metric_rollup: dict[str, Any] = field(default_factory=dict)
    permission_errors: list[str] = field(default_factory=list)
