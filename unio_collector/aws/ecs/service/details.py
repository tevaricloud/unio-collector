from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class EcsServiceDetailCollection:  # noqa: D101
    cluster_arn: str
    services: list[dict[str, Any]] = field(default_factory=list)
    permission_errors: list[str] = field(default_factory=list)
