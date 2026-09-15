from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field


@dataclass(frozen=True)
class EcsServiceArnCollection:  # noqa: D101
    cluster_arn: str
    service_arns: list[str] = field(default_factory=list)
    permission_errors: list[str] = field(default_factory=list)
