from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.scanners.security_governance.security_group.ingress_rule import (
        SecurityGroupIngressRule,
    )


@dataclass(frozen=True)
class SecurityGroupExposureEvidence:  # noqa: D101
    public_ingress_rules: tuple[SecurityGroupIngressRule, ...] = ()
    regions: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    collection_evidence_version: int = 0
