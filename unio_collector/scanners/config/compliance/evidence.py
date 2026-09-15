from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.scanners.config.compliance.rule_record import (
        ConfigComplianceRuleRecord,
    )


@dataclass(frozen=True)
class ConfigComplianceEvidence:  # noqa: D101
    records: tuple[ConfigComplianceRuleRecord, ...] = ()
    conformance_pack_records: tuple[dict[str, Any], ...] = ()
    regions: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
