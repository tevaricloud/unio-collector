from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class ConfigComplianceRuleRecord:  # noqa: D101
    region: str
    rule_name: str
    compliance_type: str
    annotation: str | None = None
