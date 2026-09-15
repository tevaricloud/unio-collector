from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class AlbOriginSecurityGroupRuleRecord:
    """Security-group ingress evidence relevant to a matched ALB."""

    group_id: str
    region: str
    protocol: str
    from_port: int | None
    to_port: int | None
    cidr: str
    public: bool
    source_type: str = "cidr"
    source_value: str = ""
    source_description: str = ""
    source_control: str = ""
    evidence_ref: str = ""
    source_control_verification: str = "legacy_unverified"
