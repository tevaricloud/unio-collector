from __future__ import annotations  # noqa: D100

from typing import Literal

from unio_collector.core.base_model import UnioBaseModel


class OrganizationCallerAuthority(UnioBaseModel):
    """Keep declared and observed organization authority separate."""

    declared_context: Literal["management", "delegated_administrator", "operator"]
    observed_authority: Literal[
        "aws_confirmed_management", "aws_confirmed_service_delegated_administrator", "operator_with_observed_organizations_read_access", "unconfirmed"
    ]
    evidence_status: Literal["confirmed", "observed_access", "unconfirmed"]
    delegated_service_principals: tuple[str, ...] = ()
    evidence_apis: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
