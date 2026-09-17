from __future__ import annotations  # noqa: D100

# ruff: noqa: TC001
from unio_collector.core.base_model import UnioBaseModel
from unio_collector.scan_workflow.organization.model.authority import OrganizationCallerAuthority


class OrganizationIdentity(UnioBaseModel):
    """Persist safe AWS Organization identity and authority evidence."""

    organization_id: str
    organization_arn: str
    feature_set: str
    management_account_id: str
    caller_account_id: str
    authority: OrganizationCallerAuthority
    alias: str
