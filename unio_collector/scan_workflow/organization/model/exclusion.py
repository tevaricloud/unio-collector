from __future__ import annotations  # noqa: D100

# ruff: noqa: TC001
from unio_collector.core.base_model import UnioBaseModel
from unio_collector.scan_workflow.organization.model.account import AwsAccountState


class ExcludedAccount(UnioBaseModel):
    """Record why one discovered account was not selected."""

    account_reference: str
    state: AwsAccountState
    exclusion_code: str
    explanation: str
