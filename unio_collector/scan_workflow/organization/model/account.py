from __future__ import annotations  # noqa: D100

from typing import Literal

from pydantic import Field

from unio_collector.core.base_model import UnioBaseModel

AwsAccountState = Literal["PENDING_ACTIVATION", "ACTIVE", "SUSPENDED", "PENDING_CLOSURE", "CLOSED", "UNKNOWN"]


class AccountIdentity(UnioBaseModel):
    """Persist normalized account identity without Organizations email."""

    account_id: str
    arn: str
    name: str | None = None
    alias: str
    state: AwsAccountState
    parent_id: str
    organizational_unit_path: tuple[str, ...]
    joined_method: str | None = None
    joined_timestamp: str | None = None
    tags: dict[str, str] = Field(default_factory=dict)
    tag_evidence_status: Literal["not_requested", "available", "unavailable"] = "not_requested"
    metadata: dict[str, tuple[str, ...]] = Field(default_factory=dict)
    metadata_provenance: Literal["operator", "none"] = "none"
    is_management_account: bool = False
    limitations: tuple[str, ...] = ()
