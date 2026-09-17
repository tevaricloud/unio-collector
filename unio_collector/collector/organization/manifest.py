from __future__ import annotations

# ruff: noqa: D100,TC001
from typing import Literal

from unio_collector.collector.organization.account import OrganizationEnvelopeAccount
from unio_collector.collector.organization.constants import ORGANIZATION_ENVELOPE_SCHEMA_VERSION
from unio_collector.core.base_model import UnioBaseModel


class OrganizationEnvelopeManifest(UnioBaseModel):
    """Describe an AWS organization envelope and its child bundles."""

    schema_version: str = ORGANIZATION_ENVELOPE_SCHEMA_VERSION
    provider_id: Literal["aws"] = "aws"
    organization_alias: str
    run_id: str
    bundle_purpose: str
    accounts: tuple[OrganizationEnvelopeAccount, ...] = ()

    def validate_account_references(self) -> None:
        """Require unique account identities and canonical successful child paths."""
        seen: set[str] = set()
        for account in self.accounts:
            reference = account.account_reference
            if not reference or reference in {".", ".."} or any(character in reference for character in ("/", "\\", ":", "\x00")):
                message = "Organization envelope account references must be non-empty portable path segments."
                raise ValueError(message)
            if reference in seen:
                message = "Organization envelope contains duplicate account references."
                raise ValueError(message)
            seen.add(reference)
            if account.status in {"completed", "degraded"} and account.bundle_path != f"accounts/{reference}/evidence-bundle.zip":
                message = "Successful organization account has a non-canonical child bundle path."
                raise ValueError(message)
