"""Closed actual-producer schema for provisioned-iops-review."""

from __future__ import annotations

from typing import ClassVar

from unio_collector.privacy.ec2.base import COMMON_FIELDS, Ec2PrivacyContract

FIELDS: dict[str, tuple[str, str, bool]] = {
    **COMMON_FIELDS,
    "records[].volume_id": ("string", "resource_id", False),
    "records[].volume_type": ("volume_type", "safe_metadata", False),
    "records[].size_gib": ("count", "safe_metadata", False),
    "records[].provisioned_iops": ("count", "safe_metadata", True),
    "records[].state": ("volume_state", "safe_metadata", False),
}


class ProvisionedIopsPrivacyContract(Ec2PrivacyContract):
    """Bind explicit record fields only to this current and historical scanner identity."""

    scanner_id: ClassVar[str] = "provisioned-iops-review"
    fixture_type: ClassVar[str] = "ProvisionedIopsFixtureEvidence"
    fields: ClassVar[dict[str, tuple[str, str, bool]]] = FIELDS
