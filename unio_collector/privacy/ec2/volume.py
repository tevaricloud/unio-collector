"""Closed actual-producer schema for ec2-unattached-ebs-volumes."""

from __future__ import annotations

from typing import ClassVar

from unio_collector.privacy.ec2.base import COMMON_FIELDS, Ec2PrivacyContract

FIELDS: dict[str, tuple[str, str, bool]] = {
    **COMMON_FIELDS,
    "records[].volume_id": ("string", "resource_id", False),
    "records[].size_gib": ("count", "safe_metadata", False),
    "records[].volume_type": ("volume_type", "safe_metadata", False),
    "records[].state": ("volume_state", "safe_metadata", False),
    "records[].create_time": ("timestamp", "timestamp", True),
    "records[].encrypted": ("boolean", "safe_metadata", True),
}


class EbsVolumePrivacyContract(Ec2PrivacyContract):
    """Bind explicit record fields only to this current and historical scanner identity."""

    scanner_id: ClassVar[str] = "ec2-unattached-ebs-volumes"
    fixture_type: ClassVar[str] = "EbsVolumeFixtureEvidence"
    fields: ClassVar[dict[str, tuple[str, str, bool]]] = FIELDS
