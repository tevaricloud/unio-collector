"""Closed actual-producer schema for ec2-stopped-instances-with-storage."""

from __future__ import annotations

from typing import ClassVar

from unio_collector.privacy.ec2.base import COMMON_FIELDS, Ec2PrivacyContract

FIELDS: dict[str, tuple[str, str, bool]] = {
    **COMMON_FIELDS,
    "records[].instance_id": ("string", "resource_id", False),
    "records[].instance_type": ("instance_type", "safe_metadata", False),
    "records[].launch_time": ("timestamp", "timestamp", True),
    "records[].attached_volume_ids": ("array", "resource_id", False),
    "records[].attached_volume_ids[]": ("string", "resource_id", False),
}


class StoppedInstancePrivacyContract(Ec2PrivacyContract):
    """Bind explicit record fields only to this current and historical scanner identity."""

    scanner_id: ClassVar[str] = "ec2-stopped-instances-with-storage"
    fixture_type: ClassVar[str] = "StoppedInstanceFixtureEvidence"
    fields: ClassVar[dict[str, tuple[str, str, bool]]] = FIELDS
