from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class CloudTrailSecurityTrailRecord:  # noqa: D101
    name: str
    arn: str | None
    home_region: str | None
    region: str
    is_multi_region: bool | None
    is_organization_trail: bool | None
    log_file_validation_enabled: bool | None
    is_logging: bool | None
    management_events_enabled: bool | None
    read_write_type: str | None = None
    s3_bucket_name: str | None = None
    kms_key_id: str | None = None
