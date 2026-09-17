from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class S3PublicAccessBucketRecord:  # noqa: D101
    bucket_name: str
    public_access_block: dict[str, bool] | None = None
    policy_is_public: bool | None = None
    acl_is_public: bool | None = None
