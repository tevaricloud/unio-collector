from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class S3BucketEncryptionRecord:  # noqa: D101
    bucket_name: str
    encryption_configured: bool | None
    encryption_rules: tuple[str, ...] = ()
