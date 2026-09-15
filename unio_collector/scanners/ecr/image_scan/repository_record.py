from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class EcrRepositoryScanRecord:  # noqa: D101
    repository_name: str
    repository_arn: str | None
    region: str
    scan_on_push: bool | None
    image_tag_mutability: str | None = None
    encryption_type: str | None = None
    kms_key: str | None = None
