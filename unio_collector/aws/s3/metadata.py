from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class S3BucketMetadataResult:  # noqa: D101
    bucket_name: str
    metadata_type: str
    payload: dict[str, Any] = field(default_factory=dict)
    tags: dict[str, str] = field(default_factory=dict)
    collected: bool = True
    limitation: str | None = None
