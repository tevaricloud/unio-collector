from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class AwsClientCacheKey:  # noqa: D101
    service_name: str
    region_name: str
    runtime_signature: tuple[object, ...]
