from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class KmsKeyPostureRecord:  # noqa: D101
    key_id: str
    arn: str | None
    region: str
    key_manager: str | None
    key_state: str | None
    key_usage: str | None
    key_spec: str | None
    rotation_enabled: bool | None = None
    origin: str | None = None
    multi_region: bool | None = None
