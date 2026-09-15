from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class EbsEncryptionRegionRecord:  # noqa: D101
    region: str
    enabled_by_default: bool | None
    default_kms_key_id: str | None = None
