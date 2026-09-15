from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class EbsSnapshotEncryptionRecord:  # noqa: D101
    snapshot_id: str
    region: str
    encrypted: bool
    kms_key_id: str | None = None
