from __future__ import annotations  # noqa: D100

from typing import Any


def kms_rotation_status_is_applicable(metadata: dict[str, Any]) -> bool:  # noqa: D103
    return (
        metadata.get("KeyManager") == "CUSTOMER"
        and metadata.get("KeyState") == "Enabled"
        and metadata.get("KeyUsage") == "ENCRYPT_DECRYPT"
        and metadata.get("KeySpec") == "SYMMETRIC_DEFAULT"
    )
