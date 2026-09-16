from __future__ import annotations  # noqa: D100

from typing import Any

from botocore.exceptions import ClientError


class MissingAwsCassetteEntryError(RuntimeError):
    """Raised when replay mode cannot satisfy an AWS call from cassette data."""


def build_client_error(payload: dict[str, Any], operation: str) -> ClientError:  # noqa: D103
    return ClientError(
        {
            "Error": dict(payload.get("Error") or {}),
            "ResponseMetadata": dict(payload.get("ResponseMetadata") or {}),
        },
        operation,
    )
