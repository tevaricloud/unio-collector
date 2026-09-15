from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class BedrockOperationLimitation:
    """Safe operation-capability metadata for one Bedrock region."""

    api_action: str
    status: str
    error_classification: str
    error_code: str | None = None
