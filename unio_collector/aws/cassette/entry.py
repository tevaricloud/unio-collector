from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class AwsCassetteEntry:  # noqa: D101
    service: str
    operation: str
    region: str | None
    request: dict[str, Any]
    response: dict[str, Any] | None = None
    error: dict[str, Any] | None = None

    def convert_to_dict(self) -> dict[str, Any]:  # noqa: D102
        return {
            "service": self.service,
            "operation": self.operation,
            "region": self.region,
            "request": self.request,
            "response": self.response,
            "error": self.error,
        }
