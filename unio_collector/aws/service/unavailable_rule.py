from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class ServiceUnavailableErrorRule:  # noqa: D101
    error_codes: frozenset[str]
    message_markers: frozenset[str]
    service_name: str | None = None
    operation_name: str | None = None
    reason: str = "service_not_enabled_or_unavailable"

    def matches(  # noqa: D102
        self,
        *,
        code: str,
        message: str,
        service_name: str | None,
        operation_name: str | None,
    ) -> bool:
        if code not in self.error_codes:
            return False
        if self.service_name is not None and service_name != self.service_name:
            return False
        if self.operation_name is not None and operation_name != self.operation_name:
            return False
        return any(marker in message for marker in self.message_markers)
