from __future__ import annotations  # noqa: D100

from enum import StrEnum


class CacheFailureCategory(StrEnum):
    """Provider-neutral classification for a failed cache load."""

    EXPECTED_ABSENCE = "expected_absence"
    PERMISSION_DENIED = "permission_denied"
    THROTTLING = "throttling"
    SERVICE_UNAVAILABLE = "service_unavailable"
    TRANSIENT_NETWORK = "transient_network"
    CANCELLATION = "cancellation"
    DEADLINE_EXPIRED = "deadline_expired"
    INTERNAL_LOADER_ERROR = "internal_loader_error"
