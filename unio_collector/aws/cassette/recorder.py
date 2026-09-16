from __future__ import annotations  # noqa: D100

import threading
from typing import TYPE_CHECKING, Any

from botocore.exceptions import ClientError

from unio_collector.aws.cassette.entry import AwsCassetteEntry

if TYPE_CHECKING:
    from unio_collector.aws.cassette.store import AwsCassetteStore
    from unio_collector.core.attempt import AttemptDeadlineContract


class AwsCassetteRecorder:  # noqa: D101
    def __init__(self, store: AwsCassetteStore) -> None:  # noqa: D107
        self.store = store
        self._late_stores: dict[str, AwsCassetteStore] = {}
        self._lock = threading.Lock()

    def record_response(  # noqa: D102
        self,
        *,
        service: str,
        operation: str,
        region: str | None,
        request: dict[str, Any],
        response: dict[str, Any],
        attempt: AttemptDeadlineContract | None = None,
        completion_classification: str = "unscoped",
    ) -> None:
        self._get_store(attempt, completion_classification).add(
            AwsCassetteEntry(
                service=service,
                operation=operation,
                region=region or "aws-global",
                request=request,
                response=response,
            ),
        )

    def record_error(  # noqa: D102
        self,
        *,
        service: str,
        operation: str,
        region: str | None,
        request: dict[str, Any],
        error: Exception,
        attempt: AttemptDeadlineContract | None = None,
        completion_classification: str = "unscoped",
    ) -> None:
        payload = convert_error_to_payload(error)
        self._get_store(attempt, completion_classification).add(
            AwsCassetteEntry(
                service=service,
                operation=operation,
                region=region or "aws-global",
                request=request,
                error=payload,
            ),
        )

    def _get_store(
        self,
        attempt: AttemptDeadlineContract | None,
        completion_classification: str,
    ) -> AwsCassetteStore:
        if completion_classification != "late" or attempt is None:
            return self.store
        with self._lock:
            store = self._late_stores.get(attempt.attempt_id)
            if store is None:
                store = self.store.create_late_attempt_store(
                    attempt_id=attempt.attempt_id,
                    scanner_id=attempt.scanner_id,
                )
                self._late_stores[attempt.attempt_id] = store
            return store


def convert_error_to_payload(error: Exception) -> dict[str, Any]:  # noqa: D103
    if isinstance(error, ClientError):
        return {
            "Error": dict(error.response.get("Error", {})),
            "ResponseMetadata": dict(error.response.get("ResponseMetadata", {})),
        }
    return {
        "Error": {
            "Code": error.__class__.__name__,
            "Message": str(error),
        },
        "ResponseMetadata": {},
    }
