from __future__ import annotations  # noqa: D100

import threading
from typing import TYPE_CHECKING, Any

from unio_collector.aws.cassette.errors import (
    MissingAwsCassetteEntryError,
    build_client_error,
)

if TYPE_CHECKING:
    from unio_collector.aws.cassette.store import AwsCassetteStore


class AwsCassetteReplayer:  # noqa: D101
    def __init__(self, store: AwsCassetteStore) -> None:  # noqa: D107
        if store.recording_status != "complete":
            msg = f"AWS cassette replay requires a complete recording; found {store.recording_status}."
            raise ValueError(msg)
        self.store = store
        self._next_index = 0
        self._lock = threading.Lock()

    def replay(  # noqa: D102
        self,
        *,
        service: str,
        operation: str,
        region: str | None,
        request: dict[str, Any],
    ) -> dict[str, Any]:
        with self._lock:
            found = self.store.find_next(
                service=service,
                operation=operation,
                region=region,
                request=request,
                start_index=self._next_index,
            )
            if found is None:
                msg = f"Missing AWS cassette entry for {service}:{operation} in {region or 'aws-global'}"
                raise MissingAwsCassetteEntryError(
                    msg,
                )
            index, entry = found
            self._next_index = index + 1
        if entry.error:
            raise build_client_error(entry.error, operation)
        return dict(entry.response or {})
