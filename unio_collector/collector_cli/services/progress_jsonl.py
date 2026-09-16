from __future__ import annotations  # noqa: D100

import json
from dataclasses import asdict
from pathlib import Path
from typing import IO, TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.scan_workflow.progress import ScanProgressEvent

PROGRESS_EVENT_SCHEMA_VERSION = 1


class CollectorJsonlProgressWriter:
    """Write optional structured collector progress without changing console output."""

    def __init__(self, stream: IO[str] | None = None) -> None:
        """Store an optional owned stream."""
        self._stream = stream

    @classmethod
    def from_args(cls, args: object) -> CollectorJsonlProgressWriter:
        """Create a writer for the requested progress path."""
        raw_path = getattr(args, "progress_jsonl", None)
        if not raw_path:
            return cls()
        path = Path(str(raw_path))
        path.parent.mkdir(parents=True, exist_ok=True)
        return cls(path.open("w", encoding="utf-8"))

    def write(self, event: ScanProgressEvent) -> None:
        """Append one event and flush it for real-time launcher consumption."""
        if self._stream is None:
            return
        payload: dict[str, object] = {
            "schema_version": PROGRESS_EVENT_SCHEMA_VERSION,
            **asdict(event),
        }
        self._stream.write(json.dumps(payload, sort_keys=True) + "\n")
        self._stream.flush()

    def close(self) -> None:
        """Close the owned stream when present."""
        if self._stream is not None:
            self._stream.close()


__all__ = ["PROGRESS_EVENT_SCHEMA_VERSION", "CollectorJsonlProgressWriter"]
