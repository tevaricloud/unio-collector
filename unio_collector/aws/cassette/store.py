from __future__ import annotations  # noqa: D100

import json
import threading
from pathlib import Path
from typing import Any

from unio_collector.aws.cassette.constants import CASSETTE_FILENAME, CASSETTE_VERSION
from unio_collector.aws.cassette.entry import AwsCassetteEntry
from unio_collector.aws.cassette.sanitizer import AwsCassetteSanitizer


class AwsCassetteStore:  # noqa: D101
    def __init__(  # noqa: D107
        self,
        path: str | Path,
        *,
        sanitizer: AwsCassetteSanitizer | None = None,
        recording_status: str = "complete",
        attempt_id: str | None = None,
        scanner_id: str | None = None,
    ) -> None:
        self.path = Path(path)
        if self.path.suffix:
            self.file_path = self.path
        else:
            self.file_path = self.path / CASSETTE_FILENAME
        self.sanitizer = sanitizer or AwsCassetteSanitizer()
        self.recording_status = recording_status
        self.attempt_id = attempt_id
        self.scanner_id = scanner_id
        self._lock = threading.Lock()
        self._entries = self._load_entries()

    def create_late_attempt_store(
        self,
        *,
        attempt_id: str,
        scanner_id: str,
    ) -> AwsCassetteStore:
        """Create an explicitly incomplete quarantine store for a late call."""
        root = self.file_path.parent / "late-attempts" / attempt_id
        return AwsCassetteStore(
            root,
            sanitizer=self.sanitizer,
            recording_status="incomplete_expired_attempt",
            attempt_id=attempt_id,
            scanner_id=scanner_id,
        )

    def add(self, entry: AwsCassetteEntry) -> None:  # noqa: D102
        sanitized = AwsCassetteEntry(
            service=entry.service,
            operation=entry.operation,
            region=entry.region,
            request=self.sanitizer.sanitize(entry.request),
            response=self.sanitizer.sanitize(entry.response),
            error=self.sanitizer.sanitize(entry.error),
        )
        with self._lock:
            self._entries.append(sanitized)
            self._write_locked()

    def find_next(  # noqa: D102
        self,
        *,
        service: str,
        operation: str,
        region: str | None,
        request: dict[str, Any],
        start_index: int,
    ) -> tuple[int, AwsCassetteEntry] | None:
        sanitized_request = self.sanitizer.sanitize(request)
        normalized_region = region or "aws-global"
        with self._lock:
            for index in range(start_index, len(self._entries)):
                entry = self._entries[index]
                if (
                    entry.service == service
                    and entry.operation == operation
                    and (entry.region or "aws-global") == normalized_region
                    and entry.request == sanitized_request
                ):
                    return index, entry
        return None

    def _load_entries(self) -> list[AwsCassetteEntry]:
        if not self.file_path.is_file():
            return []
        payload = json.loads(self.file_path.read_text(encoding="utf-8"))
        if payload.get("version") != CASSETTE_VERSION:
            msg = f"AWS cassette {self.file_path} has an unsupported version."
            raise ValueError(
                msg,
            )
        if payload.get("development_only") is not True:
            msg = f"AWS cassette {self.file_path} is missing development_only=true."
            raise ValueError(
                msg,
            )
        self.recording_status = str(payload.get("recording_status") or "complete")
        self.attempt_id = str(payload["attempt_id"]) if payload.get("attempt_id") else None
        self.scanner_id = str(payload["scanner_id"]) if payload.get("scanner_id") else None
        entries = payload.get("entries", [])
        if not isinstance(entries, list):
            msg = f"AWS cassette {self.file_path} entries must be a list."
            raise ValueError(msg)
        return [
            AwsCassetteEntry(
                service=str(item.get("service", "")),
                operation=str(item.get("operation", "")),
                region=item.get("region"),
                request=dict(item.get("request") or {}),
                response=item.get("response"),
                error=item.get("error"),
            )
            for item in entries
            if isinstance(item, dict)
        ]

    def _write_locked(self) -> None:
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": CASSETTE_VERSION,
            "development_only": True,
            "entries": [entry.convert_to_dict() for entry in self._entries],
        }
        if self.recording_status != "complete":
            payload.update(
                {
                    "recording_status": self.recording_status,
                    "attempt_id": self.attempt_id,
                    "scanner_id": self.scanner_id,
                },
            )
        self.file_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
