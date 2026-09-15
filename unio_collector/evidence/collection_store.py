"""Accumulate neutral evidence without projecting private findings."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

    from unio_collector.evidence.models import EvidenceRecord


@dataclass
class CollectionEvidenceStore:
    """Store typed records and deterministic factual collection summaries."""

    records: list[EvidenceRecord] = field(default_factory=list)
    _count_by_scanner: dict[str, int] = field(default_factory=dict, init=False, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def add(self, record: EvidenceRecord) -> None:
        """Append a collected record and update its scanner count atomically."""
        with self._lock:
            self.records.append(record)
            self._increment_scanner_count(record.source_scanner_id)

    def extend(self, records: Iterable[EvidenceRecord]) -> None:
        """Materialize caller records before atomically adding their counts."""
        materialized_records = list(records)
        with self._lock:
            self.records.extend(materialized_records)
            for record in materialized_records:
                self._increment_scanner_count(record.source_scanner_id)

    def get_records(self) -> list[EvidenceRecord]:
        """Return a stable shallow copy of collected records."""
        with self._lock:
            return list(self.records)

    def count_for_scanner(self, scanner_id: str) -> int:
        """Return the accumulated count for one scanner."""
        with self._lock:
            return self._count_by_scanner.get(scanner_id, 0)

    def _increment_scanner_count(self, scanner_id: str) -> None:
        self._count_by_scanner[scanner_id] = self._count_by_scanner.get(scanner_id, 0) + 1

    def convert_to_summary(self) -> dict[str, object]:
        """Summarize factual record counts using the existing output contract."""
        by_scanner: dict[str, int] = {}
        by_service: dict[str, int] = {}
        by_region: dict[str, int] = {}
        records = self.get_records()
        for record in records:
            by_scanner[record.source_scanner_id] = by_scanner.get(record.source_scanner_id, 0) + 1
            by_service[record.service] = by_service.get(record.service, 0) + 1
            by_region[record.region] = by_region.get(record.region, 0) + 1
        return {
            "evidence_count": len(records),
            "by_scanner": dict(sorted(by_scanner.items())),
            "by_service": dict(sorted(by_service.items())),
            "by_region": dict(sorted(by_region.items())),
            "raw_aws_payloads_stored": False,
            "limitations": [
                "Unio Collector stores normalized evidence summaries by default, not full raw AWS responses.",
            ],
        }

    def convert_to_json_records(self) -> list[dict[str, object]]:
        """Encode a stable snapshot of records through their existing model."""
        return [record.model_dump(mode="json") for record in self.get_records()]
