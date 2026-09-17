from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping


@dataclass(frozen=True)
class ScannerScheduleStage:
    """One scanner scheduler stage."""

    name: str
    scanner_ids: tuple[str, ...]
    concurrent: bool
    attached_dependents: Mapping[str, tuple[str, ...]] = field(default_factory=dict)

    def is_empty(self) -> bool:  # noqa: D102
        return not self.scanner_ids

    def list_all_scanner_ids(self) -> tuple[str, ...]:  # noqa: D102
        attached_ids = tuple(dependent_id for dependent_ids in self.attached_dependents.values() for dependent_id in dependent_ids)
        return (*self.scanner_ids, *attached_ids)

    def convert_to_dict(self) -> dict[str, object]:  # noqa: D102
        stage = {
            "name": self.name,
            "scanner_ids": list(self.scanner_ids),
            "concurrent": self.concurrent,
        }
        if self.attached_dependents:
            stage["attached_dependents"] = {
                scanner_id: list(dependent_ids)
                for scanner_id, dependent_ids in sorted(
                    self.attached_dependents.items(),
                )
            }
            stage["all_scanner_ids"] = list(self.list_all_scanner_ids())
        return stage
