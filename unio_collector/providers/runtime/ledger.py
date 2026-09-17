from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path


@dataclass
class EmptyProviderApiCallLedger:
    """Provider-neutral empty API ledger for scans without AWS API audit records."""

    records: list[dict[str, Any]] = field(default_factory=list)

    def write_jsonl(self, path: Path) -> None:
        """Write an empty JSONL ledger artifact."""
        path.write_text("", encoding="utf-8")

    def get_calls_for_scanner(self, scanner_id: str) -> list[str]:
        """Return no API calls for provider-owned non-AWS scanner execution."""
        del scanner_id
        return []

    def get_call_count_for_scanner(self, scanner_id: str) -> int:
        """Return zero API calls for provider-owned non-AWS scanner execution."""
        del scanner_id
        return 0

    def get_permission_failures(self) -> list[dict[str, Any]]:
        """Return no AWS-style permission failures."""
        return []
