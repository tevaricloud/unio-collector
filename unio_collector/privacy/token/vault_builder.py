from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.privacy.token.entry import TokenEntry


@dataclass
class TokenVaultBuilder:
    """Collect token mappings before vault encryption."""

    entries_by_token: dict[str, TokenEntry] = field(default_factory=dict)
    token_by_identity: dict[tuple[str, str, str, str, str], str] = field(
        default_factory=dict,
    )

    def add_entry(self, entry: TokenEntry) -> None:
        """Record one sensitive token mapping."""
        self.entries_by_token[entry.token] = entry
        self.token_by_identity[
            (
                entry.category,
                entry.canonicalization_version,
                entry.canonical_value,
                entry.token_scope,
                entry.scope_boundary_id,
            )
        ] = entry.token

    def convert_to_plaintext(self) -> dict[str, object]:
        """Return vault plaintext. Callers must encrypt before writing."""
        return {
            "schema_version": "2026-08-v2",
            "entries": [
                entry.convert_to_dict()
                for entry in sorted(
                    self.entries_by_token.values(),
                    key=lambda item: item.token,
                )
            ],
        }
