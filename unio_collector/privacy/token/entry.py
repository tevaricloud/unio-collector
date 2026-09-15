from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class TokenEntry:
    """Plaintext vault mapping entry."""

    token: str
    category: str
    canonical_value: str
    canonicalization_version: str
    token_scope: str
    scope_boundary_id: str
    collision_index: int
    observed_values: tuple[str, ...] = ()

    def convert_to_dict(self) -> dict[str, object]:
        """Return the sensitive plaintext mapping payload."""
        return {
            "token": self.token,
            "category": self.category,
            "canonical_value": self.canonical_value,
            "canonicalization_version": self.canonicalization_version,
            "token_scope": self.token_scope,
            "scope_boundary_id": self.scope_boundary_id,
            "collision_index": self.collision_index,
            "observed_values": list(self.observed_values),
        }
