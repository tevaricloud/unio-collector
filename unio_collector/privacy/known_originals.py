from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.privacy.tokens import TokenService


def collect_known_original_values(
    token_service: TokenService,
    *,
    minimum_length: int,
) -> set[str]:
    """Return observed/canonical values for leak scanning."""
    values: set[str] = set()
    for entry in token_service.vault_builder.entries_by_token.values():
        values.add(entry.canonical_value)
        values.update(entry.observed_values)
    return {value for value in values if value and len(value) >= minimum_length}
