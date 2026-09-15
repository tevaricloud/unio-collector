from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.privacy.token.domain import TokenDomain


@dataclass(frozen=True)
class VaultContext:
    """Version and lineage state for one vault-backed operation."""

    vault_id: str
    revision: int
    previous_vault_sha256: str | None
    token_domain: TokenDomain
    export_bindings: tuple[dict[str, object], ...] = ()
    initial_token_count: int = 0
    recovery_key: bytes | None = None
