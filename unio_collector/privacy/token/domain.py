from __future__ import annotations  # noqa: D100

# ruff: noqa: EM101,TRY003
from dataclasses import dataclass

from unio_collector.privacy.constants import SUPPORTED_TOKEN_SCOPES


@dataclass(frozen=True)
class TokenDomain:
    """Neutral correlation boundary used by token codecs and vaults."""

    token_scope: str
    scope_boundary_id: str

    def __post_init__(self) -> None:
        """Reject incomplete or unsupported token domains."""
        if self.token_scope not in SUPPORTED_TOKEN_SCOPES:
            raise ValueError("Token scope is unsupported.")
        if not self.scope_boundary_id.strip():
            raise ValueError("Token scope boundary must be a non-empty string.")
