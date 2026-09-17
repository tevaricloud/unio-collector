from __future__ import annotations  # noqa: D100

import re
from dataclasses import replace
from typing import TYPE_CHECKING

from unio_collector.privacy.token.codec import TOKEN_PREFIXES, TokenV1Codec
from unio_collector.privacy.token.domain import TokenDomain
from unio_collector.privacy.token.entry import TokenEntry
from unio_collector.privacy.token.vault_builder import TokenVaultBuilder

if TYPE_CHECKING:
    from unio_collector.privacy.canonicalization import CanonicalValue

TOKEN_RE = re.compile(r"^(ACCOUNT|RESOURCE|ROLE|IPV4|IPV6|CIDR|DNS|EMAIL|BUCKET|ARN|TAG)-[A-Z2-7]{16}$")
MAX_TOKEN_SUFFIX_BYTES = 32

__all__ = [
    "TOKEN_PREFIXES",
    "TOKEN_RE",
    "TokenEntry",
    "TokenService",
    "TokenVaultBuilder",
    "is_protected_token",
]


def is_protected_token(value: object) -> bool:
    """Return true when a value is an explicit Unio protected token."""
    return isinstance(value, str) and TOKEN_RE.fullmatch(value.strip()) is not None


class TokenService:
    """Create deterministic typed tokens from HKDF-derived HMAC keys."""

    def __init__(
        self,
        *,
        token_key: bytes,
        provider: str,
        token_scope: str,
        engagement_id: str | None = None,
        token_domain: TokenDomain | None = None,
        vault_builder: TokenVaultBuilder | None = None,
        token_suffix_bytes: int = 10,
    ) -> None:
        """Create a token service for one provider, scope, and engagement."""
        if type(token_suffix_bytes) is not int or not 1 <= token_suffix_bytes <= MAX_TOKEN_SUFFIX_BYTES:
            message = "Token suffix length must be between 1 and 32 bytes."
            raise ValueError(message)
        self._token_key = token_key
        self._provider = provider
        self._domain = token_domain or TokenDomain(
            token_scope=token_scope,
            scope_boundary_id=engagement_id or "",
        )
        self._vault_builder = vault_builder or TokenVaultBuilder()
        self._token_suffix_bytes = token_suffix_bytes
        self._initial_tokens = frozenset(self._vault_builder.entries_by_token)
        self._reused_tokens: set[str] = set()
        self._new_tokens: set[str] = set()

    @property
    def vault_builder(self) -> TokenVaultBuilder:
        """Return the plaintext mapping collector."""
        return self._vault_builder

    @property
    def reused_token_count(self) -> int:
        """Return distinct pre-existing tokens referenced in this operation."""
        return len(self._reused_tokens)

    @property
    def new_token_count(self) -> int:
        """Return distinct tokens created in this operation."""
        return len(self._new_tokens)

    def token_for(
        self,
        canonical: CanonicalValue,
        *,
        observed_value: object | None = None,
    ) -> str:
        """Return a deterministic token for a canonical sensitive value."""
        identity = (
            canonical.category,
            canonical.version,
            canonical.value,
            self._domain.token_scope,
            self._domain.scope_boundary_id,
        )
        existing = self._vault_builder.token_by_identity.get(identity)
        if existing:
            if observed_value is not None:
                entry = self._vault_builder.entries_by_token[existing]
                observed = str(observed_value)
                if observed not in entry.observed_values:
                    self._vault_builder.add_entry(replace(entry, observed_values=(*entry.observed_values, observed)))
            if existing in self._initial_tokens:
                self._reused_tokens.add(existing)
            return existing
        collision_index = 0
        while True:
            candidate = self._candidate(canonical, collision_index)
            existing_entry = self._vault_builder.entries_by_token.get(candidate)
            if existing_entry is None or self._entry_identity(existing_entry) == identity:
                break
            collision_index += 1
        entry = TokenEntry(
            token=candidate,
            category=canonical.category,
            canonical_value=canonical.value,
            canonicalization_version=canonical.version,
            token_scope=self._domain.token_scope,
            scope_boundary_id=self._domain.scope_boundary_id,
            collision_index=collision_index,
            observed_values=(str(observed_value),) if observed_value is not None else (),
        )
        self._vault_builder.add_entry(entry)
        self._new_tokens.add(candidate)
        return candidate

    def _candidate(self, canonical: CanonicalValue, collision_index: int) -> str:
        return TokenV1Codec().candidate(
            token_key=self._token_key,
            provider=self._provider,
            domain=self._domain,
            canonical=canonical,
            collision_index=collision_index,
            suffix_bytes=self._token_suffix_bytes,
        )

    def _entry_identity(self, entry: TokenEntry) -> tuple[str, str, str, str, str]:
        return (
            entry.category,
            entry.canonicalization_version,
            entry.canonical_value,
            entry.token_scope,
            entry.scope_boundary_id,
        )
