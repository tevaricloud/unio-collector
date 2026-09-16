from __future__ import annotations  # noqa: D100

# ruff: noqa: EM101,TRY003
import base64
import uuid
from typing import TYPE_CHECKING

from unio_collector.privacy.admission.vault import VaultSource
from unio_collector.privacy.canonicalization import canonicalize_value
from unio_collector.privacy.constants import (
    LEGACY_VAULT_FORMAT_VERSION,
    TOKEN_FORMAT_VERSION,
    VAULT_FORMAT_VERSION,
)
from unio_collector.privacy.crypto import derive_subkey, root_key_fingerprint, scope_fingerprint
from unio_collector.privacy.reusable_vault.context import VaultContext
from unio_collector.privacy.token.entry import TokenEntry
from unio_collector.privacy.token.vault_builder import TokenVaultBuilder
from unio_collector.privacy.tokens import TokenService, is_protected_token
from unio_collector.privacy.vault import read_vault_recovery_mode, unlock_vault

if TYPE_CHECKING:
    from pathlib import Path

    from unio_collector.privacy.token.domain import TokenDomain


class ReusableVaultLoader:
    """Unlock and validate a reusable identity vault without leaking its values."""

    def load(
        self,
        *,
        path: Path,
        domain: TokenDomain,
        passphrase: str | None,
        recovery_key_path: Path | None,
    ) -> tuple[bytes, TokenVaultBuilder, VaultContext]:
        """Return the root key, validated mappings, and next revision context."""
        source = VaultSource.read(path)
        payload = source.payload
        recovery_key = self._read_recovery_key(recovery_key_path)
        unlocked = unlock_vault(
            payload,
            passphrase=passphrase,
            recovery_key=recovery_key,
        )
        metadata = unlocked.metadata
        format_version = metadata.get("format")
        if format_version not in {LEGACY_VAULT_FORMAT_VERSION, VAULT_FORMAT_VERSION}:
            raise ValueError("Existing vault format is unsupported.")
        if metadata.get("provider", "aws") != "aws":
            raise ValueError("Existing vault provider does not match the AWS privacy workflow.")
        if metadata.get("token_format_version", TOKEN_FORMAT_VERSION) != TOKEN_FORMAT_VERSION:
            raise ValueError("Existing vault token format is unsupported.")
        if metadata.get("token_scope") != domain.token_scope:
            raise ValueError("Existing vault token scope does not match the requested scope.")
        self._validate_scope(metadata, unlocked.plaintext, unlocked.root_key, domain)
        builder = self._load_entries(unlocked.plaintext, unlocked.root_key, domain)
        vault_id = metadata.get("vault_id")
        if not isinstance(vault_id, str) or not vault_id:
            vault_id = str(uuid.uuid4())
        current_revision = metadata.get("revision")
        revision = current_revision + 1 if isinstance(current_revision, int) and current_revision > 0 else 2
        exports = unlocked.plaintext.get("export_bindings")
        if exports is not None and (not isinstance(exports, list) or any(not isinstance(item, dict) for item in exports)):
            raise ValueError("Existing vault export bindings are invalid.")
        export_bindings = tuple(exports) if isinstance(exports, list) else ()
        return (
            unlocked.root_key,
            builder,
            VaultContext(
                vault_id=vault_id,
                revision=revision,
                previous_vault_sha256=source.sha256,
                token_domain=domain,
                export_bindings=export_bindings,
                initial_token_count=len(builder.entries_by_token),
                recovery_key=recovery_key,
            ),
        )

    def _validate_scope(
        self,
        metadata: dict[str, object],
        plaintext: dict[str, object],
        root_key: bytes,
        domain: TokenDomain,
    ) -> None:
        stored = plaintext.get("scope_boundary_id")
        if not isinstance(stored, str):
            stored = metadata.get("engagement_id")
        if stored != domain.scope_boundary_id:
            raise ValueError("Existing vault scope boundary does not match the requested scope.")
        fingerprint = metadata.get("scope_fingerprint")
        expected = scope_fingerprint(root_key, domain.token_scope, domain.scope_boundary_id)
        if fingerprint is not None and fingerprint != expected:
            raise ValueError("Existing vault scope fingerprint is invalid.")
        root_fingerprint = metadata.get("root_key_fingerprint")
        if root_fingerprint != root_key_fingerprint(root_key):
            raise ValueError("Existing vault root-key fingerprint is invalid.")

    def _load_entries(
        self,
        plaintext: dict[str, object],
        root_key: bytes,
        domain: TokenDomain,
    ) -> TokenVaultBuilder:
        raw_entries = plaintext.get("entries")
        if not isinstance(raw_entries, list):
            raise ValueError("Existing vault token entries are missing or invalid.")
        builder = TokenVaultBuilder()
        verifier = TokenService(
            token_key=derive_subkey(root_key, "token-hmac"),
            provider="aws",
            token_scope=domain.token_scope,
            token_domain=domain,
        )
        identities: set[tuple[str, str, str, str, str]] = set()
        for raw in raw_entries:
            if not isinstance(raw, dict):
                raise ValueError("Existing vault contains an invalid token entry.")
            entry = self._parse_entry(raw, domain)
            identity = (
                entry.category,
                entry.canonicalization_version,
                entry.canonical_value,
                entry.token_scope,
                entry.scope_boundary_id,
            )
            if identity in identities or entry.token in builder.entries_by_token:
                raise ValueError("Existing vault contains conflicting token entries.")
            canonical = canonicalize_value(entry.category, entry.canonical_value)
            if canonical.value != entry.canonical_value or canonical.version != entry.canonicalization_version:
                raise ValueError("Existing vault canonical value is inconsistent.")
            if verifier._candidate(canonical, entry.collision_index) != entry.token:  # noqa: SLF001
                raise ValueError("Existing vault token verification failed.")
            identities.add(identity)
            builder.add_entry(entry)
        return builder

    def _parse_entry(self, raw: dict[str, object], domain: TokenDomain) -> TokenEntry:
        token = raw.get("token")
        category = raw.get("category")
        canonical_value = raw.get("canonical_value")
        canonical_version = raw.get("canonicalization_version")
        token_scope = raw.get("token_scope")
        boundary = raw.get("scope_boundary_id", raw.get("engagement_id"))
        collision_index = raw.get("collision_index")
        observed = raw.get("observed_values", [])
        if (
            not is_protected_token(token)
            or not all(isinstance(value, str) and value for value in (category, canonical_value, canonical_version, token_scope, boundary))
            or type(collision_index) is not int
            or collision_index < 0
            or token_scope != domain.token_scope
            or boundary != domain.scope_boundary_id
            or not isinstance(observed, list)
            or any(not isinstance(value, str) for value in observed)
        ):
            raise ValueError("Existing vault contains an invalid token entry.")
        return TokenEntry(
            token=str(token),
            category=str(category),
            canonical_value=str(canonical_value),
            canonicalization_version=str(canonical_version),
            token_scope=str(token_scope),
            scope_boundary_id=str(boundary),
            collision_index=collision_index,
            observed_values=tuple(observed),
        )

    def _read_recovery_key(self, path: Path | None) -> bytes | None:
        if path is None:
            return None
        try:
            return base64.b64decode(path.read_text(encoding="utf-8").strip(), validate=True)
        except (OSError, UnicodeError, ValueError) as exc:
            raise ValueError("Existing recovery key could not be read.") from exc

    def recovery_mode(self, path: Path) -> str:
        """Return the existing vault recovery mode for CLI resolution."""
        return read_vault_recovery_mode(path)
