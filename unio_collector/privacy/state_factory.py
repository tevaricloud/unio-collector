from __future__ import annotations  # noqa: D100

# ruff: noqa: EM101,S105,TRY003
import uuid
from dataclasses import replace
from typing import TYPE_CHECKING

from unio_collector.privacy.crypto import derive_subkey, generate_root_key
from unio_collector.privacy.protection_state import ProtectionState
from unio_collector.privacy.reusable_vault.context import VaultContext
from unio_collector.privacy.reusable_vault.loader import ReusableVaultLoader
from unio_collector.privacy.token.domain import TokenDomain
from unio_collector.privacy.tokens import TokenService, TokenVaultBuilder

if TYPE_CHECKING:
    from unio_collector.privacy.options import PrivacyProtectOptions
    from unio_collector.privacy.profiles import PrivacyProfile


class ProtectionStateFactory:
    """Create new or reusable token and vault state for one export."""

    def build(
        self,
        options: PrivacyProtectOptions,
        profile: PrivacyProfile,
        *,
        source_bundle_id: str,
        protected_bundle_id: str,
    ) -> ProtectionState:
        """Create state and append the current encrypted export binding."""
        domain = self._resolve_domain(options, source_bundle_id)
        if options.existing_vault_path is None:
            root_key = generate_root_key()
            vault_builder = TokenVaultBuilder()
            context = VaultContext(
                vault_id=str(uuid.uuid4()),
                revision=1,
                previous_vault_sha256=None,
                token_domain=domain,
            )
        else:
            root_key, vault_builder, context = ReusableVaultLoader().load(
                path=options.existing_vault_path,
                domain=domain,
                passphrase=options.passphrase,
                recovery_key_path=options.existing_recovery_key_path,
            )
        binding = {
            "source_bundle_id": source_bundle_id,
            "protected_bundle_id": protected_bundle_id,
            "privacy_policy_version": "2026-03",
            "profile_id": profile.profile_id,
            "profile_version": profile.version,
            "engagement_id": options.engagement_id,
        }
        context = replace(context, export_bindings=(*context.export_bindings, binding))
        return ProtectionState(
            profile=profile,
            root_key=root_key,
            token_service=TokenService(
                token_key=derive_subkey(root_key, "token-hmac"),
                provider="aws",
                token_scope=domain.token_scope,
                token_domain=domain,
                vault_builder=vault_builder,
            ),
            vault_context=context,
        )

    def validate_paths(self, options: PrivacyProtectOptions) -> None:
        """Require explicit opt-in and matching targets for in-place updates."""
        if options.in_place_vault_update and options.existing_vault_path is None:
            raise ValueError("In-place vault update requires --existing-vault.")
        if options.existing_vault_path is None:
            return
        same_path = options.existing_vault_path.resolve(strict=False) == options.vault_path.resolve(strict=False)
        if same_path and not options.in_place_vault_update:
            raise ValueError("Existing and output vault paths must differ unless in-place update is explicitly enabled.")
        if options.in_place_vault_update and not same_path:
            raise ValueError("In-place vault update requires the existing and output vault paths to match.")

    def _resolve_domain(
        self,
        options: PrivacyProtectOptions,
        source_bundle_id: str,
    ) -> TokenDomain:
        if options.token_scope == "bundle":
            if options.existing_vault_path is not None:
                raise ValueError("Bundle-scoped token vaults cannot be reused.")
            boundary = source_bundle_id
        elif options.token_scope == "client":
            if not options.client_id:
                raise ValueError("Client token scope requires --client-id.")
            boundary = options.client_id
        else:
            boundary = options.engagement_id
        return TokenDomain(token_scope=options.token_scope, scope_boundary_id=boundary)
