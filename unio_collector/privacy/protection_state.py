from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from unio_collector.privacy.registry import ClassificationSummary

if TYPE_CHECKING:
    from unio_collector.privacy.profiles import PrivacyProfile
    from unio_collector.privacy.reusable_vault.context import VaultContext
    from unio_collector.privacy.tokens import TokenService


@dataclass
class ProtectionState:
    """Mutable state for one protected bundle creation."""

    profile: PrivacyProfile
    root_key: bytes
    token_service: TokenService
    vault_context: VaultContext
    classification: ClassificationSummary = field(default_factory=ClassificationSummary)
    warnings: list[str] = field(default_factory=list)

    def vault_plaintext(self) -> dict[str, object]:
        """Return the complete sensitive vault snapshot for encryption."""
        payload = self.token_service.vault_builder.convert_to_plaintext()
        payload.update(
            {
                "vault_id": self.vault_context.vault_id,
                "revision": self.vault_context.revision,
                "token_scope": self.vault_context.token_domain.token_scope,
                "scope_boundary_id": self.vault_context.token_domain.scope_boundary_id,
                "export_bindings": list(self.vault_context.export_bindings),
            },
        )
        return payload
