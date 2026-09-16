from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.privacy.crypto import root_key_fingerprint, scope_fingerprint

if TYPE_CHECKING:
    from unio_collector.privacy.protection_state import ProtectionState


def build_vault_public_metadata(state: ProtectionState) -> dict[str, object]:
    """Return authenticated non-secret lineage and scope fingerprints."""
    context = state.vault_context
    return {
        "vault_id": context.vault_id,
        "vault_revision": context.revision,
        "root_key_fingerprint": root_key_fingerprint(state.root_key),
        "scope_fingerprint": scope_fingerprint(
            state.root_key,
            context.token_domain.token_scope,
            context.token_domain.scope_boundary_id,
        ),
    }
