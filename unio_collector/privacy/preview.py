from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

from unio_collector.privacy.constants import PRIVACY_POLICY_VERSION
from unio_collector.privacy.crypto import root_key_fingerprint, scope_fingerprint

if TYPE_CHECKING:
    from unio_collector.privacy.options import PrivacyProtectOptions
    from unio_collector.privacy.protection_state import ProtectionState
    from unio_collector.privacy.security_warning import SecurityWarning


def build_privacy_preview(
    *,
    options: PrivacyProtectOptions,
    state: ProtectionState,
    source_manifest: dict[str, Any],
    source_bundle_id: str,
    source_bundle_id_scheme: str,
    protected_bundle_id: str,
    leak_scan: dict[str, object],
    warnings: tuple[str, ...],
    warning_details: tuple[SecurityWarning, ...] = (),
) -> dict[str, object]:
    """Build the non-secret local privacy preview metadata."""
    return {
        "protected": True,
        "protected_bundle_id": protected_bundle_id,
        "source_bundle_id": source_bundle_id,
        "source_bundle_id_scheme": source_bundle_id_scheme,
        "source_bundle_schema_version": source_manifest.get("bundle_schema_version"),
        "privacy_policy_version": PRIVACY_POLICY_VERSION,
        "profile": state.profile.convert_to_dict(),
        "token_scope": options.token_scope,
        "engagement_id": options.engagement_id,
        "vault_id": state.vault_context.vault_id,
        "vault_revision": state.vault_context.revision,
        "root_key_fingerprint": root_key_fingerprint(state.root_key),
        "scope_fingerprint": scope_fingerprint(
            state.root_key,
            state.vault_context.token_domain.token_scope,
            state.vault_context.token_domain.scope_boundary_id,
        ),
        "tokenised_categories": dict(sorted(state.classification.tokenised.items())),
        "removed_count": state.classification.removed,
        "preserved_count": state.classification.preserved,
        "unclassified_field_count": len(state.classification.unclassified),
        "unclassified_fields": list(state.classification.unclassified),
        "prohibited_field_count": len(state.classification.prohibited_paths),
        "prohibited_paths": list(state.classification.prohibited_paths),
        "cost_data_remains_visible": state.profile.cost_data_included,
        "topology_may_remain_visible": state.profile.topology_detail != "reduced",
        "actual_applied_transformations": state.classification.applied_transformations(),
        "resolver_decisions": state.classification.resolver_decisions(),
        "vault_loss_risk_acknowledged": options.acknowledge_vault_loss_risk,
        "vault_loss_risk_notice": (
            "The encrypted private identity vault is required for restoration. "
            "Tevari cannot recover original identifiers, and vault/recovery "
            "material must not be transferred with the protected bundle."
        ),
        "vault_included": False,
        "recovery_material_included": False,
        "leak_scan": leak_scan,
        "warnings": [*state.classification.warnings, *warnings],
        "warning_details": [warning.convert_to_dict() for warning in warning_details],
        "notice": (
            "This is pseudonymisation, not anonymisation. Residual cost, utilisation, topology, region, service usage, and timing data may remain sensitive."
        ),
    }
