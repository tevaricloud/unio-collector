from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Mapping


_PRIVACY_COMPARISON_KEYS: tuple[str, ...] = (
    "privacy_policy_version",
    "profile_id",
    "profile_version",
    "token_format_version",
    "token_scope",
    "engagement_id",
)


def is_protected_manifest(manifest: Mapping[str, Any]) -> bool:
    """Return whether a manifest describes a protected evidence bundle."""
    privacy = manifest.get("privacy_protection")
    return isinstance(privacy, dict) and privacy.get("enabled") is True


class ProtectedLlmPolicy:
    """Enforce the v1 prohibition on protected evidence LLM processing."""

    ERROR_MESSAGE = (
        "Protected evidence bundles require an explicit --llm none in v1. "
        "Configured or inherited LLM providers are not allowed. "
        "Protected-LLM policy support is not implemented."
    )

    def validate_request(
        self,
        manifest: Mapping[str, Any],
        *,
        requested_provider: str | None,
    ) -> None:
        """Require an explicit no-LLM request before resolving configuration."""
        if is_protected_manifest(manifest) and requested_provider != "none":
            raise ValueError(self.ERROR_MESSAGE)

    def validate_effective_provider(
        self,
        manifest: Mapping[str, Any],
        *,
        requested_provider: str | None,
        effective_provider: str | None,
    ) -> None:
        """Fail closed unless both requested and effective providers disable LLMs."""
        if not is_protected_manifest(manifest):
            return
        if requested_provider != "none" or effective_provider != "none":
            raise ValueError(self.ERROR_MESSAGE)

    def validate_bundle_summary(
        self,
        summary: Mapping[str, Any],
        *,
        requested_provider: str | None,
        effective_provider: str | None,
    ) -> None:
        """Apply the policy to a report bundle at pipeline entry."""
        evidence_bundle = summary.get("evidence_bundle")
        if not isinstance(evidence_bundle, dict):
            return
        privacy = evidence_bundle.get("privacy_protection")
        if not isinstance(privacy, dict):
            return
        self.validate_effective_provider(
            {"privacy_protection": privacy},
            requested_provider=requested_provider,
            effective_provider=effective_provider,
        )


def privacy_protection_metadata(manifest: Mapping[str, Any]) -> dict[str, Any]:
    """Return non-secret protected-bundle metadata safe for offline summaries."""
    privacy = manifest.get("privacy_protection")
    if not isinstance(privacy, dict):
        return {"enabled": False}
    return {
        "enabled": privacy.get("enabled") is True,
        "privacy_policy_version": privacy.get("privacy_policy_version"),
        "profile_id": privacy.get("profile_id"),
        "profile_version": privacy.get("profile_version"),
        "token_format_version": privacy.get("token_format_version"),
        "token_scope": privacy.get("token_scope"),
        "engagement_id": privacy.get("engagement_id"),
        "vault_id": privacy.get("vault_id"),
        "vault_revision": privacy.get("vault_revision"),
        "root_key_fingerprint": privacy.get("root_key_fingerprint"),
        "scope_fingerprint": privacy.get("scope_fingerprint"),
        "protected_bundle_id": privacy.get("protected_bundle_id"),
        "source_bundle_schema_version": privacy.get(
            "source_bundle_schema_version",
        ),
        "vault_included": privacy.get("vault_included"),
        "recovery_material_included": privacy.get(
            "recovery_material_included",
        ),
        "leak_scan_passed": privacy.get("leak_scan_passed"),
        "coverage_gate": privacy.get("coverage_gate"),
        "actual_applied_transformations": privacy.get(
            "actual_applied_transformations",
        ),
        "vault_loss_risk_acknowledged": privacy.get(
            "vault_loss_risk_acknowledged",
        ),
    }


def build_protected_bundle_limitation(
    manifest: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Build a non-secret analysis limitation for protected bundles."""
    if not is_protected_manifest(manifest):
        return None
    privacy = privacy_protection_metadata(manifest)
    limitation: dict[str, Any] = {
        "type": "privacy_protection",
        "reason": ("Bundle contains pseudonymised typed token references. Offline analysis cannot restore protected identifiers."),
        "privacy_policy_version": privacy.get("privacy_policy_version"),
        "profile_id": privacy.get("profile_id"),
        "token_format_version": privacy.get("token_format_version"),
        "token_scope": privacy.get("token_scope"),
        "engagement_id": privacy.get("engagement_id"),
        "protected_bundle_id": privacy.get("protected_bundle_id"),
        "vault_required_for_restoration": True,
        "llm_policy": "llm_disabled_in_v1",
        "residual_sensitive_data": [
            "utilisation",
            "service_usage",
            "timing",
        ],
    }
    applied = privacy.get("actual_applied_transformations")
    if isinstance(applied, dict) and int(applied.get("cost_values_removed") or 0) > 0:
        limitation["cost_precision_limitation"] = "Cost values were removed or generalised by privacy policy; financial and clean-cost conclusions are limited."
    else:
        limitation["residual_sensitive_data"].append("cost")
    if isinstance(applied, dict) and int(applied.get("topology_values_reduced") or 0) > 0:
        limitation["topology_limitation"] = "Topology detail was reduced by privacy policy."
    else:
        limitation["residual_sensitive_data"].append("topology")
    if isinstance(applied, dict) and int(applied.get("regions_generalised") or 0) > 0:
        limitation["region_limitation"] = "Region detail was generalised by privacy policy."
    else:
        limitation["residual_sensitive_data"].append("region")
    return limitation


def validate_privacy_comparable(
    before_manifest: Mapping[str, Any],
    after_manifest: Mapping[str, Any],
) -> list[str]:
    """Return protected-bundle compatibility errors for comparison."""
    before_protected = is_protected_manifest(before_manifest)
    after_protected = is_protected_manifest(after_manifest)
    if before_protected != after_protected:
        return [
            f"privacy protection differs: before protected={before_protected}, after protected={after_protected}",
        ]
    if not before_protected:
        return []
    before_privacy = privacy_protection_metadata(before_manifest)
    after_privacy = privacy_protection_metadata(after_manifest)
    return [
        f"privacy protection {key} differs: before={before_privacy.get(key)!r}, after={after_privacy.get(key)!r}"
        for key in _PRIVACY_COMPARISON_KEYS
        if before_privacy.get(key) != after_privacy.get(key)
    ]


def build_privacy_comparison(
    before_manifest: Mapping[str, Any],
    after_manifest: Mapping[str, Any],
) -> dict[str, Any]:
    """Build non-secret privacy metadata for bundle comparison output."""
    before = privacy_protection_metadata(before_manifest)
    after = privacy_protection_metadata(after_manifest)
    return {
        "before": before,
        "after": after,
        "protected": bool(before.get("enabled") or after.get("enabled")),
        "same_policy": before.get("privacy_policy_version") == after.get("privacy_policy_version"),
        "same_profile": before.get("profile_id") == after.get("profile_id"),
        "same_token_format": before.get("token_format_version") == after.get("token_format_version"),
        "same_token_scope": before.get("token_scope") == after.get("token_scope"),
        "same_engagement": before.get("engagement_id") == after.get("engagement_id"),
        "llm_policy": ("llm_disabled_in_v1" if bool(before.get("enabled") or after.get("enabled")) else "not_applicable"),
    }
