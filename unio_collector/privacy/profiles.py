from __future__ import annotations  # noqa: D100

# ruff: noqa: EM101,EM102,S105,TRY003
from dataclasses import dataclass

from unio_collector.privacy.constants import SUPPORTED_PRIVACY_PROFILES


@dataclass(frozen=True)
class PrivacyProfile:
    """Machine-readable privacy profile settings."""

    profile_id: str
    version: str = "2026-03"
    token_scope: str = "engagement"
    preserve_unknown_fields: bool = False
    cost_data_included: bool = True
    region_visibility: str = "preserve"
    topology_detail: str = "tokenised"
    timestamp_precision: str = "day"

    def convert_to_dict(self) -> dict[str, object]:
        """Return profile metadata for protected bundles."""
        return {
            "profile_id": self.profile_id,
            "version": self.version,
            "token_scope": self.token_scope,
            "preserve_unknown_fields": self.preserve_unknown_fields,
            "cost_data_included": self.cost_data_included,
            "region_visibility": self.region_visibility,
            "topology_detail": self.topology_detail,
            "timestamp_precision": self.timestamp_precision,
        }


def load_privacy_profile(
    profile_id: str,
    *,
    token_scope: str | None = None,
    allow_unknown_fields: bool = False,
) -> PrivacyProfile:
    """Return a supported v1 privacy profile."""
    if profile_id not in SUPPORTED_PRIVACY_PROFILES:
        raise ValueError(
            f"Unsupported privacy profile {profile_id!r}; expected one of {SUPPORTED_PRIVACY_PROFILES}.",
        )
    if profile_id == "custom":
        return PrivacyProfile(
            profile_id=profile_id,
            token_scope=token_scope or "engagement",
            preserve_unknown_fields=allow_unknown_fields,
        )
    if allow_unknown_fields:
        raise ValueError("Only the custom privacy profile may preserve unknown fields.")
    if profile_id == "strict":
        return PrivacyProfile(
            profile_id=profile_id,
            token_scope=token_scope or "engagement",
            cost_data_included=False,
            region_visibility="generalised",
            topology_detail="reduced",
            timestamp_precision="month",
        )
    return PrivacyProfile(
        profile_id="standard",
        token_scope=token_scope or "engagement",
    )
