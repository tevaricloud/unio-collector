from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class PrivacyRegistryEntry:
    """Machine-readable privacy registry contract entry."""

    domain: str
    member_pattern: str
    json_path_pattern: str
    value_category: str
    treatment: str
    canonicaliser_id: str | None = None
    canonicaliser_version: str | None = None
    allowed_profiles: tuple[str, ...] = ("standard", "strict", "custom")
    filename_allowed: bool = False
    log_allowed: bool = False
    fallback_allowed: bool = False
    limitations: tuple[str, ...] = ()

    def convert_to_dict(self) -> dict[str, object]:
        """Return JSON-safe registry metadata."""
        return {
            "domain": self.domain,
            "member_pattern": self.member_pattern,
            "json_path_pattern": self.json_path_pattern,
            "value_category": self.value_category,
            "treatment": self.treatment,
            "canonicaliser_id": self.canonicaliser_id,
            "canonicaliser_version": self.canonicaliser_version,
            "allowed_profiles": list(self.allowed_profiles),
            "filename_allowed": self.filename_allowed,
            "log_allowed": self.log_allowed,
            "fallback_allowed": self.fallback_allowed,
            "limitations": list(self.limitations),
        }
