from __future__ import annotations  # noqa: D100

from fnmatch import fnmatchcase
from typing import TYPE_CHECKING

from unio_collector.privacy.registry import PATH_REGISTRY
from unio_collector.privacy.treatment_decision import PrivacyTreatmentDecision

if TYPE_CHECKING:
    from unio_collector.privacy.registry_entry import PrivacyRegistryEntry


class PrivacyRegistryResolver:
    """Resolve privacy treatments from the path/treatment registry."""

    def resolve(
        self,
        *,
        domain: str,
        member_path: str,
        json_path: str,
        key: str | None,
        profile_id: str,
    ) -> PrivacyTreatmentDecision:
        """Return the registry decision for one member/path/key."""
        path_entry, path_source = self._resolve_path_entry(
            domain=domain,
            member_path=member_path,
            profile_id=profile_id,
        )
        if path_entry is None:
            return self._unsupported(
                reason=f"No registry entry covers {domain}:{member_path}.",
            )

        suffix_entry = self._resolve_json_suffix_entry(
            domain=domain,
            member_path=member_path,
            json_path=json_path,
            key=key,
            profile_id=profile_id,
        )
        if suffix_entry is not None:
            return PrivacyTreatmentDecision(
                treatment=suffix_entry.treatment,
                category=suffix_entry.value_category,
                canonicaliser_id=suffix_entry.canonicaliser_id,
                canonicaliser_version=suffix_entry.canonicaliser_version,
                fallback_allowed=suffix_entry.fallback_allowed,
                decision_source="json_path_suffix",
                reason=f"Matched registry JSON suffix {suffix_entry.json_path_pattern}.",
            )

        if json_path == "$":
            return PrivacyTreatmentDecision(
                treatment=path_entry.treatment,
                category=path_entry.value_category,
                canonicaliser_id=path_entry.canonicaliser_id,
                canonicaliser_version=path_entry.canonicaliser_version,
                fallback_allowed=False,
                decision_source=path_source,
                reason=f"Matched registry path {path_entry.member_pattern}.",
            )

        if path_entry.fallback_allowed:
            return PrivacyTreatmentDecision(
                treatment=path_entry.treatment,
                category=path_entry.value_category,
                canonicaliser_id=path_entry.canonicaliser_id,
                canonicaliser_version=path_entry.canonicaliser_version,
                fallback_allowed=True,
                decision_source="fallback_allowed",
                reason=f"Matched fallback-enabled registry path {path_entry.member_pattern}.",
            )

        return self._unsupported(
            reason=f"No field treatment covers {domain}:{member_path}:{json_path}.",
        )

    def _resolve_path_entry(
        self,
        *,
        domain: str,
        member_path: str,
        profile_id: str,
    ) -> tuple[PrivacyRegistryEntry | None, str]:
        exact_entries = [
            entry
            for entry in PATH_REGISTRY
            if entry.domain == domain and entry.member_pattern == member_path and entry.json_path_pattern == "$..*" and profile_id in entry.allowed_profiles
        ]
        if exact_entries:
            return exact_entries[0], "exact_path"
        wildcard_entries = [
            entry
            for entry in PATH_REGISTRY
            if entry.domain == domain
            and "*" in entry.member_pattern
            and fnmatchcase(member_path, entry.member_pattern)
            and entry.json_path_pattern == "$..*"
            and profile_id in entry.allowed_profiles
        ]
        if wildcard_entries:
            return wildcard_entries[0], "wildcard_path"
        return None, "unsupported"

    def _resolve_json_suffix_entry(
        self,
        *,
        domain: str,
        member_path: str,
        json_path: str,
        key: str | None,
        profile_id: str,
    ) -> PrivacyRegistryEntry | None:
        for entry in PATH_REGISTRY:
            if entry.domain != domain or profile_id not in entry.allowed_profiles:
                continue
            if not self._member_matches(entry.member_pattern, member_path):
                continue
            if not self._json_suffix_matches(
                pattern=entry.json_path_pattern,
                json_path=json_path,
                key=key,
            ):
                continue
            return entry
        return None

    def _member_matches(self, pattern: str, member_path: str) -> bool:
        return pattern in {"*", member_path} or fnmatchcase(member_path, pattern)

    def _json_suffix_matches(
        self,
        *,
        pattern: str,
        json_path: str,
        key: str | None,
    ) -> bool:
        if not pattern.startswith("$..") or pattern == "$..*":
            return False
        suffix = pattern[3:]
        if suffix.lower() in {"checksums", "tags"} and f".{suffix.lower()}." in json_path.lower():
            return True
        if key is not None and key.lower() == suffix.lower():
            return True
        return json_path.lower().endswith(f".{suffix.lower()}")

    def _unsupported(self, *, reason: str) -> PrivacyTreatmentDecision:
        return PrivacyTreatmentDecision(
            treatment="unsupported",
            category=None,
            canonicaliser_id=None,
            canonicaliser_version=None,
            fallback_allowed=False,
            decision_source="unsupported",
            reason=reason,
        )
