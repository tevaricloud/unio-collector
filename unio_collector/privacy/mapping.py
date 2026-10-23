"""Exact typed-map privacy policy separated from the JSON coordinator."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from unio_collector.privacy.patterns import is_safe_literal
from unio_collector.privacy.registry import FALLBACK_SAFE_STRING_KEYS, FALLBACK_SENSITIVE_KEY_CATEGORIES, FALLBACK_TEXT_KEYS

if TYPE_CHECKING:
    from collections.abc import Callable

    from unio_collector.privacy.closed_schema import ClosedProducerContract
    from unio_collector.privacy.profiles import PrivacyProfile
    from unio_collector.privacy.registry import ClassificationSummary
    from unio_collector.privacy.token.transformer import PrivacyValueTokens


class PrivacyMappingPolicy:
    """Preserve existing region/tag/data-key treatments without widening admission."""

    def __init__(self, profile: PrivacyProfile, summary: ClassificationSummary, values: PrivacyValueTokens, tag_key: Callable[[str], str]) -> None:
        """Bind the current operation's profile, counters and token owner only."""
        self.profile = profile
        self.summary = summary
        self.values = values
        self.tag_key = tag_key

    def transform(
        self, value: dict[str, Any], category: str, path: str, contract: ClosedProducerContract, transform_value: Callable[[str, object], object]
    ) -> dict[str, object]:
        """Apply the same typed-map branch to each original key and value."""
        if category == "region":
            if self.profile.profile_id == "strict":
                self.summary.regions_generalised += len(value)
                self.summary.removed += len(value)
                return {}
            return {region: transform_value(region, status) for region, status in value.items()}
        return {self._key(str(key), category, path, contract): transform_value(str(key), child) for key, child in value.items()}

    def _key(self, key: str, category: str, path: str, contract: ClosedProducerContract) -> str:
        """Keep only explicitly declared fixed keys; protect all other map data keys."""
        if contract.preserves_mapping_key(path, key):
            return key
        return self.tag_key(key) if category == "tag_key" else self.values.tokenise(category, key)

    def tokenise_text(self, value: str, category: str, path: str, contract: ClosedProducerContract | None) -> str:
        """Map complete diagnostic bodies to tokens, retaining only a declared wire label."""
        if category == "tag_key":
            return self.tag_key(value)
        prefix = contract.diagnostic_prefix(path, value) if contract is not None else None
        if prefix is not None:
            return prefix + self.values.sensitive_string(value[len(prefix) :], category)
        return self.values.sensitive_string(value, category)

    def fallback_text(
        self,
        value: str,
        *,
        display_path: str,
        key_lower: str,
        in_tags: bool,
        allow_unknown_fields: bool,
    ) -> str:
        """Apply the existing legacy fallback without changing admission or counters."""
        category = FALLBACK_SENSITIVE_KEY_CATEGORIES.get(key_lower)
        if in_tags:
            self.summary.tag_values_tokenised += 1
            return self.values.tokenise("tag_value", value)
        if category is not None:
            return self.values.sensitive_string(value, category)
        if key_lower in FALLBACK_TEXT_KEYS:
            self.summary.text_values_tokenised += 1
            return self.values.embedded_values(value)
        if key_lower in FALLBACK_SAFE_STRING_KEYS or is_safe_literal(value):
            self.summary.preserved += 1
            return value
        transformed = self.values.embedded_values(value)
        if transformed != value:
            return transformed
        if allow_unknown_fields:
            self.summary.warnings.append(
                f"Preserved unclassified field by custom profile: {display_path}",
            )
            self.summary.preserved += 1
            return value
        self.summary.unclassified.append(display_path)
        return value
