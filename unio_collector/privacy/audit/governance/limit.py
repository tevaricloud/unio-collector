"""Closed summary-mode limitation callbacks from the Config and WAF wrappers."""

from __future__ import annotations

from typing import Any, ClassVar, Self

from unio_collector.privacy.audit.notes import AuditNoteContract
from unio_collector.privacy.closed_schema import ClosedProducerContract
from unio_collector.privacy.s3.fields import Spec, fields

LITERALS = {
    "note_type": {"configuration_limit"},
    "scope_area": {"config_rule_metadata", "waf_web_acl_associations"},
    "configured_value": {"summary"},
    "config_key": {"config-cost-governance-review.rule_detail_mode", "waf-cost-governance-review.association_detail_mode"},
    "result_scope": {"current_scan"},
}
KEY_SCOPES = {
    "config-cost-governance-review.rule_detail_mode": "config_rule_metadata",
    "waf-cost-governance-review.association_detail_mode": "waf_web_acl_associations",
}


class GovernanceLimitContract(AuditNoteContract):
    """Protect explanatory prose while retaining only the exact selected option note."""

    fields: ClassVar[dict[str, Spec]] = {
        "": ("object", "safe_metadata", False),
        **fields("note_type scope_area configured_value config_key result_scope", "note_literal"),
        **fields("summary impact", "string", "free_text"),
    }

    @classmethod
    def for_note(cls, value: dict[str, Any]) -> Self | None:
        """Recognize two exact producer keys; unknown note families are not admitted."""
        key = value.get("config_key")
        if isinstance(key, str) and key in KEY_SCOPES:
            return cls(key)
        scope = value.get("scope_area")
        for expected_key, expected_scope in KEY_SCOPES.items():
            if scope == expected_scope:
                return cls(expected_key)
        return None

    def unknown_paths(self, value: Any, member: str, suffix: str = "") -> list[str]:  # noqa: ANN401
        """Require exact literal values and the matching scanner's option/scope pair."""
        failures = ClosedProducerContract.unknown_paths(self, value, member, suffix)
        if suffix in LITERALS and (not isinstance(value, str) or value not in LITERALS[suffix]):
            failures.append(member + self.prefix[1:] + "." + suffix)
        if suffix == "scope_area" and value != KEY_SCOPES[self.scanner]:
            failures.append(member + self.prefix[1:] + ".scope_area")
        return failures

    def is_literal(self, suffix: str, value: str) -> bool:
        """Known-original scanning masks only fixed metadata of this admitted note."""
        return suffix in LITERALS and value in LITERALS[suffix]
