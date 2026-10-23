"""Typed flow primitives, tag data maps and narrow public metadata roles."""

from __future__ import annotations

from dataclasses import replace
from ipaddress import ip_address, ip_network
from math import isfinite
from typing import TYPE_CHECKING

from unio_collector.privacy.audit.contract import AuditPrivacyContract
from unio_collector.privacy.flow.fields import FIELDS
from unio_collector.privacy.flow.scan import FlowScanAdmission
from unio_collector.privacy.flow.vocabulary import VOCABULARIES

TAG_MAPS = frozenset(path for path, spec in FIELDS.items() if spec[0] == "tag_map")
PAIR_SIZE = 2
IPV4_VERSION = 4


if TYPE_CHECKING:
    from unio_collector.privacy.treatment_decision import PrivacyTreatmentDecision


class FlowPrivacyBase(AuditPrivacyContract):
    """Only independently declared types and fixed producer categories preserve values."""

    @classmethod
    def _valid(cls, value: object, kind: str, *, nullable: bool) -> bool:
        """Reject malformed/null/unknown controls before strict transformations omit anything."""
        if value is None:
            return nullable
        if kind in VOCABULARIES:
            return isinstance(value, str) and value in VOCABULARIES[kind]
        if kind == "pair":
            return isinstance(value, list) and len(value) == PAIR_SIZE and all(isinstance(child, str) for child in value)
        if kind == "grouping":
            return value == ["srcaddr", "dstaddr", "action"]
        if kind == "positive_count":
            return type(value) is int and value > 0
        if kind == "positive_number":
            return isinstance(value, int | float) and not isinstance(value, bool) and isfinite(value) and value > 0
        if kind == "tag_map":
            return isinstance(value, dict) and all(isinstance(key, str) and isinstance(child, str) for key, child in value.items())
        return super()._valid(value, kind, nullable=nullable)

    def unknown_paths(self, value: object, member: str, suffix: str = "") -> list[str]:
        """Keep data tag keys from widening the surrounding structural schema."""
        if suffix in TAG_MAPS:
            spec = self.fields.get(suffix)
            return [] if spec is not None and self._valid(value, "tag_map", nullable=spec[2]) else [member + self.prefix[1:] + "." + suffix]
        return super().unknown_paths(value, member, suffix)

    def mapping_key_category(self, path: str) -> str | None:
        """Retain the established profile-specific tag-key policy at exact typed maps."""
        return "tag_key" if path.removeprefix(self.prefix + ".") in TAG_MAPS else None

    def resolve(self, path: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Protect entire identifiers, arbitrary text and tag values in both profiles."""
        for mapping in TAG_MAPS:
            base = self.prefix + "." + mapping + "."
            if path.startswith(base):
                path = base + "0"
                break
        decision = super().resolve(path, profile)
        return (
            replace(decision, treatment="tokenise") if decision is not None and decision.category in {"network_identity", "tag_key", "tag_value"} else decision
        )

    def resolve_string(self, path: str, value: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Keep IP/CIDR semantics and finite control roles distinct from customer text."""
        decision = self.resolve(path, profile)
        if decision is None:
            return None
        suffix = path.removeprefix(self.prefix + ".")
        if self.is_literal(suffix, value):
            return replace(decision, treatment="preserve", category="safe_metadata")
        if decision.category == "network_identity":
            try:
                parsed = ip_network(value, strict=False) if "/" in value else ip_address(value)
            except ValueError:
                category = "resource_id"
            else:
                category = "cidr" if "/" in value else "ipv4" if parsed.version == IPV4_VERSION else "ipv6"
            return replace(decision, category=category)
        return decision

    def is_literal(self, suffix: str, value: object) -> bool:
        """Finite controls and typed operational counts never exempt arbitrary positions."""
        spec = self.fields.get(suffix)
        if spec is None:
            return False
        if spec[0] in VOCABULARIES:
            return isinstance(value, str) and value in VOCABULARIES[spec[0]]
        if spec[1] == "summary_count":
            return type(value) is int and self._valid(value, spec[0], nullable=False)
        return suffix.endswith(".destination") and spec[1] == "network_identity" and isinstance(value, str) and value in {"0.0.0.0/0", "::/0"}

    def admitted_scan_container(self, value: object, suffix: str) -> bool:
        """Recognize only supported strict output in a scan copy; raw preflight is unchanged."""
        return not self.unknown_paths(FlowScanAdmission.view(self, value, suffix), "", suffix)
