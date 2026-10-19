"""Identity-bound tag-attribution classification, keeping data-map keys distinct."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, ClassVar

from unio_collector.privacy.audit.contract import AuditPrivacyContract
from unio_collector.privacy.tagging.fields import FIELDS, MAPS, RESOURCES, SCANNER, SERVICES

if TYPE_CHECKING:
    from unio_collector.privacy.treatment_decision import PrivacyTreatmentDecision


class TaggingPrivacyContract(AuditPrivacyContract):
    """Protect identities, values and prose while preserving existing profile-specific tag keys."""

    scanner_id: ClassVar[str] = SCANNER
    identities: ClassVar = {SCANNER: ("tagging.evidence", "TaggingEvidence", {})}
    fields: ClassVar = FIELDS

    @classmethod
    def _valid(cls, value: object, kind: str, *, nullable: bool) -> bool:
        """Validate only producer-declared nullable values and typed string tag maps."""
        if value is None:
            return nullable
        if kind == "tag_map":
            return isinstance(value, dict) and all(isinstance(key, str) and isinstance(child, str) for key, child in value.items())
        if kind == "resource_type":
            return isinstance(value, str) and value in RESOURCES
        if kind == "service":
            return isinstance(value, str) and value in SERVICES
        if kind == "version":
            return type(value) is int and value in {0, 1}
        return super()._valid(value, kind, nullable=nullable)

    def unknown_paths(self, value: object, member: str, suffix: str = "") -> list[str]:
        """Tag keys are data, with a closed string-value contract rather than field wildcards."""
        if suffix in MAPS:
            return [] if self._valid(value, "tag_map", nullable=True) else [member + self.prefix[1:] + "." + suffix]
        return super().unknown_paths(value, member, suffix)

    def mapping_key_category(self, path: str) -> str | None:
        """Use the established tag-key policy only inside these two declared maps."""
        return "tag_key" if path.removeprefix(self.prefix + ".") in MAPS else None

    def resolve(self, path: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Protect whole arbitrary text and values without matching generated prose."""
        for mapping in MAPS:
            base = self.prefix + "." + mapping + "."
            if path.startswith(base):
                path = base + "0"
                break
        decision = super().resolve(path, profile)
        return replace(decision, treatment="tokenise") if decision is not None and decision.category in {"tag_key", "tag_value"} else decision

    def is_literal(self, suffix: str, value: object) -> bool:
        """Only resource/service categories at their exact owned fields are public metadata."""
        spec = self.fields.get(suffix)
        return spec is not None and spec[0] in {"resource_type", "service", "version"} and self._valid(value, spec[0], nullable=spec[2])
