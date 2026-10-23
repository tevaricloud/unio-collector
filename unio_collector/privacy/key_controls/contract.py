"""Closed identity and finite vocabulary admission for key/control producers."""

from __future__ import annotations

from typing import ClassVar

from unio_collector.privacy.audit.contract import AuditPrivacyContract
from unio_collector.privacy.key_controls.fields import SCANNERS, VOCABULARIES


class KeyControlPrivacyContract(AuditPrivacyContract):
    """Protect customer strings without admitting arbitrary provider enum values."""

    identities: ClassVar = SCANNERS

    @classmethod
    def _valid(cls, value: object, kind: str, *, nullable: bool) -> bool:
        if value is None:
            return nullable
        if kind in VOCABULARIES:
            return isinstance(value, str) and value in VOCABULARIES[kind]
        return super()._valid(value, kind, nullable=nullable)

    def is_literal(self, suffix: str, value: str) -> bool:
        """Distinguish only a declared finite metadata position from customer text."""
        spec = self.fields.get(suffix)
        return spec is not None and spec[0] in VOCABULARIES and value in VOCABULARIES[spec[0]]
