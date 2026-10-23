"""Identity-bound finite governance privacy admission without provider imports."""

from __future__ import annotations

from typing import ClassVar

from unio_collector.privacy.audit.contract import AuditPrivacyContract
from unio_collector.privacy.audit.governance.fields import SCANNERS, VOCABULARIES


class GovernancePrivacyContract(AuditPrivacyContract):
    """Protect identities and prose; admit only reviewed enum/count/container shapes."""

    identities: ClassVar = SCANNERS

    @classmethod
    def _valid(cls, value: object, kind: str, *, nullable: bool) -> bool:
        """Require finite enum values even when strict would omit another field."""
        if value is None:
            return nullable
        if kind in VOCABULARIES:
            return isinstance(value, str) and value in VOCABULARIES[kind]
        return super()._valid(value, kind, nullable=nullable)

    def is_literal(self, suffix: str, value: str) -> bool:
        """Mark only the actual admitted enum position, never an equal resource ID."""
        spec = self.fields.get(suffix)
        return spec is not None and spec[0] in VOCABULARIES and value in VOCABULARIES[spec[0]]
