from __future__ import annotations

# ruff: noqa: D100
from unio_collector.core.base_model import UnioBaseModel


class OrganizationEnvelopeValidationResult(UnioBaseModel):
    """Return structural, checksum, child, and signature validation state."""

    valid: bool
    schema_version: str | None = None
    signed: bool = False
    signature_verified: bool = False
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
