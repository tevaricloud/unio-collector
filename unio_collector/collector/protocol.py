"""Coherent evidence protocol families, separate from Python package names."""

from __future__ import annotations

# ruff: noqa: EM101,TRY003
from dataclasses import dataclass


@dataclass(frozen=True)
class EvidenceProtocol:
    """Select persistent identifiers and crypto contexts as one contract."""

    namespace: str

    @property
    def import_namespace(self) -> str:
        """Identify typed evidence imports independently of protocol labels."""
        return __name__.split(".", 1)[0] if self == DEFAULT_PROTOCOL else "unio_collector"

    def identifier(self, suffix: str) -> str:
        """Return a wire identifier within this selected family."""
        return f"{self.namespace}-{suffix}"

    def privacy_context(self, purpose: str) -> bytes:
        """Return the family-specific HKDF context, never an import path."""
        return f"{self.namespace}/privacy/v1/{purpose}".encode()

    def report_type(self, version: str) -> str:
        """Identify the signed return package independently of imports."""
        return f"{self.namespace}_protected_report_package_json_{version}"

    @classmethod
    def from_report_type(cls, value: object, version: str) -> EvidenceProtocol:
        """Select one explicit package family before authentication."""
        for protocol in (DEFAULT_PROTOCOL, UNIO_PROTOCOL):
            if value == protocol.report_type(version):
                return protocol
        raise ValueError("Unsupported protected report package type.")

    @classmethod
    def from_identifier(cls, value: object, suffixes: tuple[str, ...]) -> EvidenceProtocol:
        """Reject unknown markers; never try a second family after selection."""
        for protocol in (DEFAULT_PROTOCOL, UNIO_PROTOCOL):
            if value in tuple(protocol.identifier(suffix) for suffix in suffixes):
                return protocol
        raise ValueError("Unsupported evidence protocol family identifier.")

    def validate_privacy(self, metadata: dict[str, object], *, vault: bool = False) -> None:
        """Reject present token/source markers from another family."""
        token_format = metadata.get("token_format_version")
        if (token_format is not None or "token_format_version" in metadata) and token_format != self.identifier("token-v1"):
            raise ValueError("Evidence protocol family token format mismatch.")
        for key in ("bundle_id_scheme", "source_bundle_id_scheme"):
            if key in metadata and metadata[key] not in (self.identifier("source-bundle-content-sha256-v1"), "legacy-path-uuid5-v1"):
                raise ValueError("Evidence protocol family source identity mismatch.")
        if vault and metadata.get("format") not in (self.identifier("vault-v1"), self.identifier("vault-v2")):
            raise ValueError("Evidence protocol family vault format mismatch.")


DEFAULT_PROTOCOL = EvidenceProtocol("unio")
UNIO_PROTOCOL = EvidenceProtocol("unio")
