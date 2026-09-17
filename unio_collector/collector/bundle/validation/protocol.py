"""Choose the bundle family once and reject contradictory protocol markers."""

from __future__ import annotations

# ruff: noqa: EM101,TRY003,TRY301
from typing import TYPE_CHECKING

from unio_collector.collector.bundle.encoding import load_json_object
from unio_collector.collector.protocol import DEFAULT_PROTOCOL, UNIO_PROTOCOL, EvidenceProtocol

if TYPE_CHECKING:
    from zipfile import ZipFile


class BundleProtocolValidator:
    """Admit coherent legacy or Unio metadata before semantic validation."""

    def validate(self, archive: ZipFile, manifest: dict[str, object], errors: list[str]) -> EvidenceProtocol | None:
        """Resolve the schema discriminator and cross-check all wire markers."""
        schema = self._read(archive, "bundle-schema.json", errors)
        try:
            protocol = DEFAULT_PROTOCOL if "format" not in schema else EvidenceProtocol.from_identifier(schema["format"], ("result-evidence-bundle",))
            privacy = manifest.get("privacy_protection")
            if isinstance(privacy, dict):
                protocol.validate_privacy(privacy)
            schema_privacy = schema.get("privacy_protection")
            if isinstance(schema_privacy, dict) and schema_privacy.get("format") != protocol.identifier("protected-evidence-bundle"):
                raise ValueError("Evidence protocol family protected format mismatch.")
            scanner = self._read(archive, "scan-result/scanner-evidence.json", errors)
            if scanner and scanner.get("payload_format") != protocol.identifier("scanner-evidence-v1"):
                raise ValueError("Evidence protocol family scanner discriminator mismatch.")
            records = scanner.get("scanner_evidence")
            if isinstance(records, list):
                for record in records:
                    if isinstance(record, dict):
                        self._validate_module(record.get("evidence_module"), protocol)
            for name in ("privacy/protection-policy.json", "privacy/preview-summary.json", "privacy/token-metadata.json"):
                protocol.validate_privacy(self._read(archive, name, errors))
            self._validate_ledger(archive, protocol)
        except ValueError as exc:
            errors.append(str(exc))
            return None
        return protocol

    def _validate_module(self, value: object, protocol: EvidenceProtocol) -> None:
        if not isinstance(value, str):
            return
        for other in (DEFAULT_PROTOCOL, UNIO_PROTOCOL):
            if other != protocol and (value == other.import_namespace or value.startswith(f"{other.import_namespace}.")):
                raise ValueError("Evidence protocol family typed module mismatch.")

    def _validate_ledger(self, archive: ZipFile, protocol: EvidenceProtocol) -> None:
        if "collection-log.jsonl" not in archive.namelist():
            return
        for line in archive.read("collection-log.jsonl").decode("utf-8").splitlines():
            if not line.strip():
                continue
            record = load_json_object(line)
            if "eventVersion" in record and record["eventVersion"] != protocol.identifier("1"):
                raise ValueError("Evidence protocol family ledger event version mismatch.")
            for other in (DEFAULT_PROTOCOL, UNIO_PROTOCOL):
                if other != protocol and other.namespace in record:
                    raise ValueError("Evidence protocol family ledger metadata mismatch.")

    def _read(self, archive: ZipFile, name: str, errors: list[str]) -> dict[str, object]:
        if name not in archive.namelist():
            return {}
        try:
            return load_json_object(archive.read(name).decode("utf-8"))
        except (ValueError, UnicodeError):
            errors.append(f"Invalid protocol metadata in {name}.")
            return {}
