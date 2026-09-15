from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.collector.bundle.encoding import load_json_object
from unio_collector.collector.protocol import DEFAULT_PROTOCOL, EvidenceProtocol

if TYPE_CHECKING:
    from zipfile import ZipFile

SCANNER_EVIDENCE_PAYLOAD_FILE = "scan-result/scanner-evidence.json"


class ScannerEvidencePayloadValidator:  # noqa: D101
    def validate(  # noqa: D102
        self,
        archive: ZipFile,
        manifest: dict[str, object],
        errors: list[str],
        *,
        protocol: EvidenceProtocol | None = None,
    ) -> dict[str, object]:
        if SCANNER_EVIDENCE_PAYLOAD_FILE not in archive.namelist():
            return {}
        payload = _read_payload(archive, errors)
        if not payload:
            return {}
        if payload.get("bundle_schema_version") != manifest.get(
            "bundle_schema_version",
        ):
            errors.append(
                "scan-result/scanner-evidence.json bundle_schema_version does not match manifest.json.",
            )
        if protocol is None:
            try:
                protocol = EvidenceProtocol.from_identifier(payload.get("payload_format"), ("scanner-evidence-v1",))
            except ValueError:
                protocol = DEFAULT_PROTOCOL
        expected_format = protocol.identifier("scanner-evidence-v1")
        if payload.get("payload_format") != expected_format:
            errors.append(
                f"scan-result/scanner-evidence.json payload_format must be '{expected_format}'.",
            )
        records = payload.get("scanner_evidence")
        if not isinstance(records, list):
            errors.append(
                "scan-result/scanner-evidence.json scanner_evidence must be a list.",
            )
            return payload
        declared_count = payload.get("scanner_evidence_count")
        if type(declared_count) is not int or declared_count != len(records):
            errors.append(
                "scan-result/scanner-evidence.json scanner_evidence_count does not match scanner_evidence length.",
            )
        for index, record in enumerate(records):
            _validate_record(
                record,
                index,
                errors,
                expected_schema_version=manifest.get("bundle_schema_version"),
            )
        return payload


def _validate_record(
    record: object,
    index: int,
    errors: list[str],
    *,
    expected_schema_version: object,
) -> None:
    if not isinstance(record, dict):
        errors.append(
            f"scan-result/scanner-evidence.json scanner_evidence[{index}] must be an object.",
        )
        return
    errors.extend(
        f"scan-result/scanner-evidence.json scanner_evidence[{index}].{key} must be a non-empty string."
        for key in ("scanner_id", "serialization_status", "evidence_type")
        if not isinstance(record.get(key), str) or not record.get(key)
    )
    if record.get("bundle_schema_version") != expected_schema_version:
        errors.append(
            f"scan-result/scanner-evidence.json scanner_evidence[{index}].bundle_schema_version does not match manifest.json.",
        )
    limitations = record.get("limitations")
    if "payload" not in record:
        errors.append(f"scan-result/scanner-evidence.json scanner_evidence[{index}] is missing payload.")
    if not isinstance(limitations, list):
        errors.append(
            f"scan-result/scanner-evidence.json scanner_evidence[{index}].limitations must be a list.",
        )
    elif any(not isinstance(item, str) for item in limitations):
        errors.append(f"scan-result/scanner-evidence.json scanner_evidence[{index}].limitations must contain strings.")


def _read_payload(
    archive: ZipFile,
    errors: list[str],
) -> dict[str, object]:
    try:
        value = archive.read(SCANNER_EVIDENCE_PAYLOAD_FILE).decode("utf-8")
        payload = load_json_object(value)
    except Exception:  # noqa: BLE001
        errors.append(f"{SCANNER_EVIDENCE_PAYLOAD_FILE} must contain a valid non-empty JSON object.")
        return {}
    if isinstance(payload, dict):
        return payload
    errors.append(f"{SCANNER_EVIDENCE_PAYLOAD_FILE} must contain a JSON object.")
    return {}
