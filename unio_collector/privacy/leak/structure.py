"""Separate fixed reviewed producer field names from potentially private content."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from unio_collector.privacy.leak.public.metadata import is_public_payload_literal, mask_network_identity, mask_network_references, mask_pricing_counter
from unio_collector.privacy.leak.public.paths import PROTOCOL_MEMBERS, mask_protocol_references
from unio_collector.privacy.leak.public.service import admitted_service_record
from unio_collector.privacy.selection import select_producer_contract
from unio_collector.privacy.service.coverage import ServiceCoveragePrivacyContract

if TYPE_CHECKING:
    from unio_collector.privacy.closed_schema import ClosedProducerContract


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            message = "Duplicate JSON key cannot be normalized for leak scanning."
            raise ValueError(message)
        result[key] = value
    return result


def _mask_fixed_keys(value: Any, contract: ClosedProducerContract, suffix: str = "") -> Any:  # noqa: ANN401
    if suffix == "records[]" and isinstance(contract, ServiceCoveragePrivacyContract) and not admitted_service_record(value, contract):
        return value
    if suffix == "topology[].resources[]" and contract.unknown_paths(value, "", suffix):
        return value
    if is_public_payload_literal(contract, suffix, value):
        return ""
    fields = contract.fields
    spec = fields.get(suffix)
    if spec is None:
        return value
    if isinstance(value, list) and spec[0] == "array":
        return [_mask_fixed_keys(child, contract, suffix + "[]") for child in value]
    if isinstance(value, dict) and spec[0] == "object":
        result = []
        for key, child in value.items():
            path = suffix + ("." if suffix else "") + key
            declared = not any(character in key for character in ".[]") and path in fields
            result.append(["" if declared else key, _mask_fixed_keys(child, contract, path) if declared else child])
        return result
    return value


def _structured_scan_content(path: str, content: str) -> str:
    """Mask declared keys and narrowly enumerated public literals, never customer content.

    This view is solely for known-original substring matching. The unchanged raw
    content still receives credential, account, ARN, IP and private-key scans.
    Dynamic tag keys, unknown paths, unknown identities and malformed JSON remain
    scanned. No output archive bytes or privacy classification decisions change.
    """
    if path not in {
        "scan-result/scanner-evidence.json",
        "scan-result/scanner-results.json",
        "analysis-readiness.json",
        "collection-summary.json",
        "scan-result/pricing-context.json",
        *PROTOCOL_MEMBERS,
    }:
        return content
    try:
        document = json.loads(content, object_pairs_hook=_unique_object)
        if not isinstance(document, dict):
            return content
        if path == "scan-result/pricing-context.json":
            return json.dumps(mask_pricing_counter(document), ensure_ascii=False)
        if path in PROTOCOL_MEMBERS:
            mask_protocol_references(path, document)
            return json.dumps(document, ensure_ascii=False)
        if path != "scan-result/scanner-evidence.json":
            mask_network_references(path, document)
            return json.dumps(document, ensure_ascii=False)
        return _scanner_scan_content(document, content)
    except (ValueError, TypeError, RecursionError):
        return content


def json_syntax_scan_content(path: str, content: str) -> str:
    """Exclude boolean/null syntax, retaining every string, key and numeric value.

    A customer name such as "true" must not collide with a JSON boolean. String
    values and dynamic keys remain visible, including decoded Unicode escapes.
    Malformed or duplicate-key input falls back to its complete original text.
    """

    def replace_syntax(value: Any) -> Any:  # noqa: ANN401
        if value is None or isinstance(value, bool):
            return ""
        if isinstance(value, dict):
            return {key: replace_syntax(child) for key, child in value.items()}
        if isinstance(value, list):
            return [replace_syntax(child) for child in value]
        return value

    if not path.endswith((".json", ".jsonl")):
        return content
    try:
        documents = content.splitlines() if path.endswith(".jsonl") else [content]
        return "\n".join(
            json.dumps(replace_syntax(json.loads(line, object_pairs_hook=_unique_object)), ensure_ascii=False) for line in documents if line.strip()
        )
    except (ValueError, TypeError, RecursionError):
        return content


def known_value_scan_content(path: str, content: str) -> str:
    """Return the structural view, retaining unknown members and malformed input."""
    return _structured_scan_content(path, content)


def _scanner_scan_content(document: dict[str, Any], content: str) -> str:
    """Mask admitted scanner rows while preserving malformed envelopes verbatim."""
    if not isinstance(document.get("scanner_evidence"), list):
        return content
    for row in document["scanner_evidence"]:
        if not isinstance(row, dict):
            return content
        contract = select_producer_contract(row)
        if contract is not None and "payload" in row:
            mask_network_identity(row, contract)
            row["payload"] = _mask_fixed_keys(row["payload"], contract)
    return json.dumps(document, ensure_ascii=False)
