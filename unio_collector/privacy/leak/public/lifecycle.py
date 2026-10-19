"""Exact reproduced lifecycle metadata roles in the known-original scan view."""

from __future__ import annotations

from unio_collector.collector.protocol import UNIO_PROTOCOL
from unio_collector.privacy.leak.public.transport import TransportErrorScanContract
from unio_collector.privacy.producer_fields import producer_category, unknown_producer_paths

KEYS = {
    (member, prefix + "." + field)
    for member, prefix in (
        ("analysis-readiness.json", "$.scanner_evidence_coverage"),
        ("collection-summary.json", "$.strict_analysis_readiness.scanner_evidence_coverage"),
        ("scan-result/report-bundle.json", "$.summary.scanner_evidence_coverage"),
    )
    for field in ("unavailable_scanner_ids", "unknown_payload_ids")
} | {("manifest.json", "$.services_unavailable")}
_LITERALS = {
    "outcome": frozenset({"available", "dependency_unavailable", "service_unavailable"}),
    "limitation_category": frozenset({"evidence_unavailable"}),
    "category": frozenset({"evidence_unavailable"}),
    "error_classification": frozenset({"service_unavailable"}),
}
VALUES = {
    ("collection-summary.json", "$.billing_region_coverage.status"): frozenset({"available", "unavailable"}),
    **{
        (member, prefix + "." + field): _LITERALS[field]
        for member, prefix, fields in (
            ("manifest.json", "$.permission_limitations[]", ("outcome", "limitation_category")),
            ("permissions-summary.json", "$.permission_degradation.degradation_details[]", ("outcome", "category")),
            ("permissions-summary.json", "$.permission_degradation.stable_limitation_details[]", ("outcome", "category")),
            ("permissions/degradation-records.json", "$.records[]", ("outcome", "limitation_category", "error_classification")),
        )
        for field in fields
    },
}


class ProtocolLifecycleScanContract:
    """Normalize finite metadata only at reproduced actual protocol positions."""

    @staticmethod
    def public_key(member: str, path: str, child: object) -> bool:
        """Do not mask list values, malformed containers or unknown lookalike keys."""
        return (member, path) in KEYS and isinstance(child, list) and all(isinstance(value, str) for value in child)

    @staticmethod
    def public_value(member: str, path: str, value: object) -> bool:
        """Arbitrary text, suffixes and unknown fields remain fully visible."""
        return producer_category(member, path) is not None and isinstance(value, str) and value in VALUES.get((member, path), ())

    @staticmethod
    def ledger_view(member: str, path: str, value: dict[str, object], generated_tokens: frozenset[str]) -> dict[str, object]:
        """Require the existing complete local, read-only ledger identity guard."""
        if (member, path) != ("collection-log.jsonl", "$") or unknown_producer_paths(value, member, path):
            return value
        if not TransportErrorScanContract._ledger(value, generated_tokens):  # noqa: SLF001
            return value
        envelope = value.get(UNIO_PROTOCOL.namespace)
        if not isinstance(envelope, dict):
            return value
        copied = dict(envelope)
        for field, literals in (("service_availability_status", {"not_enabled_or_unavailable", "unknown"}), ("error_category", {"service_unavailable"})):
            if isinstance(copied.get(field), str) and copied[field] in literals:
                copied[field] = ""
        return {**value, UNIO_PROTOCOL.namespace: copied}
