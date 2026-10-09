"""Synthetic complete collection summaries from the canonical offline writer."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

from unio_collector.collector.bundle.payload_writer import EvidencePayloadWriter
from unio_collector.collector.bundle.source import EvidenceBundleSource
from unio_collector.collector.minimisation import EvidenceMinimisationOptions
from unio_collector.evidence.permission.planning.summary_stats import LIMITATION_CATEGORY_BY_OUTCOME

SECONDARY_CLASSIFICATIONS = (
    "expected_absence",
    "service_unavailable",
    "permission_denied",
    "throttling",
    "unsupported_operation",
    "unsupported_region",
    "failure",
    "access_denied_policy_source_unknown",
    "chargeable_api_disabled",
    "interrupted",
    "partial_collection",
    "unknown",
    "legacy_limitation",
    "completed",
    "completed_with_warnings",
    "disabled",
    "failed",
    "skipped",
    "unavailable",
)


def collection_summary_shapes(provenance: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Invoke actual summary and limitation builders; no sessions or collectors."""
    records = (
        tuple(
            {
                "outcome": outcome,
                "error_classification": classification,
                "api_action": "kms:DescribeKey",
                "account_id": "123456789012",
                "region": "us-east-1",
                "record_id": "synthetic-record",
                "resource_id": "synthetic-resource",
                "scanner_id": "synthetic-scanner",
                "client_explanation": "Synthetic limitation for 123456789012",
                "iam_action_requirement": "conditional" if index % 2 else "required",
            }
            for index, classification in enumerate(SECONDARY_CLASSIFICATIONS)
            for outcome in (tuple(LIMITATION_CATEGORY_BY_OUTCOME)[index % len(LIMITATION_CATEGORY_BY_OUTCOME)],)
        )
        + tuple(
            {"outcome": "denied", "error_classification": "permission_denied", "iam_action_requirement": requirement}
            for requirement in ("required", "conditional")
        )
        + ({"outcome": "available", "error_classification": "none", "api_action": "ec2:DescribeInstances"},)
    )
    return {
        name: _summary(provenance, selected, status)
        for name, selected, status in (
            ("success", (), "completed"),
            ("populated", records, "completed_with_warnings"),
            ("denied", tuple(record for record in records if record["outcome"] == "denied"), "permission_denied"),
            ("partial", tuple(record for record in records if record["outcome"] == "partial"), "completed_with_warnings"),
            ("unavailable", tuple(record for record in records if record["outcome"] == "service_unavailable"), "unavailable"),
            ("unsupported", tuple(record for record in records if record["outcome"] == "unsupported_operation"), "unavailable"),
            ("degraded", tuple(record for record in records if record["outcome"] == "interrupted"), "failed"),
        )
    }


def _summary(provenance: dict[str, Any], records: tuple[dict[str, Any], ...], status: str) -> dict[str, Any]:
    billing = {**provenance["billing_region_coverage"], "region_scope_derivation": provenance["billing_region_scope_derivation"]}
    source = EvidenceBundleSource(
        datetime(2026, 8, 31, tzinfo=UTC),
        {"account_id": "123456789012"},
        None,
        {
            "billing_region_coverage": billing,
            "billing_region_scope_derivation": provenance["billing_region_scope_derivation"],
            "region_scope": {"limitations": ["Synthetic region exclusion for 123456789012"]},
        },
        {},
        0,
        [],
    )
    result = SimpleNamespace(evidence_store=SimpleNamespace(get_records=list), ledger=SimpleNamespace(records=[]))
    return EvidencePayloadWriter()._build_collection_summary(  # noqa: SLF001
        bundle=source,
        scan_result=result,
        scanner_results=[{"status": status}],
        minimisation=EvidenceMinimisationOptions(redact_before_export=True, minimise_export="standard", exclude_services=("s3",), no_cost_data=True),
        scanner_boundary_summary={},
        strict_analysis_readiness={},
        degradation_records=records,
    )
