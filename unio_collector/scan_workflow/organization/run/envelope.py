"""Neutral organization envelope assembly from accepted account outcomes."""

from __future__ import annotations

from typing import TYPE_CHECKING

from unio_collector.collector.organization import (
    ORGANIZATION_ENVELOPE_SCHEMA_VERSION,
    OrganizationEnvelopeAccount,
    OrganizationEnvelopeManifest,
    OrganizationEnvelopeWriter,
)
from unio_collector.scan_workflow.organization.model.coverage import ConsolidatedCoverageSummary

if TYPE_CHECKING:
    from pathlib import Path

    from unio_collector.scan_workflow.organization.model.failure import AccountFailure
    from unio_collector.scan_workflow.organization.run.envelope_context import OrganizationEnvelopeContext


class OrganizationEnvelopeAssembler:
    """Serialize declared purpose, completeness and accepted child-bundle metadata."""

    def write(self, context: OrganizationEnvelopeContext) -> tuple[Path, ConsolidatedCoverageSummary, tuple[AccountFailure, ...]]:
        """Write the existing envelope layout without executing collection or analysis."""
        discovery = context.discovery
        run_id = context.run_id
        fingerprint = context.fingerprint
        output = context.output
        signing_key = context.signing_key
        signing_key_id = context.signing_key_id
        results = context.results
        bundle_results = results.bundle_results
        failures = results.failures
        children = results.children
        audits = results.audits
        cancelled = results.cancelled
        completed = sum(not item.limitations for item in bundle_results.values())
        degraded = sum(bool(item.limitations) for item in bundle_results.values())
        coverage = ConsolidatedCoverageSummary(
            discovered=len(discovery.accounts),
            selected=len(discovery.selection.selected),
            excluded=len(discovery.selection.excluded),
            completed=completed,
            degraded=degraded,
            failed=len(failures),
            cancelled=results.cancelled_count,
        )
        accounts = tuple(
            OrganizationEnvelopeAccount(
                account_reference=reference,
                bundle_path=f"accounts/{reference}/evidence-bundle.zip",
                bundle_sha256=item.bundle_sha256,
                status="degraded" if item.limitations else "completed",
                analysis_state=context.analysis_state,
                bundle_purpose=item.bundle_purpose,
                bundle_schema_version=item.bundle_schema_version,
            )
            for reference, item in sorted(bundle_results.items())
        )
        manifest = OrganizationEnvelopeManifest(
            organization_alias=discovery.organization.alias,
            run_id=run_id,
            bundle_purpose=context.bundle_purpose,
            accounts=accounts,
        )
        envelope = output / "organization-envelope.zip"
        OrganizationEnvelopeWriter().write(
            path=envelope,
            manifest=manifest,
            request_payload={
                "schema_version": ORGANIZATION_ENVELOPE_SCHEMA_VERSION,
                "request_fingerprint": fingerprint,
                "provider_id": "aws",
                "cross_account_assessment": True,
            },
            scope_payload={
                "organization": discovery.organization.model_dump(mode="json"),
                "selected_accounts": [item.model_dump(mode="json") for item in discovery.selection.selected],
                "excluded_accounts": [item.model_dump(mode="json") for item in discovery.selection.excluded],
                "organizational_units": [item.model_dump(mode="json") for item in discovery.organizational_units],
            },
            coverage_payload=coverage.model_dump(mode="json"),
            run_summary_payload={
                "status": "partial" if failures or cancelled or degraded else "completed",
                "failures": [item.model_dump(mode="json") for item in sorted(failures.values(), key=lambda item: item.account_reference)],
                "billing_allocation_status": "not_collected",
            },
            role_audit_records=audits,
            child_bundles=children,
            signing_key=signing_key,
            signing_key_id=signing_key_id,
        )
        return envelope, coverage, tuple(sorted(failures.values(), key=lambda item: item.account_reference))
