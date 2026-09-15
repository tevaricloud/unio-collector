from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, cast

from unio_collector.collector.bundle.context import CollectorBundleContext
from unio_collector.collector.bundle.minimised_summary import build_minimised_summary
from unio_collector.collector.bundle.payload_writer import EvidencePayloadWriter
from unio_collector.collector.bundle.service_filter import filter_evidence_records
from unio_collector.collector.bundle.source import EvidenceBundleSource
from unio_collector.collector.minimisation import EvidenceMinimisationOptions

if TYPE_CHECKING:
    from pathlib import Path

    from unio_collector.collector.bundle.write_result import BundleWriteResult
    from unio_collector.collector.execution.result import CollectorExecutionResult
    from unio_collector.evidence.collection_store import CollectionEvidenceStore


class CollectorEvidenceBundleWriter:
    """Write a collector-purpose bundle without evaluating findings."""

    def write(
        self,
        *,
        path: Path,
        result: CollectorExecutionResult,
        minimisation: EvidenceMinimisationOptions | None = None,
    ) -> BundleWriteResult:
        """Write the canonical evidence bundle from collection-only output."""
        options = minimisation or EvidenceMinimisationOptions()
        context = CollectorBundleContext(
            generated_at=result.generated_at,
            account_context=result.account_context,
            scan_period=result.scan_period,
            summary={
                **result.collection_summary,
                "bundle_purpose": "collector_evidence",
                "provider": result.provider_id,
            },
        )
        if options.exclude_services or options.no_cost_data:
            context = context.model_copy(
                update={"summary": build_minimised_summary(context.summary, options, removed_count=0, retained_count=0)},
            )
        source = EvidenceBundleSource(
            generated_at=context.generated_at,
            account_context=context.account_context,
            scan_period=context.scan_period,
            summary=context.summary,
            compatibility_payload=context.model_dump(mode="json"),
            finding_count=0,
            evidence_records=filter_evidence_records(cast("CollectionEvidenceStore", result.evidence_store).convert_to_json_records(), options),
        )
        return EvidencePayloadWriter().write(
            path=path,
            bundle=source,
            scan_result=result,
            config=result.config,
            minimisation=options,
            bundle_purpose="collector_evidence",
        )
