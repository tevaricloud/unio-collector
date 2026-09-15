from __future__ import annotations  # noqa: D100

from typing import Any

from unio_collector.evidence.permission.planning import summarize_degradation_records
from unio_collector.evidence.permission.summary_builder import PermissionSummaryBuilder


class PermissionExportBuilder:  # noqa: D101
    def build(  # noqa: D102
        self,
        *,
        bundle: Any,  # noqa: ANN401
        config: Any,  # noqa: ANN401
        scan_result: Any,  # noqa: ANN401
        degradation_records: tuple[Any, ...] = (),
    ) -> dict[str, Any]:
        summary = PermissionSummaryBuilder().build(
            generated_at=bundle.generated_at,
            profile_name=getattr(config, "profile", None),
            mode=getattr(config, "mode", "read-only"),
            caller_identity=bundle.account_context,
            scanner_results=scan_result.scanner_results,
            ledger=scan_result.ledger,
        )
        payload = summary.convert_to_dict()
        payload["permission_degradation"] = summarize_degradation_records(
            degradation_records,
        )
        return payload
