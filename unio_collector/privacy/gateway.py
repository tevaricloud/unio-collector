"""Closed actual-producer privacy contract for api-gateway-cost-review."""

from __future__ import annotations

from typing import Any, ClassVar, Self

from unio_collector.collector.protocol import UNIO_PROTOCOL
from unio_collector.privacy.closed_schema import ClosedProducerContract
from unio_collector.scanners.scanner.schema import admit_evidence_schema

FIELDS: dict[str, tuple[str, str, bool]] = {
    "": ("object", "safe_metadata", False),
    "records": ("array", "safe_metadata", False),
    "records[]": ("object", "safe_metadata", False),
    "regions": ("array", "region", False),
    "regions[]": ("string", "region", False),
    "records[].account_id": ("string", "aws_account_id", False),
    "records[].region": ("string", "region", False),
    "records[].rest_api_count": ("count", "safe_metadata", False),
    "records[].http_api_count": ("count", "safe_metadata", False),
    "records[].websocket_api_count": ("count", "safe_metadata", False),
    "records[].private_rest_api_count": ("count", "safe_metadata", False),
    "records[].regional_rest_api_count": ("count", "safe_metadata", False),
    "records[].edge_optimized_rest_api_count": ("count", "safe_metadata", False),
    "records[].stage_count": ("count", "safe_metadata", False),
    "records[].auto_deploy_stage_count": ("count", "safe_metadata", False),
    "records[].cache_enabled_stage_count": ("count", "safe_metadata", False),
    "records[].access_logging_stage_count": ("count", "safe_metadata", False),
    "records[].execution_logging_stage_count": ("count", "safe_metadata", False),
    "records[].detailed_metrics_stage_count": ("count", "safe_metadata", False),
    "records[].data_trace_stage_count": ("count", "safe_metadata", False),
    "records[].xray_tracing_stage_count": ("count", "safe_metadata", False),
    "records[].route_count": ("count", "safe_metadata", False),
    "records[].authorization_configured_route_count": ("count", "safe_metadata", False),
    "records[].default_route_count": ("count", "safe_metadata", False),
    "records[].cors_configured_api_count": ("count", "safe_metadata", False),
    "records[].throttling_configured_stage_count": ("count", "safe_metadata", False),
    "records[].vpc_link_count": ("count", "safe_metadata", False),
    "records[].available_vpc_link_count": ("count", "safe_metadata", False),
    "records[].regional_cost_record_count": ("count", "safe_metadata", False),
    "records[].sample_api_names": ("array", "resource_name", False),
    "records[].sample_api_names[]": ("string", "resource_name", False),
    "records[].sample_route_keys": ("array", "resource_name", False),
    "records[].sample_route_keys[]": ("string", "resource_name", False),
    "records[].sample_stage_names": ("array", "resource_name", False),
    "records[].sample_stage_names[]": ("string", "resource_name", False),
    "records[].sample_vpc_link_names": ("array", "resource_name", False),
    "records[].sample_vpc_link_names[]": ("string", "resource_name", False),
    "records[].service_current_cost": ("money", "cost", True),
    "records[].service_previous_cost": ("money", "cost", True),
    "records[].regional_current_cost": ("money", "cost", True),
    "records[].service_cost_currency": ("string", "cost", True),
    "records[].regional_cost_currency": ("string", "cost", True),
    "records[].permission_errors": ("array", "removed_diagnostic", False),
    "records[].permission_errors[]": ("string", "removed_diagnostic", False),
    "records[].vpc_link_detail_collected": ("boolean", "safe_metadata", False),
    "records[].sample_endpoint_types": ("array", "safe_metadata", False),
    "records[].sample_endpoint_types[]": ("endpoint", "safe_metadata", False),
}


class GatewayPrivacyContract(ClosedProducerContract):
    """Scope exact typed fields to the matching legacy AWS producer."""

    fields: ClassVar[dict[str, tuple[str, str, bool]]] = FIELDS

    @classmethod
    def for_record(cls, record: dict[str, Any]) -> Self | None:
        """Reject conflicting identities before interpreting producer fields."""
        if record.get("scanner_id") != "api-gateway-cost-review":
            return None
        schema = admit_evidence_schema(record)
        if (
            schema is not None
            or record.get("provider_id", "aws") != "aws"
            or (record.get("evidence_module"), record.get("evidence_type"))
            not in {
                (f"{namespace}.scanners.platform.api_gateway.evidence", "ApiGatewayCostReviewEvidence")
                for namespace in UNIO_PROTOCOL.accepted_import_namespaces
            }
        ):
            message = "Inventory privacy contract requires its matching legacy AWS evidence identity."
            raise ValueError(message)
        return cls()

    @classmethod
    def _valid(cls, value: object, kind: str, *, nullable: bool) -> bool:
        """Validate finite metadata before profile-driven omission."""
        if value is None:
            return nullable
        if kind == "endpoint":
            return isinstance(value, str) and value in {"REGIONAL", "EDGE", "PRIVATE"}
        return super()._valid(value, kind, nullable=nullable)
