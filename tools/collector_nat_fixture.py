"""Actual NAT inventory collection and admission with synthetic provider responses."""

from __future__ import annotations

import json
from dataclasses import asdict, replace
from datetime import UTC, date, datetime
from types import SimpleNamespace
from typing import Any

from botocore.exceptions import ClientError

from tools.collector_balancer_fixture import SyntheticBalancerSession
from tools.collector_scanner_fixture import add_scanner_producer_payload
from unio_collector.aws.audit.context import AwsAuditContext
from unio_collector.aws.network.inventory import NetworkInventoryCollector
from unio_collector.aws.network.metrics import NetworkMetricCollector
from unio_collector.core.scan.period_resolver import ScanPeriodResolver
from unio_collector.scan_workflow.evidence.network import NetworkEvidenceMixin
from unio_collector.scanners.network.nat_gateway.inventory.collector import NatGatewayInventoryCollector
from unio_collector.scanners.scanner.context import ScannerContext
from unio_collector.scanners.scanner.evidence_serializer import build_scanner_evidence_payload

SCANNER = "nat-gateway-inventory"
VARIANTS = (
    "success",
    "optional",
    "empty",
    "private",
    "pending",
    "failed",
    "deleting",
    "deleted",
    "missing_id",
    "legacy_metrics",
    "legacy_partial",
    "legacy_unavailable",
    "legacy_empty",
)
REJECTED_VARIANTS = ("denied", "unsupported", "unavailable", "failure", "partial", "opt_in", "malformed", "cycle")


class SyntheticNatSession(SyntheticBalancerSession):
    """Never create an SDK session and reject unexpected endpoint access."""

    def create_client(self, service_name: str, *, region_name: str | None, audit_context: AwsAuditContext) -> SyntheticNatSession:
        """Serve the two finite read-only fixture endpoints."""
        del audit_context
        if service_name not in {"ec2", "cloudwatch"} or region_name != "eu-west-2":
            message = "Unexpected synthetic NAT endpoint."
            raise ValueError(message)
        return self

    def describe_nat_gateways(self, **kwargs: object) -> dict[str, Any]:
        """Exercise actual pagination, finite states, nullable fields and admission."""
        code = {
            "denied": "UnauthorizedOperation",
            "unsupported": "UnsupportedOperation",
            "unavailable": "ServiceUnavailable",
            "failure": "InternalFailure",
            "opt_in": "OptInRequired",
        }.get(self.variant)
        if self.variant == "partial" and kwargs.get("NextToken"):
            code = "ThrottlingException"
        if code:
            raise ClientError({"Error": {"Code": code, "Message": "Synthetic unavailable endpoint"}}, "DescribeNatGateways")
        row: dict[str, Any] = {
            "NatGatewayId": "nat-00000000000000000",
            "State": "available",
            "SubnetId": "subnet-00000000000000000",
            "VpcId": "vpc-00000000000000000",
            "ConnectivityType": "public",
            "CreateTime": datetime(2026, 9, 1, tzinfo=UTC),
            "Tags": [{"Key": "Name", "Value": "synthetic-customer-gateway"}],
        }
        if self.variant == "optional":
            row = {"NatGatewayId": "nat-00000000000000000"}
        if self.variant == "missing_id":
            row.pop("NatGatewayId")
        if self.variant == "private":
            row["ConnectivityType"] = "private"
        if self.variant in {"pending", "failed", "deleting", "deleted"}:
            row["State"] = self.variant
        if self.variant == "malformed":
            return {"NatGateways": [None]}
        return {"NatGateways": [] if self.variant == "empty" else [row], **({"NextToken": "synthetic-next"} if self.variant in {"partial", "cycle"} else {})}


def nat_producer_case(variant: str = "success") -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Invoke real cached-admission logic as well as wrapper, gateway and producer."""
    if variant not in (*VARIANTS, *REJECTED_VARIANTS):
        message = "Unknown synthetic NAT variant."
        raise ValueError(message)
    session = SyntheticNatSession(
        {"legacy_partial": "metrics_partial", "legacy_unavailable": "metrics_failed", "legacy_empty": "metrics_empty"}.get(variant, variant)
    )
    definition: Any = SimpleNamespace(scanner_id=SCANNER)
    collector = NetworkInventoryCollector(
        session,
        account_id="123456789012",
        audit_context=AwsAuditContext(scanner_id=SCANNER, collector="NetworkInventoryCollector", allowed_api_calls=()),
        selected_regions=["eu-west-2"],
    )
    runtime: Any = SimpleNamespace(
        runner=SimpleNamespace(
            runtime_state=SimpleNamespace(
                account_id="123456789012",
                cache=SimpleNamespace(get_or_load_with_status=lambda _ns, _key, load, **_kwargs: SimpleNamespace(status="loaded", value=load())),
            )
        ),
        ensure_can_start_evidence_collection=lambda *_args, **_kwargs: None,
        get_cached_network_regions=lambda _d: ["eu-west-2"],
        create_network_collector=lambda _d, **_kwargs: collector,
        build_network_cache_keys=lambda: NetworkEvidenceMixin.build_network_cache_keys(runtime),
        build_network_labels=lambda: NetworkEvidenceMixin.build_network_labels(runtime),
        build_cache_access_policy=lambda **_kwargs: None,
        add_cached_evidence_note=lambda *_args, **_kwargs: None,
    )
    runtime.collect_cached_network_nat_gateway_records = lambda d: NetworkEvidenceMixin.collect_cached_network_nat_gateway_records(runtime, d)
    evidence = NatGatewayInventoryCollector(definition).collect(ScannerContext(runtime=runtime, definition=definition))
    if variant.startswith("legacy_"):
        period = ScanPeriodResolver().resolve(days=7, reference_date=date(2026, 5, 20))
        metrics = NetworkMetricCollector(session, audit_context=collector.audit_context, regions=["eu-west-2"])
        evidence = replace(evidence, records=metrics.add_nat_gateway_metrics(evidence.records, period))
    row = json.loads(json.dumps(build_scanner_evidence_payload(scanner_id=SCANNER, evidence=evidence)))
    if variant.startswith("legacy_"):
        row.update(evidence_module="unio_collector.scanners.fixture_parity.synthetic_types", evidence_type="NatGatewayFixtureEvidence")
    return row, [asdict(item) for batch in collector.collected_batches() for item in batch.coverage]


def add_nat_producer_payload(files: dict[str, bytes], *, unknown_field: bool = False) -> None:
    """Share actual populated, nullable and private-network inventory with smoke."""
    row, _ = nat_producer_case()
    for variant in ("optional", "private"):
        extra, _ = nat_producer_case(variant)
        row["payload"]["records"].extend(extra["payload"]["records"])
    if unknown_field:
        row["payload"]["records"][0]["unknown_nat_container"] = {}
    add_scanner_producer_payload(files, row)
