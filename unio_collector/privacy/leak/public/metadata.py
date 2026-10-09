"""Exact public constants whose text is not customer evidence."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from unio_collector.privacy.ec2.load_balancer import VOCABULARIES as BALANCER_VOCABULARIES
from unio_collector.privacy.ec2.load_balancer import LoadBalancerPrivacyContract
from unio_collector.privacy.ec2.stopped import StoppedInstancePrivacyContract
from unio_collector.privacy.leak.public.service import is_service_literal
from unio_collector.privacy.network.base import NetworkPrivacyContract
from unio_collector.privacy.network.facts import enum_values
from unio_collector.privacy.network.fields import VOCABULARIES as NETWORK_VOCABULARIES
from unio_collector.privacy.network.nat_cost import NatCostPrivacyContract
from unio_collector.privacy.network.privatelink import PrivateLinkPrivacyContract
from unio_collector.privacy.network.public_ipv4 import PublicIpv4PrivacyContract
from unio_collector.privacy.network.transit import RESOURCE_TYPES, TransitGatewayPrivacyContract
from unio_collector.privacy.network.vpc import VpcEndpointPrivacyContract
from unio_collector.privacy.s3.base import S3PrivacyContract
from unio_collector.privacy.s3.fields import PUBLIC_LITERALS as S3_LITERALS
from unio_collector.privacy.service.coverage import ServiceCoveragePrivacyContract

if TYPE_CHECKING:
    from unio_collector.privacy.closed_schema import ClosedProducerContract

PUBLIC_SCANNER_IDS = frozenset(
    contract.scanner_id
    for contract in (
        PublicIpv4PrivacyContract,
        PrivateLinkPrivacyContract,
        TransitGatewayPrivacyContract,
        NatCostPrivacyContract,
        VpcEndpointPrivacyContract,
        StoppedInstancePrivacyContract,
    )
)
COVERAGE_LISTS = frozenset({"scanner_evidence_payload_ids", "selected_scanner_ids", "successful_scanner_ids"})


def is_public_payload_literal(contract: ClosedProducerContract, suffix: str, value: object) -> bool:
    """Recognize only finite literal values at their exact reviewed payload paths."""
    if not isinstance(value, str):
        return False
    if isinstance(contract, (S3PrivacyContract, ServiceCoveragePrivacyContract)):
        return _is_scanner_literal(contract, suffix, value)
    if isinstance(contract, LoadBalancerPrivacyContract) and suffix == "records[].load_balancer_type":
        return value in BALANCER_VOCABULARIES["lb_type"]
    if isinstance(contract, VpcEndpointPrivacyContract):
        if suffix == "records[].sample_candidate_network_interface_contexts[].interface_type":
            return value in enum_values("NetworkInterfaceType")
        if suffix == "records[].sample_candidate_network_interface_contexts[].requester_managed":
            return value == "true"
    if isinstance(contract, TransitGatewayPrivacyContract):
        if suffix == "records[].sample_attachment_resource_types[]":
            return value in RESOURCE_TYPES
        if suffix == "topology[].resources[].facts.ResourceType":
            return value.casefold() in {item.casefold() for item in enum_values("TransitGatewayAttachmentResourceType")}
    return isinstance(contract, NetworkPrivacyContract) and _is_network_literal(contract, suffix, value)


def _is_network_literal(contract: NetworkPrivacyContract, suffix: str, value: str) -> bool:
    if suffix == "topology[].resources[].facts.InterfaceType":
        return value in enum_values("NetworkInterfaceType")
    spec = contract.fields.get(suffix)
    if spec is not None and spec[1] == "safe_metadata" and spec[0] in NETWORK_VOCABULARIES:
        kind = spec[0]
        if kind == "resource_kind":
            return value in contract.collection_names
        values = NETWORK_VOCABULARIES[kind]
        return value in values or (kind == "operation" and value in contract.collection_names)
    return False


def mask_network_identity(row: dict[str, Any], contract: ClosedProducerContract) -> None:
    """Mask the exact envelope identity already admitted by its selected contract."""
    if isinstance(contract, (NetworkPrivacyContract, StoppedInstancePrivacyContract)):
        for key in ("scanner_id", "evidence_module", "evidence_type"):
            row[key] = ""


def mask_network_references(member: str, document: dict[str, Any]) -> None:
    """Normalize only exact reviewed scanner IDs at fixed producer reference positions."""
    if member == "scan-result/scanner-results.json":
        rows = document.get("scanner_results")
        if isinstance(rows, list):
            for row in rows:
                if isinstance(row, dict) and isinstance(row.get("scanner_id"), str) and row["scanner_id"] in PUBLIC_SCANNER_IDS:
                    row["scanner_id"] = ""
        return
    root = document if member == "analysis-readiness.json" else document.get("strict_analysis_readiness")
    if not isinstance(root, dict):
        return
    coverage = root.get("scanner_evidence_coverage")
    if isinstance(coverage, dict):
        for key in COVERAGE_LISTS:
            values = coverage.get(key)
            if isinstance(values, list):
                coverage[key] = ["" if isinstance(value, str) and value in PUBLIC_SCANNER_IDS else value for value in values]


def mask_pricing_counter(document: dict[str, Any]) -> Any:  # noqa: ANN401
    """Mask the fixed PricingReplayContext counter key only for valid integer counts."""
    counter = document.get("stopped_lookup_request_count")
    if type(counter) is not int or counter < 0:
        return document
    return [["" if key == "stopped_lookup_request_count" else key, value] for key, value in document.items()]


def _is_scanner_literal(contract: S3PrivacyContract | ServiceCoveragePrivacyContract, suffix: str, value: str) -> bool:
    if isinstance(contract, ServiceCoveragePrivacyContract):
        return is_service_literal(contract, suffix, value)
    return suffix in contract.fields and value in S3_LITERALS.get(suffix, set())
