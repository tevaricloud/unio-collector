"""Exact public constants whose text is not customer evidence."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from unio_collector.privacy.active_findings import VOCABULARIES as SECURITY_FINDING_VOCABULARIES
from unio_collector.privacy.active_findings import SecurityFindingsPrivacyContract
from unio_collector.privacy.audit.condition import AuditConditionContract
from unio_collector.privacy.audit.contract import AuditPrivacyContract
from unio_collector.privacy.audit.fields import VOCABULARIES as AUDIT_VOCABULARIES
from unio_collector.privacy.audit.governance.contract import GovernancePrivacyContract
from unio_collector.privacy.audit.governance.fields import SCANNERS as GOVERNANCE_SCANNERS
from unio_collector.privacy.audit.notes import AuditNoteContract
from unio_collector.privacy.backup.contract import BackupPrivacyContract
from unio_collector.privacy.bedrock import BedrockPrivacyContract
from unio_collector.privacy.billing.contract import BillingPrivacyContract
from unio_collector.privacy.commitment.base import CommitmentPrivacyBase
from unio_collector.privacy.cost_delta import CostDeltaPrivacyContract
from unio_collector.privacy.cur import CurPrivacyContract
from unio_collector.privacy.dynamodb.contract import DynamoPrivacyContract
from unio_collector.privacy.ec2.base import VOCABULARIES as EC2_VOCABULARIES
from unio_collector.privacy.ec2.base import Ec2PrivacyContract
from unio_collector.privacy.ec2.idle import CONTRACTS as IDLE_CONTRACTS
from unio_collector.privacy.ec2.idle import IdleBundlePrivacyContract
from unio_collector.privacy.ec2.iops import ProvisionedIopsPrivacyContract
from unio_collector.privacy.ec2.load_balancer import VOCABULARIES as BALANCER_VOCABULARIES
from unio_collector.privacy.ec2.load_balancer import LoadBalancerPrivacyContract
from unio_collector.privacy.ec2.nat_inventory import VOCABULARIES as NAT_VOCABULARIES
from unio_collector.privacy.ec2.nat_inventory import NatInventoryPrivacyContract
from unio_collector.privacy.ec2.running import RunningInstancePrivacyContract
from unio_collector.privacy.ec2.stopped import StoppedInstancePrivacyContract
from unio_collector.privacy.ec2.volume import EbsVolumePrivacyContract
from unio_collector.privacy.edge.contract import EdgePrivacyContract
from unio_collector.privacy.edge.coverage import EdgeCoverageContract
from unio_collector.privacy.exposure.contract import ExposurePrivacyContract
from unio_collector.privacy.exposure.fields import SCANNERS as EXPOSURE_SCANNERS
from unio_collector.privacy.exposure.group import SecurityGroupPrivacyContract
from unio_collector.privacy.flow.base import FlowPrivacyBase
from unio_collector.privacy.free_tier import FreeTierPrivacyContract
from unio_collector.privacy.identity.contract import IdentityPrivacyContract
from unio_collector.privacy.identity.fields import SCANNERS as IDENTITY_SCANNERS
from unio_collector.privacy.key_controls.contract import KeyControlPrivacyContract
from unio_collector.privacy.key_controls.fields import SCANNERS as KEY_CONTROL_SCANNERS
from unio_collector.privacy.leak.public.operational import OperationalScanPolicy
from unio_collector.privacy.leak.public.region import public_region
from unio_collector.privacy.leak.public.serverless import IDENTITIES as SERVERLESS_IDENTITIES
from unio_collector.privacy.leak.public.serverless import ServerlessScanContract
from unio_collector.privacy.leak.public.service import is_service_literal
from unio_collector.privacy.leak.public.temporal import TemporalScanPolicy
from unio_collector.privacy.log_activity import VOCABULARIES as LOG_VOCABULARIES
from unio_collector.privacy.log_activity import LogActivityPrivacyContract
from unio_collector.privacy.network.base import NetworkPrivacyContract, public_services
from unio_collector.privacy.network.facts import enum_values
from unio_collector.privacy.network.fields import VOCABULARIES as NETWORK_VOCABULARIES
from unio_collector.privacy.network.nat_cost import NatCostPrivacyContract
from unio_collector.privacy.network.privatelink import PrivateLinkPrivacyContract
from unio_collector.privacy.network.public_ipv4 import PublicIpv4PrivacyContract
from unio_collector.privacy.network.transit import RESOURCE_TYPES, TransitGatewayPrivacyContract
from unio_collector.privacy.network.vpc import VpcEndpointPrivacyContract
from unio_collector.privacy.platform.elasticache import VOCABULARIES as CACHE_VOCABULARIES
from unio_collector.privacy.platform.elasticache import ElastiCachePrivacyContract
from unio_collector.privacy.quota import QuotaPrivacyContract
from unio_collector.privacy.rds.base import RdsPrivacyContract
from unio_collector.privacy.recommendation.contract import RecommendationPrivacyContract
from unio_collector.privacy.recommendation.fields import SCANNERS as RECOMMENDATION_SCANNERS
from unio_collector.privacy.recommendation.record import RecommendationRecordContract
from unio_collector.privacy.retention import LogRetentionPrivacyContract
from unio_collector.privacy.s3.base import S3PrivacyContract
from unio_collector.privacy.s3.fields import PUBLIC_LITERALS as S3_LITERALS
from unio_collector.privacy.s3.multipart import S3MultipartPrivacyContract
from unio_collector.privacy.serverless.lifecycle import LifecyclePrivacyContract
from unio_collector.privacy.serverless.metric import ServerlessMetricContract
from unio_collector.privacy.service.coverage import ServiceCoveragePrivacyContract
from unio_collector.privacy.tagging.contract import TaggingPrivacyContract

if TYPE_CHECKING:
    from unio_collector.privacy.closed_schema import ClosedProducerContract
    from unio_collector.privacy.treatment_decision import PrivacyTreatmentDecision

PUBLIC_SCANNER_IDS = frozenset(
    contract.scanner_id
    for contract in (
        PublicIpv4PrivacyContract,
        PrivateLinkPrivacyContract,
        TransitGatewayPrivacyContract,
        NatCostPrivacyContract,
        VpcEndpointPrivacyContract,
        StoppedInstancePrivacyContract,
        RunningInstancePrivacyContract,
        LogRetentionPrivacyContract,
        IdleBundlePrivacyContract,
    )
)
PUBLIC_SCANNER_IDS |= frozenset({BillingPrivacyContract.scanner_id, "cur-data-export-attribution"})
PUBLIC_SCANNER_IDS |= frozenset(SERVERLESS_IDENTITIES)
PUBLIC_SCANNER_IDS |= (
    frozenset({QuotaPrivacyContract.scanner_id, FreeTierPrivacyContract.scanner_id, CostDeltaPrivacyContract.scanner_id})
    | frozenset(S3MultipartPrivacyContract.scanners)
    | frozenset(GOVERNANCE_SCANNERS)
    | frozenset(KEY_CONTROL_SCANNERS)
    | frozenset(IDENTITY_SCANNERS)
    | frozenset(EXPOSURE_SCANNERS)
    | frozenset(RECOMMENDATION_SCANNERS)
)
COVERAGE_LISTS = frozenset({"scanner_evidence_payload_ids", "selected_scanner_ids", "successful_scanner_ids", "permission_denied_scanner_ids"})


def is_public_payload_literal(contract: ClosedProducerContract, suffix: str, value: object) -> bool:
    """Recognize only exact reviewed producer roles; arbitrary strings remain scanned."""
    if isinstance(contract, IdleBundlePrivacyContract):
        collection, separator, remainder = suffix.partition("[]")
        delegate = IDLE_CONTRACTS.get(collection)
        return delegate is not None and bool(separator) and is_public_payload_literal(delegate, "records[]" + remainder, value)
    if TemporalScanPolicy.payload_value(contract, suffix, value):
        return True
    if isinstance(
        contract,
        BackupPrivacyContract
        | LifecyclePrivacyContract
        | DynamoPrivacyContract
        | EdgePrivacyContract
        | EdgeCoverageContract
        | TaggingPrivacyContract
        | FlowPrivacyBase
        | CommitmentPrivacyBase,
    ):
        return contract.is_literal(suffix, value)
    if isinstance(contract, ServerlessMetricContract):
        return contract.is_literal(suffix, value)
    if isinstance(contract, BedrockPrivacyContract) and suffix.startswith("records[].operation_limitations[]."):
        return contract.is_public_capability(suffix, value)
    if isinstance(contract, CurPrivacyContract):
        return contract.is_literal(suffix, value)
    if isinstance(contract, RunningInstancePrivacyContract):
        return contract.is_public_literal(suffix, value)
    if isinstance(contract, RdsPrivacyContract):
        return contract.is_public_literal(suffix, value)
    return _metric_literal(contract, suffix, value) or _public_payload_literal(contract, suffix, value)


def _metric_literal(contract: ClosedProducerContract, suffix: str, value: object) -> bool:
    """Recognize exact finite metric roles after their independently guarded parent."""
    vocabularies = (
        CACHE_VOCABULARIES
        if isinstance(contract, ElastiCachePrivacyContract)
        else BALANCER_VOCABULARIES
        if isinstance(contract, LoadBalancerPrivacyContract)
        else LOG_VOCABULARIES
        if isinstance(contract, LogActivityPrivacyContract)
        else {}
    )
    spec = contract.fields.get(suffix)
    return isinstance(value, str) and spec is not None and spec[1] == "safe_metadata" and value in vocabularies.get(spec[0], ())


def _public_payload_literal(contract: ClosedProducerContract, suffix: str, value: object) -> bool:
    """Recognize only finite literal values at their exact reviewed payload paths."""
    if not isinstance(value, str):
        return (isinstance(contract, SecurityGroupPrivacyContract) and contract.is_public_port(suffix, value)) or _operational_number(contract, suffix, value)
    if isinstance(
        contract,
        (
            S3PrivacyContract,
            ServiceCoveragePrivacyContract,
            AuditPrivacyContract,
            AuditConditionContract,
            AuditNoteContract,
            QuotaPrivacyContract,
            FreeTierPrivacyContract,
            CostDeltaPrivacyContract,
        ),
    ):
        return _is_scanner_literal(contract, suffix, value)
    if isinstance(contract, VpcEndpointPrivacyContract):
        if suffix == "records[].sample_candidate_network_interface_contexts[].classification":
            return contract.fields.get(suffix) == ("classification", "safe_metadata", False) and contract._valid(value, "classification", nullable=False)  # noqa: SLF001
        if suffix == "records[].sample_candidate_network_interface_contexts[].interface_type":
            return value in enum_values("NetworkInterfaceType")
        if suffix == "records[].sample_candidate_network_interface_contexts[].requester_managed":
            return value == "true"
    if isinstance(contract, TransitGatewayPrivacyContract):
        if suffix == "records[].sample_attachment_resource_types[]":
            return value in RESOURCE_TYPES
        if suffix == "topology[].resources[].facts.ResourceType":
            return value.casefold() in {item.casefold() for item in enum_values("TransitGatewayAttachmentResourceType")}
    return _is_security_literal(contract, suffix, value) or (isinstance(contract, NetworkPrivacyContract) and _is_network_literal(contract, suffix, value))


def _is_network_literal(contract: NetworkPrivacyContract, suffix: str, value: str) -> bool:
    spec = contract.fields.get(suffix)
    if spec is not None and spec[1] in {"network_service", "network_identity"} and value in public_services():
        return True
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
    if ServerlessScanContract.owns(contract) or isinstance(
        contract,
        (
            NetworkPrivacyContract,
            Ec2PrivacyContract,
            LogRetentionPrivacyContract,
            IdleBundlePrivacyContract,
            AuditPrivacyContract,
            QuotaPrivacyContract,
            FreeTierPrivacyContract,
            CostDeltaPrivacyContract,
            RecommendationPrivacyContract,
            BillingPrivacyContract,
            CurPrivacyContract,
            S3MultipartPrivacyContract,
        ),
    ):
        for key in ("scanner_id", "evidence_module", "evidence_type"):
            row[key] = ""
    if isinstance(contract, LogRetentionPrivacyContract) and "evidence_schema_id" in row:
        row["evidence_schema_id"] = ""


def mask_network_references(member: str, document: dict[str, Any]) -> None:
    """Normalize only exact reviewed scanner IDs at fixed producer reference positions."""
    if member == "scan-result/scanner-results.json":
        rows = document.get("scanner_results")
        if isinstance(rows, list):
            for row in rows:
                if isinstance(row, dict) and isinstance(row.get("scanner_id"), str) and row["scanner_id"] in PUBLIC_SCANNER_IDS:
                    regions = row.get("regions_scanned")
                    if isinstance(regions, list) and all(public_region(region) for region in regions):
                        row["regions_scanned"] = ["" for _ in regions]
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


def _is_scanner_literal(
    contract: S3PrivacyContract
    | ServiceCoveragePrivacyContract
    | AuditPrivacyContract
    | AuditConditionContract
    | AuditNoteContract
    | QuotaPrivacyContract
    | FreeTierPrivacyContract
    | CostDeltaPrivacyContract,
    suffix: str,
    value: str,
) -> bool:
    if isinstance(contract, (AuditConditionContract, AuditNoteContract, QuotaPrivacyContract, FreeTierPrivacyContract, CostDeltaPrivacyContract)):
        return contract.is_literal(suffix, value)
    if isinstance(contract, (GovernancePrivacyContract, KeyControlPrivacyContract, IdentityPrivacyContract, ExposurePrivacyContract)):
        return contract.is_literal(suffix, value)
    if isinstance(contract, AuditPrivacyContract):
        spec = contract.fields.get(suffix)
        return spec is not None and spec[0] in AUDIT_VOCABULARIES and value in AUDIT_VOCABULARIES[spec[0]]
    if isinstance(contract, ServiceCoveragePrivacyContract):
        return is_service_literal(contract, suffix, value)
    return suffix in contract.fields and value in S3_LITERALS.get(suffix, set())


def _is_security_literal(contract: ClosedProducerContract, suffix: str, value: str) -> bool:
    """Recognize the existing trusted active-finding finite status positions only."""
    if isinstance(contract, NatInventoryPrivacyContract):
        spec = contract.fields.get(suffix)
        return spec is not None and spec[1] == "safe_metadata" and spec[0] in NAT_VOCABULARIES and value in NAT_VOCABULARIES[spec[0]]
    if isinstance(contract, NatCostPrivacyContract) and suffix.startswith("nat_gateways[]"):
        return _is_security_literal(NatInventoryPrivacyContract(), suffix.replace("nat_gateways", "records", 1), value)
    if isinstance(contract, StoppedInstancePrivacyContract) and suffix == "records[].instance_type":
        return contract.fields.get(suffix) == ("instance_type", "safe_metadata", False) and contract._valid(value, "instance_type", nullable=False)  # noqa: SLF001
    if isinstance(contract, (EbsVolumePrivacyContract, ProvisionedIopsPrivacyContract)):
        spec = contract.fields.get(suffix)
        return spec is not None and spec[1] == "safe_metadata" and spec[0] in EC2_VOCABULARIES and value in EC2_VOCABULARIES[spec[0]]
    if isinstance(contract, BillingPrivacyContract):
        return contract.is_literal(suffix, value) or contract.metric_literal(suffix, value)
    if isinstance(contract, (RecommendationPrivacyContract, RecommendationRecordContract)):
        return isinstance(value, str) and contract.is_literal(suffix, value)
    spec = contract.fields.get(suffix)
    if spec is not None and spec[:2] == ("status", "safe_metadata"):
        return not contract.unknown_paths(value, "", suffix)
    if isinstance(contract, SecurityFindingsPrivacyContract):
        spec = contract.fields.get(suffix)
        return spec is not None and spec[0] in SECURITY_FINDING_VOCABULARIES and value in SECURITY_FINDING_VOCABULARIES[spec[0]]
    return False


def is_public_denied_reference(member: str, path: str, value: str, decision: PrivacyTreatmentDecision) -> bool:
    """Recognize only reviewed static scanner identities at the three producer paths."""
    if decision.decision_source != "exact_json_path" or decision.category != "resource_name" or decision.treatment != "tokenise":
        return False
    return (member, path) in {
        ("analysis-readiness.json", "$.scanner_evidence_coverage.permission_denied_scanner_ids[]"),
        ("collection-summary.json", "$.strict_analysis_readiness.scanner_evidence_coverage.permission_denied_scanner_ids[]"),
        ("scan-result/report-bundle.json", "$.summary.scanner_evidence_coverage.permission_denied_scanner_ids[]"),
    } and value in PUBLIC_SCANNER_IDS


def _operational_number(contract: ClosedProducerContract, suffix: str, value: object) -> bool:
    """Treat only reproduced finite SDK numbers and the neutral IPv4 byte counter."""
    if OperationalScanPolicy.number(contract, suffix, value):
        return True
    if isinstance(contract, BillingPrivacyContract):
        return contract.is_literal(suffix, value)
    if isinstance(contract, (RecommendationPrivacyContract, RecommendationRecordContract)):
        return contract.is_public_number(suffix, value)
    return (
        isinstance(contract, PublicIpv4PrivacyContract)
        and suffix == "topology[].bytes_used"
        and contract.fields.get(suffix) == ("count", "safe_metadata", False)
        and type(value) is int
        and value >= 0
    )
