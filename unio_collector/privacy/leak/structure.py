"""Separate fixed reviewed producer field names from potentially private content."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from unio_collector.privacy.audit.selection import select_audit_note
from unio_collector.privacy.backup.contract import BackupPrivacyContract
from unio_collector.privacy.backup.notes import BackupNoteContract
from unio_collector.privacy.bedrock import BedrockPrivacyContract
from unio_collector.privacy.billing.contract import BillingPrivacyContract
from unio_collector.privacy.billing.notes import SCANNER as BILLING_SCANNER
from unio_collector.privacy.billing.notes import BillingNoteContract
from unio_collector.privacy.cache.notes import CacheNoteContract
from unio_collector.privacy.commitment.base import CommitmentPrivacyBase
from unio_collector.privacy.dynamodb.contract import DynamoPrivacyContract
from unio_collector.privacy.dynamodb.notes import DynamoNoteContract
from unio_collector.privacy.ec2.load_balancer import LoadBalancerPrivacyContract
from unio_collector.privacy.ec2.notes import SCANNER as COMPUTE_SCANNER
from unio_collector.privacy.ec2.notes import ComputeLimitNoteContract
from unio_collector.privacy.edge.contract import EdgePrivacyContract
from unio_collector.privacy.edge.notes import SCANNER as EDGE_SCANNER
from unio_collector.privacy.edge.notes import EdgeNoteContract
from unio_collector.privacy.exposure.contract import ExposurePrivacyContract
from unio_collector.privacy.exposure.notes import SCANNER as ECR_SCANNER
from unio_collector.privacy.exposure.notes import EcrNoteContract
from unio_collector.privacy.flow.base import FlowPrivacyBase
from unio_collector.privacy.identity.contract import IdentityPrivacyContract
from unio_collector.privacy.identity.notes import IdentityNoteContract
from unio_collector.privacy.inventory_notes import InventoryNoteContract
from unio_collector.privacy.leak.public.environment import EnvironmentContextScanContract
from unio_collector.privacy.leak.public.legacy import LegacyRegionScanContract
from unio_collector.privacy.leak.public.metadata import is_public_payload_literal, mask_network_identity, mask_network_references
from unio_collector.privacy.leak.public.network import NetworkLiteralScanPolicy
from unio_collector.privacy.leak.public.operational import OperationalScanPolicy
from unio_collector.privacy.leak.public.paths import PROTOCOL_MEMBERS, mask_protocol_references
from unio_collector.privacy.leak.public.protocol import ProtocolScanContract
from unio_collector.privacy.leak.public.region import public_location
from unio_collector.privacy.leak.public.serverless import ServerlessScanContract
from unio_collector.privacy.leak.public.service import admitted_service_record
from unio_collector.privacy.log_activity import LogActivityPrivacyContract
from unio_collector.privacy.network.base import NetworkPrivacyContract
from unio_collector.privacy.network.public_ipv4 import PublicIpv4PrivacyContract
from unio_collector.privacy.network.vpc import VpcEndpointPrivacyContract
from unio_collector.privacy.platform.elasticache import ElastiCachePrivacyContract
from unio_collector.privacy.platform.metric_scan import admitted_metric
from unio_collector.privacy.platform.notes import ManagedNoteContract
from unio_collector.privacy.quota import QuotaPrivacyContract
from unio_collector.privacy.rds.base import RdsPrivacyContract
from unio_collector.privacy.recommendation.record import RecommendationRecordContract
from unio_collector.privacy.selection import select_producer_contract
from unio_collector.privacy.serverless.lifecycle import LifecyclePrivacyContract
from unio_collector.privacy.serverless.metric import METRIC, ServerlessMetricContract
from unio_collector.privacy.serverless.notes import PollingNoteContract
from unio_collector.privacy.service.coverage import ServiceCoveragePrivacyContract
from unio_collector.privacy.tagging.contract import TaggingPrivacyContract
from unio_collector.privacy.tagging.fields import SCANNER as TAGGING_SCANNER
from unio_collector.privacy.tagging.notes import TaggingNoteContract

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


def _admitted_record_view(value: object, contract: ClosedProducerContract) -> bool:
    """Keep independently owned record guard policies before structural masking."""
    if isinstance(contract, BackupPrivacyContract | LifecyclePrivacyContract):
        return contract.admitted_scan_record(value)
    if isinstance(contract, DynamoPrivacyContract):
        return contract.admitted_scan_record(value)
    if isinstance(contract, RdsPrivacyContract):
        return contract.admitted_scan_record(value)
    if isinstance(contract, ServiceCoveragePrivacyContract):
        return admitted_service_record(value, contract)
    return True


def _guarded_container_invalid(value: Any, contract: ClosedProducerContract, suffix: str) -> bool:  # noqa: ANN401
    """Retain exact independent shape guards before any structural normalization."""
    operational_invalid = OperationalScanPolicy.container_invalid(value, contract, suffix)
    if operational_invalid is not None:
        return operational_invalid
    if isinstance(contract, TaggingPrivacyContract) and isinstance(value, (dict, list)):
        return bool(contract.unknown_paths(value, "", suffix))
    if isinstance(contract, EdgePrivacyContract | FlowPrivacyBase | CommitmentPrivacyBase) and isinstance(value, (dict, list)):
        return not contract.admitted_scan_container(value, suffix)
    checked = EnvironmentContextScanContract.validation_view(value, contract, suffix)
    if isinstance(contract, LoadBalancerPrivacyContract | ElastiCachePrivacyContract | LogActivityPrivacyContract) and suffix == "records[].metrics[]":
        return not admitted_metric(checked, contract, suffix)
    if isinstance(contract, ServerlessMetricContract) and suffix == METRIC:
        return not admitted_metric(checked, contract, suffix)
    if isinstance(contract, InventoryNoteContract | ManagedNoteContract | CacheNoteContract | PollingNoteContract | BackupNoteContract | DynamoNoteContract):
        return bool(contract.unknown_paths(checked, "", suffix))
    if isinstance(contract, BedrockPrivacyContract) and suffix == "records[].operation_limitations[]":
        return not contract.admitted_operation_limitation(checked)
    guarded = (
        (suffix == "quota_records[]" and isinstance(contract, QuotaPrivacyContract))
        or (suffix in {"records[]", "global_records[]"} and isinstance(contract, ExposurePrivacyContract))
        or (suffix == "topology[]" and isinstance(contract, PublicIpv4PrivacyContract))
        or suffix == "topology[].resources[]"
    )
    if guarded and contract.unknown_paths(checked, "", suffix):
        return True
    return suffix == "records[]" and not _admitted_record_view(checked, contract)


def _network_resource_view(value: Any, contract: ClosedProducerContract, suffix: str) -> Any:  # noqa: ANN401
    """Apply kind-bound enum normalization only after the parent guard."""
    return (
        NetworkLiteralScanPolicy.view(value, contract.collection_names)
        if suffix == "topology[].resources[]" and isinstance(contract, NetworkPrivacyContract)
        else value
    )


def _mask_fixed_keys(
    value: Any,  # noqa: ANN401
    contract: ClosedProducerContract,
    suffix: str = "",
    generated_tokens: frozenset[str] = frozenset(),
    *,
    mask_arn_regions: bool = False,
) -> Any:  # noqa: ANN401
    if _guarded_container_invalid(value, contract, suffix):
        return value
    value = _network_resource_view(value, contract, suffix)
    if isinstance(value, list):
        selected = contract.for_sequence(value, contract.prefix + ("." + suffix if suffix else ""))
        if selected is not None:
            contract = selected
    if isinstance(value, dict):
        container = contract.for_container(value, "$.scanner_evidence[].payload." + suffix)
        if container is not None:
            contract = container
    terminal, viewed = _payload_metadata_view(value, contract, suffix, generated_tokens, mask_arn_regions=mask_arn_regions)
    if terminal:
        return viewed
    fields = contract.fields
    spec = fields[suffix]
    financial_union = isinstance(contract, RecommendationRecordContract) and spec[0] == "financial_union" and isinstance(value, dict)
    identity_union = isinstance(contract, IdentityPrivacyContract) and spec[0] in {"statement", "strings"} and contract._valid(value, spec[0], nullable=spec[2])  # noqa: SLF001
    if isinstance(value, list) and (spec[0] in {"array", "pair"} or identity_union):
        return [
            _mask_fixed_keys(child, contract, contract.sequence_item_path(suffix, index), generated_tokens, mask_arn_regions=mask_arn_regions)
            for index, child in enumerate(value)
        ]
    if isinstance(value, dict) and (spec[0] == "object" or identity_union or financial_union):
        result = []
        for key, child in value.items():
            path = suffix + ("." if suffix else "") + key
            declared = not any(character in key for character in ".[]") and path in fields
            context = key == "environment_context" and EnvironmentContextScanContract.admitted(value, contract, suffix)
            result.append(
                [
                    "" if declared or context else key,
                    "" if context else _mask_fixed_keys(child, contract, path, generated_tokens, mask_arn_regions=mask_arn_regions) if declared else child,
                ]
            )
        return result
    return value


def _payload_metadata_view(
    value: Any,  # noqa: ANN401
    contract: ClosedProducerContract,
    suffix: str,
    generated_tokens: frozenset[str],
    *,
    mask_arn_regions: bool,
) -> tuple[bool, Any]:
    """Separate exact finite metadata and typed regions from customer content."""
    terminal, diagnostic = _billing_diagnostic_view(value, contract, suffix, generated_tokens)
    if terminal:
        return True, diagnostic
    if is_public_payload_literal(contract, suffix, value):
        return True, ""
    if isinstance(contract, IdentityPrivacyContract) and suffix == "analyzer_inventory_status":
        if not contract.unknown_paths(value, "", suffix):
            return True, ""
        return True, value
    spec = contract.fields.get(suffix)
    if spec is None:
        return True, value
    if (
        isinstance(contract, BillingPrivacyContract)
        and isinstance(value, dict)
        and suffix in {"budgets[].budget.CostFilters", "budgets[].budget.PlannedBudgetLimits"}
    ):
        return True, _billing_map_view(value, contract, suffix, generated_tokens, mask_arn_regions=mask_arn_regions)
    if isinstance(value, str) and spec[1] == "region" and public_location(value):
        return True, ""
    if isinstance(value, str) and spec[1] in {"arn", "arn_or_name"}:
        return True, ServerlessScanContract.arn_view(contract, suffix, value, generated_tokens, mask_regions=mask_arn_regions)
    if (
        isinstance(value, dict)
        and isinstance(contract, VpcEndpointPrivacyContract)
        and suffix == "records[].nat_gateway_availability_zones"
        and spec[:2] == ("string_map", "region")
        and contract.mapping_key_category("$.scanner_evidence[].payload." + suffix) == "resource_id"
        and not contract.unknown_paths(value, "", suffix)
        and all(public_location(child) for child in value.values())
    ):
        return True, [[key, ""] for key in value]
    return False, value


def _structured_scan_content(
    path: str, content: str, generated_tokens: frozenset[str], *, mask_arn_regions: bool, verified_checksums: frozenset[tuple[str, str]]
) -> str:
    """Mask declared keys and narrowly enumerated public literals, never customer content.

    This view is solely for known-original substring matching. The unchanged raw
    content still receives credential, account, ARN, IP and private-key scans.
    Dynamic tag keys, unknown paths, unknown identities and malformed JSON remain
    scanned. No output archive bytes or privacy classification decisions change.
    """
    if path not in {
        "scan-result/scanner-evidence.json",
        "scan-result/scanner-results.json",
        "scan-result/api-runtime-summary.json",
        "analysis-readiness.json",
        "collection-summary.json",
        "scan-result/pricing-context.json",
        "account-scope.json",
        "analysis-contract.json",
        "permissions-summary.json",
        "permissions/degradation-records.json",
        "scan-result/report-bundle.json",
        "collection-log.jsonl",
        "privacy/protection-policy.json",
        "privacy/preview-summary.json",
        "signature.json",
        *PROTOCOL_MEMBERS,
    }:
        return content
    try:
        if path.endswith(".jsonl"):
            return "\n".join(
                json.dumps(ProtocolScanContract(generated_tokens).mask(path, json.loads(line, object_pairs_hook=_unique_object)), ensure_ascii=False)
                for line in content.splitlines()
                if line.strip()
            )
        document = json.loads(content, object_pairs_hook=_unique_object)
        if not isinstance(document, dict):
            return content
        if path == "scan-result/pricing-context.json":
            return json.dumps(ProtocolScanContract(generated_tokens).mask(path, document), ensure_ascii=False)
        if path in PROTOCOL_MEMBERS:
            mask_protocol_references(path, document, verified_checksums=verified_checksums)
            return json.dumps(ProtocolScanContract(generated_tokens).mask(path, document), ensure_ascii=False)
        if path != "scan-result/scanner-evidence.json":
            if path == "scan-result/scanner-results.json":
                _mask_audit_notes(document, generated_tokens, mask_arn_regions=mask_arn_regions)
            if path != "scan-result/scanner-results.json":
                mask_network_references(path, document)
            return json.dumps(ProtocolScanContract(generated_tokens).mask(path, document), ensure_ascii=False)
        return _scanner_scan_content(document, content, generated_tokens, mask_arn_regions=mask_arn_regions)
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


def known_value_scan_content(
    path: str,
    content: str,
    generated_tokens: frozenset[str] = frozenset(),
    *,
    mask_arn_regions: bool = False,
    verified_checksums: frozenset[tuple[str, str]] = frozenset(),
) -> str:
    """Return the structural view, retaining unknown members and malformed input."""
    return _structured_scan_content(path, content, generated_tokens, mask_arn_regions=mask_arn_regions, verified_checksums=verified_checksums)


def _scanner_scan_content(document: dict[str, Any], content: str, generated_tokens: frozenset[str], *, mask_arn_regions: bool) -> str:
    """Mask admitted scanner rows while preserving malformed envelopes verbatim."""
    if not isinstance(document.get("scanner_evidence"), list):
        return content
    for row in document["scanner_evidence"]:
        if not isinstance(row, dict):
            return content
        contract = select_producer_contract(row)
        if contract is None:
            LegacyRegionScanContract.mask(row)
        if contract is not None and "payload" in row:
            mask_network_identity(row, contract)
            row["payload"] = _mask_fixed_keys(row["payload"], contract, generated_tokens=generated_tokens, mask_arn_regions=mask_arn_regions)
    return json.dumps(document, ensure_ascii=False)


def _mask_audit_notes(document: dict[str, Any], generated_tokens: frozenset[str], *, mask_arn_regions: bool) -> None:
    rows = document.get("scanner_results")
    if not isinstance(rows, list):
        return
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("coverage_notes"), list):
            continue
        for index, note in enumerate(row["coverage_notes"]):
            if not isinstance(note, dict):
                continue
            contract = _owned_audit_note(note, row.get("scanner_id"), provider=row.get("provider_id", "aws"))
            if contract is not None:
                row["coverage_notes"][index] = _mask_fixed_keys(note, contract, generated_tokens=generated_tokens, mask_arn_regions=mask_arn_regions)


def _owned_audit_note(note: dict[str, Any], scanner: object, *, provider: object = "aws") -> ClosedProducerContract | None:
    """Keep exact callback control views bound to their existing originating scanner."""
    contract = select_audit_note(note)
    if isinstance(contract, TaggingNoteContract | EdgeNoteContract):
        return _owned_attribution_note(contract, note, scanner, provider)
    if isinstance(contract, DynamoNoteContract):
        return DynamoNoteContract.for_parent(note, scanner, provider)
    if isinstance(contract, BackupNoteContract):
        return BackupNoteContract.for_parent(note, scanner, provider)
    if isinstance(contract, PollingNoteContract):
        return PollingNoteContract.for_parent(note, scanner, provider)
    if isinstance(contract, CacheNoteContract):
        return CacheNoteContract.for_parent(note, scanner, provider)
    owners = ((ComputeLimitNoteContract, COMPUTE_SCANNER), (EcrNoteContract, ECR_SCANNER), (BillingNoteContract, BILLING_SCANNER))
    if any(isinstance(contract, kind) and scanner != owner for kind, owner in owners):
        return None
    if isinstance(contract, InventoryNoteContract):
        return InventoryNoteContract.for_note(note, scanner_id=str(scanner))
    if isinstance(contract, ManagedNoteContract):
        return ManagedNoteContract.for_note(note, scanner_id=str(scanner))
    if isinstance(contract, IdentityNoteContract):
        return IdentityNoteContract.for_note(note, scanner_id=str(scanner))
    return contract


def _owned_attribution_note(
    contract: TaggingNoteContract | EdgeNoteContract, note: dict[str, Any], scanner: object, provider: object
) -> ClosedProducerContract | None:
    """Keep the two new callback schemas bound to their exact AWS parent."""
    owner = TAGGING_SCANNER if isinstance(contract, TaggingNoteContract) else EDGE_SCANNER
    return contract if scanner == owner and provider == "aws" and not contract.unknown_paths(note, "") else None


def _billing_map_view(
    value: dict[str, Any], contract: BillingPrivacyContract, suffix: str, generated_tokens: frozenset[str], *, mask_arn_regions: bool
) -> list[list[Any]]:
    """Retain data keys; traverse only the declared SDK map value schema."""
    rows = []
    for key, child in value.items():
        path = suffix + "." + key
        child_path = suffix + ".0" if suffix.endswith(".PlannedBudgetLimits") and key in generated_tokens else path
        public_key = contract.preserves_mapping_key("$.scanner_evidence[].payload." + suffix, key)
        viewed = _mask_fixed_keys(child, contract, child_path, generated_tokens, mask_arn_regions=mask_arn_regions)
        rows.append(["" if public_key else key, viewed])
    return rows


def _billing_diagnostic_view(value: object, contract: ClosedProducerContract, suffix: str, generated_tokens: frozenset[str]) -> tuple[bool, object]:
    """Check exact operation labels without hiding any unregistered diagnostic body."""
    if not isinstance(contract, BillingPrivacyContract) or not isinstance(value, str) or suffix != "permission_errors[]":
        return False, value
    prefix = contract.diagnostic_prefix("$.scanner_evidence[].payload." + suffix, value)
    if prefix is not None and value[len(prefix) :] in generated_tokens:
        return True, value[len(prefix) :]
    return True, value
