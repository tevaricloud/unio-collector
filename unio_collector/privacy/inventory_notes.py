"""Closed actual API Gateway, Athena and Bedrock wrapper callback notes."""

from __future__ import annotations

from typing import Any, ClassVar

from unio_collector.privacy.audit.notes import AuditNoteContract
from unio_collector.privacy.bedrock import CAPABILITY_VOCABULARIES, BedrockPrivacyContract, is_capability_value
from unio_collector.privacy.closed_schema import ClosedProducerContract
from unio_collector.privacy.s3.fields import fields

GATEWAY = "api-gateway-cost-review"
ATHENA = "athena-query-efficiency-review"
BEDROCK = "bedrock-cost-review"
GLUE = "glue-job-crawler-cost-review"
SAGEMAKER = "sagemaker-cost-review"
OPENSEARCH = "opensearch-cost-review"
REDSHIFT = "redshift-cost-review"
MANAGED = frozenset({GATEWAY, OPENSEARCH, REDSHIFT})
SCANNERS = frozenset({GATEWAY, ATHENA, BEDROCK, GLUE, SAGEMAKER, OPENSEARCH, REDSHIFT})
DETAILS: dict[str, frozenset[str]] = {
    OPENSEARCH: frozenset(["total_instance_count", "total_ebs_volume_gb", "multi_az_domain_count", "warm_storage_domain_count"]),
    REDSHIFT: frozenset(["cluster_count", "serverless_workgroup_count", "total_node_count", "paused_cluster_count", "serverless_base_capacity_rpu_total"]),
    GLUE: frozenset(
        ["crawler_count", "scheduled_crawler_count", "job_count", "high_capacity_job_count", "job_run_count", "failed_job_run_count", "high_dpu_job_run_count"]
    ),
    SAGEMAKER: frozenset(
        [
            "notebook_count",
            "running_notebook_count",
            "endpoint_count",
            "in_service_endpoint_count",
            "training_job_count",
            "processing_job_count",
            "transform_job_count",
        ]
    ),
    GATEWAY: frozenset(
        ["rest_api_count", "http_api_count", "websocket_api_count", "vpc_link_count", "cache_enabled_stage_count", "observability_stage_setting_count"]
    ),
    ATHENA: frozenset(["workgroup_count", "unbounded_workgroup_count", "enforced_workgroup_count", "data_catalog_count", "query_execution_count"]),
    BEDROCK: frozenset(
        ["foundation_model_count", "custom_model_count", "provisioned_throughput_count", "inference_profile_count", "agent_count", "knowledge_base_count"]
    ),
}
LABELS: dict[str, str] = {GATEWAY: "stage", ATHENA: "workgroup, data catalog, or query execution", BEDROCK: "account resource or regional catalogue signal"}
LABELS.update({GLUE: "crawler, job, or job run", SAGEMAKER: "notebook, endpoint, or job"})
LABELS.update({OPENSEARCH: "domain", REDSHIFT: "cluster or serverless workgroup"})
GLUE_CONFIG_KEYS = [GLUE + ".max_job_run_jobs", GLUE + ".max_job_runs_per_job"]
CONFIG_KEY = GATEWAY + ".vpc_link_detail_mode"
CONFIG_KEYS = [ATHENA + ".max_query_execution_workgroups", ATHENA + ".max_query_executions_per_workgroup"]
EXECUTION = frozenset(
    [
        "note_type",
        "scanner_id",
        "scope_area",
        "summary",
        "regions_attempted",
        "region_record_count",
        "resource_label",
        "resource_count",
        "detail_counts",
        "permission_error_count",
        "result_scope",
        "impact",
    ]
)
ROOTS: dict[tuple[str, str], frozenset[str]] = {
    (GATEWAY, "execution_detail"): EXECUTION | {"cost_context_record_count"},
    (ATHENA, "execution_detail"): EXECUTION | {"billing_context_record_count"},
    (BEDROCK, "execution_detail"): EXECUTION | {"billing_context_record_count"},
    (GATEWAY, "configuration_limit"): frozenset(["note_type", "scope_area", "summary", "configured_value", "config_key", "result_scope", "impact"]),
    (ATHENA, "configuration_limit"): frozenset(
        [
            "scanner_id",
            "note_type",
            "scope_area",
            "region",
            "summary",
            "reason",
            "config_keys",
            "workgroups_checked",
            "workgroup_count",
            "query_execution_count",
        ]
    ),
    (BEDROCK, "service_coverage"): frozenset(["note_type", "scanner_id", "scope_area", "operation_limitations", "impact"]),
}


ROOTS[(OPENSEARCH, "execution_detail")] = EXECUTION | {"cost_context_record_count"}
ROOTS[(REDSHIFT, "execution_detail")] = EXECUTION | {"cost_context_record_count"}
ROOTS[(GLUE, "execution_detail")] = EXECUTION | {"billing_context_record_count"}
ROOTS[(SAGEMAKER, "execution_detail")] = EXECUTION | {"billing_context_record_count"}
ROOTS[(GLUE, "configuration_limit")] = (ROOTS[(ATHENA, "configuration_limit")] - {"workgroups_checked", "workgroup_count", "query_execution_count"}) | {
    "jobs_checked",
    "job_count",
    "job_run_count",
}


class InventoryNoteContract(AuditNoteContract):
    """Bind each finite callback shape to its actual originating wrapper."""

    fields: ClassVar[dict[str, tuple[str, str, bool]]] = {
        "": ("object", "safe_metadata", False),
        **fields("note_type scanner_id scope_area resource_label result_scope configured_value config_key", "note_literal"),
        **fields("summary reason impact", "string", "free_text"),
        **fields("regions_attempted config_keys operation_limitations", "array"),
        **fields("regions_attempted[] region operation_limitations[].region", "string", "region"),
        **fields("config_keys[] operation_limitations[].status operation_limitations[].error_classification", "note_literal"),
        **fields("detail_counts operation_limitations[]", "object"),
        **fields("operation_limitations[].api_action", "note_literal"),
        **fields("operation_limitations[].error_code", "capability_code", nullable=True),
        **fields(
            "region_record_count resource_count cost_context_record_count billing_context_record_count "
            "permission_error_count workgroups_checked workgroup_count query_execution_count jobs_checked job_count job_run_count",
            "count",
            "summary_count",
        ),
        **fields(" ".join("detail_counts." + key for key in sorted(set.union(*(set(keys) for keys in DETAILS.values())))), "count", "summary_count"),
    }

    def __init__(self, scanner: str, kind: str) -> None:
        """Select an exact emitted root shape; never merge schemas at admission."""
        super().__init__(scanner)
        self.kind = kind

    @classmethod
    def for_note(cls, value: dict[str, Any], *, scanner_id: str | None = None) -> InventoryNoteContract | None:
        """Recognize finite child identities and reject a conflicting parent scanner."""
        scanner = value.get("scanner_id")
        if value.get("config_key") == CONFIG_KEY or value.get("scope_area") == "api_gateway_vpc_links":
            scanner = GATEWAY
        if not isinstance(scanner, str) or scanner not in SCANNERS:
            return None
        if scanner_id is not None and scanner_id != scanner:
            message = "Inventory callback conflicts with its originating scanner identity."
            raise ValueError(message)
        kind = value.get("note_type")
        return cls(scanner, kind if isinstance(kind, str) else "unsupported")

    def unknown_paths(self, value: Any, member: str, suffix: str = "") -> list[str]:  # noqa: ANN401
        """Reject missing, foreign-shape, nullable, malformed and unknown descendants."""
        failures = ClosedProducerContract.unknown_paths(self, value, member, suffix)
        path = member + self.prefix[1:] + ("." + suffix if suffix else "")
        if isinstance(value, dict):
            keys = self._keys(suffix)
            if keys is not None and set(value) != keys:
                failures.extend(path + "." + key for key in sorted(set(value) ^ keys))
        if suffix == "operation_limitations[]" and isinstance(value, dict):
            capability = {key: child for key, child in value.items() if key != "region"}
            if not BedrockPrivacyContract().admitted_operation_limitation(capability):
                failures.append(path + ".capability_contract")
        if suffix == "detail_counts" and self.scanner == GLUE and isinstance(value, dict):
            base = DETAILS[GLUE] - {"high_capacity_job_count", "high_dpu_job_run_count"}
            if set(value) not in (base, DETAILS[GLUE]):
                failures.append(path)
        if suffix == "config_keys" and value != (GLUE_CONFIG_KEYS if self.scanner == GLUE else CONFIG_KEYS):
            failures.append(path)
        spec = self.fields.get(suffix)
        if spec is not None and spec[0] == "note_literal" and not self.is_literal(suffix, value):
            failures.append(path)
        return failures

    def _keys(self, suffix: str) -> frozenset[str] | None:
        if not suffix:
            return ROOTS.get((self.scanner, self.kind), frozenset({"unsupported_note_kind"}))
        if suffix == "detail_counts":
            return None if self.scanner == GLUE else DETAILS[self.scanner]
        if suffix == "operation_limitations[]":
            return frozenset({"region", "api_action", "status", "error_classification", "error_code"})
        return None

    @classmethod
    def _valid(cls, value: object, kind: str, *, nullable: bool) -> bool:
        if kind == "capability_code":
            return is_capability_value(value, kind, nullable=nullable)
        return super()._valid(value, kind, nullable=nullable)

    def is_literal(self, suffix: str, value: object) -> bool:
        """Preserve only the exact selected note's closed control vocabulary."""
        if not isinstance(value, str):
            return False
        scope = "managed_platform_metadata" if self.scanner in MANAGED else "analytics_ai_metadata"
        if self.kind == "configuration_limit" and self.scanner == GATEWAY:
            scope = "api_gateway_vpc_links"
        if self.kind == "service_coverage":
            scope = "bedrock_operation_capability"
        literals = {
            "note_type": {self.kind} if (self.scanner, self.kind) in ROOTS else set(),
            "scanner_id": {self.scanner},
            "scope_area": {scope},
            "resource_label": {LABELS[self.scanner]},
            "result_scope": {"current_scan" if self.scanner in MANAGED else "metadata_with_optional_billing_context"},
            "configured_value": {"summary"},
            "config_key": {CONFIG_KEY},
            "config_keys[]": set(GLUE_CONFIG_KEYS if self.scanner == GLUE else CONFIG_KEYS),
            "operation_limitations[].api_action": CAPABILITY_VOCABULARIES["capability_action"],
            "operation_limitations[].error_code": CAPABILITY_VOCABULARIES["capability_code"],
            "operation_limitations[].status": CAPABILITY_VOCABULARIES["capability_status"],
            "operation_limitations[].error_classification": {"unsupported_operation"},
        }
        return value in literals.get(suffix, set())


def unknown_inventory_notes(value: object, member: str) -> list[str]:
    """Preflight child and parent identities before any strict note transformation."""
    if member != "scan-result/scanner-results.json" or not isinstance(value, dict) or not isinstance(value.get("scanner_results"), list):
        return []
    failures = []
    for row in value["scanner_results"]:
        if not isinstance(row, dict) or not isinstance(row.get("coverage_notes"), list):
            continue
        for note in row["coverage_notes"]:
            if not isinstance(note, dict):
                continue
            try:
                contract = InventoryNoteContract.for_note(note, scanner_id=str(row.get("scanner_id")))
            except ValueError:
                failures.append(member + ".scanner_results[].coverage_notes[].identity")
                continue
            if contract is not None:
                failures.extend(contract.unknown_paths(note, member))
            elif row.get("scanner_id") in SCANNERS:
                failures.append(member + ".scanner_results[].coverage_notes[].scope")
    return failures
