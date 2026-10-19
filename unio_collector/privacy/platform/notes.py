"""Closed actual ECS/EKS/ElastiCache execution and configuration callback notes."""

from __future__ import annotations

from typing import Any, ClassVar

from unio_collector.privacy.audit.notes import AuditNoteContract
from unio_collector.privacy.closed_schema import ClosedProducerContract
from unio_collector.privacy.inventory_notes import EXECUTION
from unio_collector.privacy.s3.fields import fields

ECS = "ecs-cost-governance-review"
EKS = "eks-cost-risk-review"
CACHE = "elasticache-cost-review"
SCANNERS = frozenset({ECS, EKS, CACHE})
DETAILS = {
    ECS: frozenset(
        ["cluster_count", "desired_task_count", "running_task_count", "fargate_service_count", "service_without_running_tasks_count", "untagged_service_count"]
    ),
    EKS: frozenset(["nodegroup_count", "fargate_profile_count", "public_endpoint_cluster_count", "untagged_cluster_count"]),
    CACHE: frozenset(
        ["replication_group_count", "total_node_count", "metric_observation_count", "low_activity_cluster_count", "capacity_pressure_cluster_count"]
    ),
}
LABELS = {ECS: "service", EKS: "cluster", CACHE: "cache cluster"}
CONFIGS = {
    "ecs_task_definitions": (ECS, ECS + ".task_definition_detail_mode", "summary"),
    "ecs_regional_collection": (ECS, ECS + ".regional_collection_mode", "billing-active"),
    "elasticache_cloudwatch_metrics": (CACHE, CACHE + ".metric_detail_mode", "summary"),
}
CONFIG_KEYS = frozenset(["note_type", "scope_area", "summary", "configured_value", "config_key", "result_scope", "impact"])
REGION_KEYS = frozenset(["attempted_region_count", "collection_region_count", "skipped_region_count", "collection_regions", "skipped_regions"])


class ManagedNoteContract(AuditNoteContract):
    """Bind each finite note shape and conditional scope to its originating wrapper."""

    fields: ClassVar[dict[str, tuple[str, str, bool]]] = {
        "": ("object", "safe_metadata", False),
        **fields("note_type scanner_id scope_area configured_value config_key result_scope resource_label", "note_literal"),
        **fields("summary impact", "string", "free_text"),
        **fields("regions_attempted collection_regions skipped_regions", "array"),
        **fields("regions_attempted[] collection_regions[] skipped_regions[]", "string", "region"),
        **fields("detail_counts", "object"),
        **fields(
            "region_record_count resource_count cost_context_record_count permission_error_count "
            "attempted_region_count collection_region_count skipped_region_count",
            "count",
            "summary_count",
        ),
        **fields(" ".join("detail_counts." + key for key in sorted(set.union(*(set(keys) for keys in DETAILS.values())))), "count", "summary_count"),
    }

    def __init__(self, scanner: str, kind: str, scope: str) -> None:
        """Retain exact caller-bound kind/scope, never infer behavior from prose."""
        super().__init__(scanner)
        self.kind = kind
        self.scope = scope

    @classmethod
    def for_note(cls, value: dict[str, Any], *, scanner_id: str | None = None) -> ManagedNoteContract | None:
        """Recognize actual owner identities and reject a conflicting parent scanner."""
        scanner = value.get("scanner_id")
        scope = value.get("scope_area")
        config = CONFIGS.get(scope) if isinstance(scope, str) else None
        if config is not None:
            scanner = config[0]
        if not isinstance(scanner, str) or scanner not in SCANNERS:
            return None
        if scanner_id is not None and scanner_id != scanner:
            message = "Managed callback conflicts with its originating scanner identity."
            raise ValueError(message)
        return cls(scanner, str(value.get("note_type")), str(scope))

    def _keys(self, suffix: str) -> frozenset[str] | None:
        if not suffix:
            if self.kind == "execution_detail" and self.scope == "managed_platform_metadata":
                return EXECUTION | {"cost_context_record_count"}
            if self.kind == "configuration_limit" and self.scope in CONFIGS and CONFIGS[self.scope][0] == self.scanner:
                return CONFIG_KEYS | REGION_KEYS if self.scope == "ecs_regional_collection" else CONFIG_KEYS
            return frozenset({"unsupported_note_shape"})
        return DETAILS[self.scanner] if suffix == "detail_counts" else None

    def unknown_paths(self, value: Any, member: str, suffix: str = "") -> list[str]:  # noqa: ANN401
        """Require complete emitted containers and consistent finite regional scope."""
        failures = ClosedProducerContract.unknown_paths(self, value, member, suffix)
        path = member + self.prefix[1:] + ("." + suffix if suffix else "")
        if isinstance(value, dict):
            keys = self._keys(suffix)
            if keys is not None and set(value) != keys:
                failures.extend(path + "." + key for key in sorted(set(value) ^ keys))
            if not suffix and self.scope == "ecs_regional_collection" and not failures:
                collected, skipped = value["collection_regions"], value["skipped_regions"]
                if (
                    len(collected) != value["collection_region_count"]
                    or len(skipped) != value["skipped_region_count"]
                    or value["attempted_region_count"] != len(collected) + len(skipped)
                    or len(set(collected)) != len(collected)
                    or len(set(skipped)) != len(skipped)
                    or set(collected) & set(skipped)
                ):
                    failures.append(path + ".regional_scope")
        spec = self.fields.get(suffix)
        if spec is not None and spec[0] == "note_literal" and not self.is_literal(suffix, value):
            failures.append(path)
        return failures

    def is_literal(self, suffix: str, value: object) -> bool:
        """Normalize only this admitted scope's exact public control positions."""
        if not isinstance(value, str):
            return False
        config = CONFIGS.get(self.scope)
        literals = {
            "note_type": {self.kind} if self._keys("") != frozenset({"unsupported_note_shape"}) else set(),
            "scanner_id": {self.scanner},
            "scope_area": {self.scope} if self._keys("") != frozenset({"unsupported_note_shape"}) else set(),
            "resource_label": {LABELS[self.scanner]},
            "result_scope": {"current_scan"},
            "configured_value": {config[2]} if config is not None else set(),
            "config_key": {config[1]} if config is not None else set(),
        }
        return value in literals.get(suffix, set())


def unknown_managed_notes(value: object, member: str) -> list[str]:
    """Preflight originating identities, malformed containers and unknown notes."""
    if member != "scan-result/scanner-results.json" or not isinstance(value, dict) or not isinstance(value.get("scanner_results"), list):
        return []
    failures = []
    prefix = member + ".scanner_results[].coverage_notes"
    for row in value["scanner_results"]:
        if not isinstance(row, dict):
            continue
        notes = row.get("coverage_notes")
        if not isinstance(notes, list):
            if row.get("scanner_id") in SCANNERS:
                failures.append(prefix)
            continue
        for note in notes:
            failures.extend(_unknown_note(row, note, member, prefix))
    return failures


def _unknown_note(row: dict[str, Any], note: object, member: str, prefix: str) -> list[str]:
    """Check one callback while retaining its parent binding and malformed values."""
    if not isinstance(note, dict):
        return [prefix + "[]"] if row.get("scanner_id") in SCANNERS else []
    try:
        contract = ManagedNoteContract.for_note(note, scanner_id=str(row.get("scanner_id")))
    except ValueError:
        return [prefix + "[].identity"]
    if contract is not None:
        return contract.unknown_paths(note, member)
    return [prefix + "[].scope"] if row.get("scanner_id") in SCANNERS else []
