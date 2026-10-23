"""Closed AWS Backup inventory union with exact producer identities and field roles."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from functools import lru_cache
from typing import TYPE_CHECKING, Any, ClassVar

from botocore.loaders import Loader

from unio_collector.privacy.audit.contract import AuditPrivacyContract
from unio_collector.privacy.backup.fields import FIELDS, PLAN, POINT, RULE, RULE_PATH, SCANNER, SELECTION, SELECTION_PATH, VAULT
from unio_collector.privacy.closed_schema import PREFIX
from unio_collector.privacy.leak.public.temporal import MONTH_PRECISION_LENGTH, TemporalScanPolicy

if TYPE_CHECKING:
    from unio_collector.privacy.treatment_decision import PrivacyTreatmentDecision


@lru_cache(maxsize=1)
def backup_statuses() -> frozenset[str]:
    """Read only the pinned local SDK's finite recovery point status vocabulary."""
    model = Loader().load_service_model("backup", "service-2")
    shape = model["shapes"]["RecoveryPointByBackupVault"]["members"]["Status"]["shape"]
    return frozenset(model["shapes"][shape]["enum"])


class BackupPrivacyContract(AuditPrivacyContract):
    """Unknown union members, conditions, nulls and conflicting DTO shapes fail closed."""

    scanner_id: ClassVar[str] = SCANNER
    identities: ClassVar = {SCANNER: ("inventory_evidence", "InventoryEvidence", {})}
    fields: ClassVar[dict[str, tuple[str, str, bool]]] = FIELDS

    @classmethod
    def _valid(cls, value: object, kind: str, *, nullable: bool) -> bool:
        """Validate declared tag maps, integers and finite Backup control values."""
        if value is None:
            return nullable
        if kind == "string_map":
            return isinstance(value, dict) and all(isinstance(key, str) and isinstance(child, str) for key, child in value.items())
        if kind == "integer":
            return type(value) is int
        if kind == "positive":
            return type(value) is int and value > 0
        if kind == "detail_mode":
            return isinstance(value, str) and value in {"full", "summary"}
        if kind == "condition_type":
            return value == "STRINGEQUALS"
        return super()._valid(value, kind, nullable=nullable)

    @staticmethod
    def record_fields(value: dict[str, Any]) -> frozenset[str]:
        """Identify only actual complete DTO discriminants, never generated prose."""
        if "recovery_point_arn" in value:
            return POINT
        if "backup_plan_id" in value:
            return PLAN
        return VAULT if "backup_vault_name" in value else frozenset()

    def unknown_paths(self, value: Any, member: str, suffix: str = "") -> list[str]:  # noqa: ANN401
        """Check exact DTO key sets, declared defaults and typed protected tags."""
        path = member + PREFIX[1:] + ("." + suffix if suffix else "")
        if suffix == "records[].tags":
            return [] if self._valid(value, "string_map", nullable=False) else [path]
        failures = super().unknown_paths(value, member, suffix)
        if isinstance(value, dict):
            expected = (
                self.record_fields(value)
                if suffix == "records[]"
                else RULE
                if suffix == RULE_PATH
                else SELECTION
                if suffix == SELECTION_PATH
                else frozenset({"ConditionKey", "ConditionValue"})
                if suffix.startswith(SELECTION_PATH + ".conditions.") and suffix.endswith("[]")
                else frozenset({"ConditionType", "ConditionKey", "ConditionValue"})
                if suffix == SELECTION_PATH + ".list_of_tags[]"
                else None
            )
            if expected is not None:
                defaults = {"tags_collected"} if suffix == "records[]" and expected in (PLAN, VAULT) else set()
                if not expected or not (expected - defaults).issubset(value) or not set(value).issubset(expected):
                    failures.append(path)
        return failures

    def mapping_key_category(self, path: str) -> str | None:
        """Use the existing tag-key policy only for the exact declared tag map."""
        return "tag_key" if path == PREFIX + ".records[].tags" else None

    def resolve(self, path: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Protect arbitrary tag values whole; fixed map shape remains independently checked."""
        if path.startswith(PREFIX + ".records[].tags."):
            decision = super().resolve(PREFIX + ".records[].backup_plan_name", profile)
            return replace(decision, category="tag_value") if decision is not None else None
        return super().resolve(path, profile)

    def is_literal(self, suffix: str, value: object) -> bool:
        """Only exact fixed controls, public status codes and resource selectors stay public."""
        if not isinstance(value, str):
            return False
        return (
            (suffix == "metadata.selection_detail_mode" and value in {"full", "summary"})
            or (suffix == "records[].status" and isinstance(value, str) and value in backup_statuses())
            or (suffix == SELECTION_PATH + ".list_of_tags[].ConditionType" and value == "STRINGEQUALS")
            or (suffix in {SELECTION_PATH + ".resources[]", SELECTION_PATH + ".not_resources[]"} and value == "*")
        )

    def resolve_string(self, path: str, value: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Retain finite controls only at the current identity-selected producer role."""
        decision = self.resolve(path, profile)
        return (
            replace(decision, treatment="preserve", category="safe_metadata")
            if decision is not None and self.is_literal(path.removeprefix(PREFIX + "."), value)
            else decision
        )

    def admitted_scan_record(self, value: object) -> bool:
        """Validate strict-month timestamps in a separate view without accepting them as raw source."""
        if not isinstance(value, dict):
            return False
        checked = deepcopy(value)
        containers = [checked, *checked.get("selections", [])] if isinstance(checked.get("selections", []), list) else [checked]
        for container in containers:
            if not isinstance(container, dict):
                return False
            for key in ("creation_date", "completion_date", "calculated_delete_at", "last_execution_date"):
                instant = container.get(key)
                if isinstance(instant, str) and len(instant) == MONTH_PRECISION_LENGTH and TemporalScanPolicy.timestamp(instant):
                    container[key] = instant + "-01"
        return not self.unknown_paths(checked, "", "records[]")
