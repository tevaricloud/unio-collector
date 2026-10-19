"""Explicit typed SDK billing evidence without fallback or provider imports."""

from __future__ import annotations

from dataclasses import replace
from typing import Any, ClassVar, Self

from unio_collector.collector.protocol import UNIO_PROTOCOL
from unio_collector.privacy.billing import alarm, anomaly, budgets
from unio_collector.privacy.billing.index import BillingFieldIndex
from unio_collector.privacy.billing.value import valid_shape
from unio_collector.privacy.closed_schema import PREFIX, ClosedProducerContract
from unio_collector.privacy.treatment_decision import PrivacyTreatmentDecision
from unio_collector.scanners.scanner.schema import admit_evidence_schema


class BillingPrivacyContract(ClosedProducerContract):
    """Admit only the registered billing DTO and its explicit nested SDK graph."""

    scanner_id: ClassVar[str] = "billing-alerts-and-budgets-review"
    schemas: ClassVar[dict[str, dict[str, Any]]] = {
        **{"budgets:" + k: v for k, v in budgets.SHAPES.items()},
        **{"ce:" + k: v for k, v in anomaly.SHAPES.items()},
        **{"cloudwatch:" + k: v for k, v in alarm.SHAPES.items()},
        "payload": {
            "kind": "structure",
            "members": {
                "account_id": ("text", "aws_account_id"),
                "budgets": ("budget_rows", "safe_metadata"),
                "anomaly_monitors": ("monitors", "safe_metadata"),
                "anomaly_subscriptions": ("subscriptions", "safe_metadata"),
                "billing_alarms": ("alarms", "safe_metadata"),
                "permission_errors": ("diagnostics", "safe_metadata"),
            },
            "required": ["account_id", "budgets", "anomaly_monitors", "anomaly_subscriptions", "billing_alarms", "permission_errors"],
        },
        "budget_rows": {"kind": "list", "member": "budget_row"},
        "budget_row": {
            "kind": "structure",
            "members": {
                "budget": ("budgets:Budget", "safe_metadata"),
                "notifications": ("notifications", "safe_metadata"),
                "notification_details": ("details", "safe_metadata"),
            },
            "required": ["budget", "notifications"],
        },
        "notifications": {"kind": "list", "member": "budgets:Notification"},
        "details": {"kind": "list", "member": "detail"},
        "detail": {
            "kind": "structure",
            "members": {"notification": ("budgets:Notification", "safe_metadata"), "subscriber_count": ("count", "summary_count")},
            "required": ["notification", "subscriber_count"],
        },
        "monitors": {"kind": "list", "member": "ce:AnomalyMonitor"},
        "subscriptions": {"kind": "list", "member": "ce:AnomalySubscription"},
        "alarms": {"kind": "list", "member": "cloudwatch:MetricAlarm"},
        "diagnostics": {"kind": "list", "member": "text", "category": "free_text"},
        "text": {"kind": "string"},
        "count": {"kind": "integer", "minimum": 0},
    }

    @classmethod
    def for_record(cls, record: dict[str, Any]) -> Self | None:
        """Bind the actual AWS dataclass wire identity in either import namespace."""
        if record.get("scanner_id") != cls.scanner_id:
            return None
        if (
            admit_evidence_schema(record) is not None
            or record.get("provider_id", "aws") != "aws"
            or record.get("evidence_type") != "BillingGuardrailRecord"
            or record.get("evidence_module") not in {n + ".aws.billing_guardrails.record" for n in UNIO_PROTOCOL.accepted_import_namespaces}
        ):
            message = "Billing privacy requires its matching registered AWS evidence identity."
            raise ValueError(message)
        return cls()

    def spec(self, suffix: str) -> tuple[dict[str, Any], str] | None:
        """Traverse only declared fields; recursion follows the exact Expression schema."""
        node = self.schemas["payload"]
        category = "safe_metadata"
        namespace = ""
        segments = suffix.replace("[]", ".[]").split(".") if suffix else []
        for segment in segments:
            if node["kind"] == "structure":
                edge = node["members"].get(segment)
                if edge is None:
                    return None
                name, category = edge
            elif node["kind"] == "list" and segment == "[]":
                name = node["member"]
                category = node.get("category", category)
            elif node["kind"] == "map" and segment and not any(c in segment for c in "[]"):
                if node["member"] == "Spend" and (not segment.isascii() or not segment.isdecimal()):
                    return None
                name = node["member"]
                category = "free_text" if name == "Values" else category
            else:
                return None
            if ":" in name:
                namespace = name.split(":", 1)[0]
            key = name if name in self.schemas else namespace + ":" + name
            node = self.schemas[key]
        if node["kind"] in {"structure", "list", "map"}:
            category = "safe_metadata"
        return node, category

    def unknown_paths(self, value: object, member: str, suffix: str = "") -> list[str]:
        """Reject unknown, nullable, malformed and missing-required SDK shapes early."""
        found = self.spec(suffix)
        path = member + PREFIX[1:] + ("." + suffix if suffix else "")
        if found is None or not self.valid(value, found[0]):
            return [path]
        if isinstance(value, dict):
            failures = []
            for key, child in value.items():
                child_suffix = suffix + ("." if suffix else "") + key
                if any(c in key for c in ".[]"):
                    failures.append(member + PREFIX[1:] + "." + child_suffix)
                else:
                    failures.extend(self.unknown_paths(child, member, child_suffix))
            return failures
        if isinstance(value, list):
            return [p for child in value for p in self.unknown_paths(child, member, suffix + "[]")]
        return []

    @staticmethod
    def valid(value: object, node: dict[str, Any]) -> bool:
        """Validate before profile omission using the pinned SDK primitive contract."""
        return valid_shape(value, node)

    def resolve(self, path: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Protect every identifier/free string; strict removes declared financial values."""
        if path != PREFIX and not path.startswith((PREFIX + ".", PREFIX + "[")):
            return None
        suffix = path[len(PREFIX) :].removeprefix(".")
        spec = self.spec(suffix)
        if spec is None:
            return super().resolve(path, profile)
        node, category = spec
        if category == "cost" and node["kind"] in {"double", "float", "string"}:
            treatment = "remove" if profile == "strict" else "preserve"
        elif category == "timestamp":
            treatment = "generalise" if profile == "strict" else "preserve"
        elif category in {"free_text", "aws_account_id", "arn", "resource_id", "resource_name"}:
            treatment = "tokenise"
        else:
            treatment = "preserve"
        return PrivacyTreatmentDecision(
            treatment=treatment,
            category=category,
            canonicaliser_id=None,
            canonicaliser_version=None,
            fallback_allowed=False,
            decision_source="exact_json_path",
            reason="Exact identity-bound SDK billing schema; no unknown-field fallback.",
        )

    def mapping_key_category(self, path: str) -> str | None:
        """Protect arbitrary keys only in the two exact SDK budget maps."""
        spec = self.spec(path.removeprefix(PREFIX + "."))
        return "resource_id" if spec is not None and spec[0]["kind"] == "map" else None

    def is_literal(self, suffix: str, value: object) -> bool:
        """Only exact typed finite SDK controls and operational counts have public views."""
        spec = self.spec(suffix)
        return (
            spec is not None
            and spec[1] in {"safe_metadata", "summary_count"}
            and self.valid(value, spec[0])
            and (bool(spec[0].get("enum")) or type(value) in {int, bool})
        )

    def resolve_string(self, path: str, value: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Preserve only two exact billing metric constants, not arbitrary namespace text."""
        decision = self.resolve(path, profile)
        suffix = path.removeprefix(PREFIX + ".")
        if self.metric_literal(suffix, value) and decision is not None:
            return replace(decision, treatment="preserve", category="safe_metadata")
        return decision

    def metric_literal(self, suffix: str, value: object) -> bool:
        """Check actual typed fields in the closed billing alarm graph."""
        return (
            self.spec(suffix) is not None
            and suffix.startswith("billing_alarms[].")
            and ((suffix.endswith(".Namespace") and value == "AWS/Billing") or (suffix.endswith(".MetricName") and value == "EstimatedCharges"))
        )

    def preserves_mapping_key(self, path: str, key: str) -> bool:
        """Only five SDK-documented legacy budget filter dimension names are fixed keys."""
        return path == PREFIX + ".budgets[].budget.CostFilters" and key in {"Region", "Service", "LinkedAccount", "Tag", "CostCategory"}

    def diagnostic_prefix(self, path: str, value: str) -> str | None:
        """Retain exact legacy operation labels required by offline limitation analysis."""
        if path != PREFIX + ".permission_errors[]":
            return None
        prefixes = (
            "budgets:describe_budgets:",
            "budgets:describe_notifications_for_budget:",
            "budgets:describe_subscribers_for_notification:",
            "ce:get_anomaly_monitors:",
            "ce:get_anomaly_subscriptions:",
            "cloudwatch:describe_alarms:",
        )
        return next((prefix for prefix in prefixes if value.startswith(prefix)), None)


BillingPrivacyContract.fields = BillingFieldIndex(BillingPrivacyContract().spec)
