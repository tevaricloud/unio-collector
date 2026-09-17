from __future__ import annotations  # noqa: D100

import json
from typing import TYPE_CHECKING, Any

from unio_collector.evidence.permission.summary import PermissionCategory, PermissionSummary
from unio_collector.scanners.registry.catalog import get_scanner
from unio_collector.scanners.scanner.permission_summary import ScannerPermissionSummary

if TYPE_CHECKING:
    from datetime import datetime
    from pathlib import Path

    from unio_collector.scanners.scanner.result import ScannerExecutionResult

PERMISSION_ERROR_MARKERS = frozenset(
    {
        "accessdenied",
        "unauthorized",
        "unrecognizedclient",
        "invalidclienttoken",
    },
)

ACTION_ALIASES: dict[str, tuple[str, ...]] = {
    "s3:ListBuckets": ("s3:ListAllMyBuckets",),
    "s3:ListAllMyBuckets": ("s3:ListBuckets",),
    "s3:GetLifecycleConfiguration": ("s3:GetBucketLifecycleConfiguration",),
    "s3:GetBucketLifecycleConfiguration": ("s3:GetLifecycleConfiguration",),
    "s3:GetReplicationConfiguration": ("s3:GetBucketReplication",),
    "s3:GetBucketReplication": ("s3:GetReplicationConfiguration",),
    "s3:ListBucketMultipartUploads": ("s3:ListMultipartUploads",),
    "s3:ListMultipartUploads": ("s3:ListBucketMultipartUploads",),
    "s3:GetBucketNotificationConfiguration": ("s3:GetBucketNotification",),
    "s3:GetBucketNotification": ("s3:GetBucketNotificationConfiguration",),
    "elbv2:DescribeLoadBalancers": ("elasticloadbalancing:DescribeLoadBalancers",),
    "elasticloadbalancing:DescribeLoadBalancers": ("elbv2:DescribeLoadBalancers",),
    "elbv2:DescribeTags": ("elasticloadbalancing:DescribeTags",),
    "elasticloadbalancing:DescribeTags": ("elbv2:DescribeTags",),
    "elbv2:DescribeTargetGroups": ("elasticloadbalancing:DescribeTargetGroups",),
    "elasticloadbalancing:DescribeTargetGroups": ("elbv2:DescribeTargetGroups",),
    "elbv2:DescribeTargetHealth": ("elasticloadbalancing:DescribeTargetHealth",),
    "elasticloadbalancing:DescribeTargetHealth": ("elbv2:DescribeTargetHealth",),
    "apigateway:GET": (
        "apigateway:GetRestApis",
        "apigateway:GetStages",
        "apigatewayv2:GetApis",
        "apigatewayv2:GetStages",
    ),
    "apigateway:GetRestApis": ("apigateway:GET",),
    "apigateway:GetStages": ("apigateway:GET",),
    "apigatewayv2:GetApis": ("apigateway:GET",),
    "apigatewayv2:GetStages": ("apigateway:GET",),
    "es:ListDomainNames": ("opensearch:ListDomainNames",),
    "opensearch:ListDomainNames": ("es:ListDomainNames",),
    "es:DescribeDomains": ("opensearch:DescribeDomains",),
    "opensearch:DescribeDomains": ("es:DescribeDomains",),
    "bedrock:ListKnowledgeBases": ("bedrock-agent:ListKnowledgeBases",),
    "bedrock-agent:ListKnowledgeBases": ("bedrock:ListKnowledgeBases",),
}


class PermissionSummaryBuilder:  # noqa: D101
    def build(  # noqa: D102
        self,
        *,
        generated_at: datetime,
        profile_name: str | None,
        mode: str,
        caller_identity: dict[str, Any],
        scanner_results: list[ScannerExecutionResult],
        ledger: Any,  # noqa: ANN401
    ) -> PermissionSummary:
        available_actions = self._collect_available_actions(ledger)
        missing_actions = self._collect_missing_actions(ledger)
        service_unavailable_actions = self._collect_service_unavailable_actions(ledger)
        write_actions_observed = self._collect_write_actions(ledger)
        scanner_permissions = [
            self._build_scanner_permission_summary(
                result=result,
                available_actions=set(available_actions),
                missing_actions=set(missing_actions),
                service_unavailable_actions=set(service_unavailable_actions),
            )
            for result in scanner_results
        ]
        not_attempted_actions = sorted(
            {action for summary in scanner_permissions for action in summary.not_attempted_actions},
        )
        not_attempted_conditional_actions = sorted(
            {action for summary in scanner_permissions for action in summary.not_attempted_conditional_actions},
        )
        unknown_actions = sorted(
            {action for summary in scanner_permissions for action in summary.unknown_actions},
        )

        return PermissionSummary(
            generated_at=generated_at.isoformat(),
            profile_name=profile_name,
            mode=mode,
            category=self._categorize(
                available_actions,
                missing_actions,
                write_actions_observed,
            ),
            assessment_method="observed_unio_collector_api_calls",
            caller_identity=caller_identity,
            account_id=str(caller_identity.get("account_id") or "unknown-account"),
            available_actions=available_actions,
            missing_actions=missing_actions,
            service_unavailable_actions=service_unavailable_actions,
            not_attempted_actions=not_attempted_actions,
            not_attempted_conditional_actions=not_attempted_conditional_actions,
            unknown_actions=unknown_actions,
            write_actions_observed=write_actions_observed,
            scanner_permissions=scanner_permissions,
            permission_failures=ledger.get_permission_failures(),
            limitations=[
                "This is a Unio Collector capability check, not a security audit.",
                (
                    "Actions are marked available when Unio Collector observed a "
                    "successful API call or a handled no-data/no-resource "
                    "response that proves the read API was reachable."
                ),
                ("Actions are marked missing only when Unio Collector observed a permission-denied API call."),
                ("Actions marked service-unavailable indicate the target AWS service or feature was not enabled or not opted in."),
                (
                    "Actions marked not-attempted were declared by scanners but "
                    "were not needed during this scan path, usually because no "
                    "matching resources required follow-up API calls."
                ),
                (
                    "Unknown actions are declared scanner actions that were "
                    "neither observed, denied, service-unavailable, nor explainable "
                    "as not attempted by a completed scanner."
                ),
                "Authoritative permission review should be performed in AWS IAM and CloudTrail.",
            ],
        )

    def write_json(self, path: Path, summary: PermissionSummary) -> None:  # noqa: D102
        path.write_text(
            json.dumps(summary.convert_to_dict(), indent=2, sort_keys=True),
            encoding="utf-8",
        )

    def _collect_available_actions(self, ledger: Any) -> list[str]:  # noqa: ANN401
        actions = {record.get("unio", {}).get("declared_api_call") for record in ledger.records if self._is_available_capability_record(record)}
        return sorted(expand_equivalent_actions(actions))

    def _collect_missing_actions(self, ledger: Any) -> list[str]:  # noqa: ANN401
        actions = {record.get("unio", {}).get("declared_api_call") for record in ledger.records if self._is_permission_denied_record(record)}
        return sorted(expand_equivalent_actions(actions))

    def _collect_service_unavailable_actions(
        self,
        ledger: Any,  # noqa: ANN401
    ) -> list[str]:
        actions = {record.get("unio", {}).get("declared_api_call") for record in ledger.records if self._is_service_unavailable_record(record)}
        return sorted(expand_equivalent_actions(actions))

    def _collect_write_actions(self, ledger: Any) -> list[str]:  # noqa: ANN401
        actions = {record.get("unio", {}).get("declared_api_call") for record in ledger.records if record.get("unio", {}).get("write_operation") is True}
        return sorted(action for action in actions if isinstance(action, str))

    def _categorize(
        self,
        available_actions: list[str],
        missing_actions: list[str],
        write_actions_observed: list[str],
    ) -> PermissionCategory:
        if write_actions_observed:
            return "write_limited"
        if available_actions:
            return "read_only"
        if missing_actions:
            return "unknown"
        return "unknown"

    def _build_scanner_permission_summary(
        self,
        *,
        result: ScannerExecutionResult,
        available_actions: set[str],
        missing_actions: set[str],
        service_unavailable_actions: set[str],
    ) -> ScannerPermissionSummary:
        try:
            definition = get_scanner(result.scanner_id)
            required_actions = set(definition.required_iam_actions)
            conditional_actions = set(definition.conditional_iam_actions)
            required_permission_level = definition.required_permission_level
        except ValueError:
            required_actions = set(result.required_iam_actions)
            conditional_actions = set(result.conditional_iam_actions)
            required_permission_level = result.required_permission_level or "read_only"
        available = {action for action in required_actions if action_has_equivalent(action, available_actions)}
        available_conditional = {action for action in conditional_actions if action_has_equivalent(action, available_actions)}
        missing = {action for action in required_actions if action_has_equivalent(action, missing_actions)}
        missing_conditional = {action for action in conditional_actions if action_has_equivalent(action, missing_actions)}
        service_unavailable = {action for action in required_actions if action_has_equivalent(action, service_unavailable_actions)}
        service_unavailable_conditional = {action for action in conditional_actions if action_has_equivalent(action, service_unavailable_actions)}
        unresolved = required_actions - available - missing - service_unavailable
        unresolved_conditional = conditional_actions - available_conditional - missing_conditional - service_unavailable_conditional
        not_attempted: set[str] = set()
        not_attempted_conditional: set[str] = set()
        unknown = unresolved
        unknown_conditional = unresolved_conditional
        if result.status in {"completed", "completed_with_warnings"}:
            not_attempted = unresolved
            not_attempted_conditional = unresolved_conditional
            unknown = set()
            unknown_conditional = set()
        elif result.status in {"disabled", "skipped"}:
            unknown = set()
            unknown_conditional = set()
        return ScannerPermissionSummary(
            scanner_id=result.scanner_id,
            required_permission_level=required_permission_level,
            required_iam_actions=sorted(required_actions),
            conditional_iam_actions=sorted(conditional_actions),
            available_actions=sorted(available),
            available_conditional_actions=sorted(available_conditional),
            missing_actions=sorted(missing),
            missing_conditional_actions=sorted(missing_conditional),
            service_unavailable_actions=sorted(service_unavailable),
            service_unavailable_conditional_actions=sorted(
                service_unavailable_conditional,
            ),
            not_attempted_actions=sorted(not_attempted),
            not_attempted_conditional_actions=sorted(not_attempted_conditional),
            unknown_actions=sorted(unknown),
            unknown_conditional_actions=sorted(unknown_conditional),
            scanner_status=result.status,
        )

    def _is_permission_denied_record(self, record: dict[str, Any]) -> bool:
        unio = record.get("unio", {})
        if not isinstance(unio, dict):
            unio = {}
        if unio.get("expected_absence"):
            return False
        if unio.get("permission_denied"):
            return True
        return is_permission_error_code(str(record.get("errorCode") or ""))

    def _is_available_capability_record(self, record: dict[str, Any]) -> bool:
        if record.get("errorCode") is None:
            return True
        unio = record.get("unio", {})
        if not isinstance(unio, dict):
            return False
        if unio.get("permission_denied") or unio.get("service_unavailable"):
            return False
        return bool(unio.get("expected_absence"))

    def _is_service_unavailable_record(self, record: dict[str, Any]) -> bool:
        unio = record.get("unio", {})
        if not isinstance(unio, dict):
            return False
        return bool(unio.get("service_unavailable"))


def is_permission_error_code(code: str) -> bool:  # noqa: D103
    normalized = code.lower()
    return any(marker in normalized for marker in PERMISSION_ERROR_MARKERS)


def expand_equivalent_actions(actions: set[object]) -> set[str]:  # noqa: D103
    expanded: set[str] = set()
    for action in actions:
        if not isinstance(action, str):
            continue
        expanded.add(action)
        expanded.update(ACTION_ALIASES.get(action, ()))
    return expanded


def action_has_equivalent(action: str, observed_actions: set[str]) -> bool:  # noqa: D103
    return bool({action, *ACTION_ALIASES.get(action, ())} & observed_actions)
