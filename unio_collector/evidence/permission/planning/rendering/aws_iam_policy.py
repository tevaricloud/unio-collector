from __future__ import annotations  # noqa: D100

import json
from typing import TYPE_CHECKING

from unio_collector.evidence.permission.planning.condition import AwsIamConditionRenderer
from unio_collector.evidence.permission.planning.validation import AwsPermissionPlanValidator

if TYPE_CHECKING:
    from unio_collector.evidence.permission.planning.plan import PermissionPlan
    from unio_collector.evidence.permission.planning.rendering.policy_status import (
        PolicyRenderingStatus,
    )
    from unio_collector.evidence.permission.planning.requirement import (
        PermissionRequirement,
    )


class AwsIamPolicyRenderer:
    """Render read-only AWS IAM policy documents from a permission plan."""

    def render(
        self,
        plan: PermissionPlan,
        *,
        include_conditional_actions: bool = False,
        fail_on_excluded_conditional: bool = False,
    ) -> dict[str, object]:
        """Return a deterministic AWS IAM policy document."""
        AwsPermissionPlanValidator().validate(plan)
        non_required_actions = non_required_iam_actions(plan)
        if fail_on_excluded_conditional and non_required_actions and not include_conditional_actions:
            msg = (
                "IAM policy output would omit conditional or optional-enrichment actions: "
                f"{', '.join(non_required_actions)}. Re-run with "
                "--include-conditional-actions to include them."
            )
            raise ValueError(msg)
        requirements = included_policy_requirements(
            plan,
            include_conditional_actions=include_conditional_actions,
        )
        unresolved = sorted(requirement.api_action for requirement in plan.requirements if requirement.scope_status == "unresolved")
        if unresolved:
            msg = "AWS IAM policy scope is unresolved for: " + ", ".join(unresolved) + ". Use JSON or summary planning output to inspect unresolved variables."
            raise ValueError(msg)
        return {
            "Version": "2012-10-17",
            "Statement": _policy_statements(requirements),
        }


def included_policy_requirements(
    plan: PermissionPlan,
    *,
    include_conditional_actions: bool,
) -> list[PermissionRequirement]:
    """Return requirements included by the rendering option."""
    return [
        requirement
        for requirement in plan.requirements
        if requirement.requirement_type == "required"
        or (include_conditional_actions and requirement.requirement_type in {"conditional", "optional_enrichment"})
    ]


def policy_rendering_status(
    plan: PermissionPlan,
) -> PolicyRenderingStatus:
    """Return deployability for the complete enabled-scanner plan."""
    AwsPermissionPlanValidator().validate(plan)
    unresolved = sorted(requirement.api_action for requirement in plan.requirements if requirement.scope_status == "unresolved")
    contains_wildcard = any(requirement.scope_status == "wildcard_required" for requirement in plan.requirements)
    status = "unresolved_policy_plan" if unresolved else "valid_wildcard_policy" if contains_wildcard else "exact_scoped_policy"
    return {
        "status": status,
        "deployable": not unresolved,
        "unresolved_actions": unresolved,
    }


def _policy_statements(
    requirements: list[PermissionRequirement],
) -> list[dict[str, object]]:
    grouped: dict[tuple[tuple[str, ...], str], set[str]] = {}
    conditions_by_key: dict[tuple[tuple[str, ...], str], dict[str, object]] = {}
    for requirement in requirements:
        resources = tuple(requirement.resolved_resources)
        if not resources:
            msg = f"AWS IAM policy has no resolved resources for {requirement.api_action}."
            raise ValueError(msg)
        condition = _iam_condition(requirement.iam_conditions)
        condition_key = json.dumps(condition, sort_keys=True, separators=(",", ":"))
        key = (resources, condition_key)
        grouped.setdefault(key, set()).add(requirement.api_action)
        conditions_by_key[key] = condition
    statements: list[dict[str, object]] = []
    for index, key in enumerate(sorted(grouped), start=1):
        resources, _condition_key = key
        statement: dict[str, object] = {
            "Sid": f"UnioCollectorReadOnly{index:03d}",
            "Effect": "Allow",
            "Action": sorted(grouped[key]),
            "Resource": resources[0] if len(resources) == 1 else list(resources),
        }
        condition = conditions_by_key[key]
        if condition:
            statement["Condition"] = condition
        statements.append(statement)
    return statements


def _iam_condition(
    conditions: tuple[dict[str, object], ...],
) -> dict[str, object]:
    return AwsIamConditionRenderer().render(conditions)


def required_iam_actions(plan: PermissionPlan) -> list[str]:
    """Return required IAM actions from a plan."""
    return sorted(
        {requirement.api_action for requirement in plan.requirements if requirement.requirement_type == "required"},
    )


def conditional_iam_actions(plan: PermissionPlan) -> list[str]:
    """Return conditional IAM actions from a plan."""
    return sorted(
        {requirement.api_action for requirement in plan.requirements if requirement.requirement_type == "conditional"},
    )


def optional_enrichment_iam_actions(plan: PermissionPlan) -> list[str]:
    """Return optional enrichment IAM actions from a plan."""
    return sorted(
        {requirement.api_action for requirement in plan.requirements if requirement.requirement_type == "optional_enrichment"},
    )


def non_required_iam_actions(plan: PermissionPlan) -> list[str]:
    """Return policy-omitted non-required actions from a plan."""
    return sorted({*conditional_iam_actions(plan), *optional_enrichment_iam_actions(plan)})


def policy_iam_actions(
    plan: PermissionPlan,
    *,
    include_conditional_actions: bool,
) -> list[str]:
    """Return the actions rendered into the IAM policy document."""
    actions = set(required_iam_actions(plan))
    if include_conditional_actions:
        actions.update(non_required_iam_actions(plan))
    return sorted(actions)


def iam_policy_document_options(
    plan: PermissionPlan,
    *,
    include_conditional_actions: bool,
) -> dict[str, object]:
    """Return machine-readable metadata for rendered IAM policy contents."""
    conditional_actions = conditional_iam_actions(plan)
    optional_enrichment_actions = optional_enrichment_iam_actions(plan)
    non_required_actions = non_required_iam_actions(plan)
    included = non_required_actions if include_conditional_actions else []
    excluded = [] if include_conditional_actions else non_required_actions
    return {
        "include_conditional_actions_flag": include_conditional_actions,
        "conditional_actions_included": bool(included),
        "conditional_actions_excluded": bool(excluded),
        "included_conditional_actions": conditional_actions if include_conditional_actions else [],
        "excluded_conditional_actions": [] if include_conditional_actions else conditional_actions,
        "included_optional_enrichment_actions": optional_enrichment_actions if include_conditional_actions else [],
        "excluded_optional_enrichment_actions": [] if include_conditional_actions else optional_enrichment_actions,
        "included_non_required_actions": included,
        "excluded_non_required_actions": excluded,
        "rendered_action_count": len(
            policy_iam_actions(
                plan,
                include_conditional_actions=include_conditional_actions,
            ),
        ),
        "policy_rendering": policy_rendering_status(
            plan,
        ),
    }


__all__ = [
    "AwsIamPolicyRenderer",
    "conditional_iam_actions",
    "iam_policy_document_options",
    "included_policy_requirements",
    "non_required_iam_actions",
    "optional_enrichment_iam_actions",
    "policy_iam_actions",
    "policy_rendering_status",
    "required_iam_actions",
]
