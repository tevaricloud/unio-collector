"""Validate permission-plan integrity before producing deployable output."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, NoReturn

from unio_collector.evidence.permission.planning.condition import AwsIamConditionRenderer
from unio_collector.scanners.permission_classifier import is_read_only_iam_action

if TYPE_CHECKING:
    from unio_collector.evidence.permission.planning.plan import PermissionPlan
    from unio_collector.evidence.permission.planning.requirement import PermissionRequirement

_ACTION_PATTERN = re.compile(r"[A-Za-z0-9-]+:[A-Za-z0-9]+")


class AwsPermissionPlanValidator:
    """Check actual requirements rather than trusting cached action labels."""

    def validate(self, plan: PermissionPlan) -> None:
        """Reject unsafe actions, unknown scope and malformed restrictions."""
        if plan.provider_id != "aws":
            self._fail()
        rejected = set(plan.rejected_actions)
        for requirement in plan.requirements:
            action = requirement.api_action
            if not isinstance(action, str) or not _ACTION_PATTERN.fullmatch(action):
                self._fail()
            if not is_read_only_iam_action(action):
                rejected.add(action)
            self._validate_requirement(requirement)
        if rejected:
            message = "Permission plan contains non-read-only actions: " + ", ".join(sorted(rejected))
            raise ValueError(message)
        self._validate_status(plan)

    def _validate_status(self, plan: PermissionPlan) -> None:
        unresolved = tuple(sorted(requirement.api_action for requirement in plan.requirements if requirement.scope_status == "unresolved"))
        wildcard = any(requirement.scope_status == "wildcard_required" for requirement in plan.requirements)
        status = "unresolved_policy_plan" if unresolved else "valid_wildcard_policy" if wildcard else "exact_scoped_policy"
        if plan.unresolved_actions != unresolved or plan.policy_status != status or plan.deployable is not (not unresolved):
            self._fail()

    def _validate_requirement(self, requirement: PermissionRequirement) -> None:
        if requirement.provider_id != "aws" or requirement.requirement_type not in {"required", "conditional", "optional_enrichment"}:
            self._fail()
        if requirement.scope_status not in {"unresolved", "resource_scoped", "wildcard_required"}:
            self._fail()
        if requirement.scope_status != "unresolved":
            resources = requirement.resolved_resources
            if not isinstance(resources, (tuple, list)) or not resources or not all(isinstance(value, str) and value.strip() for value in resources):
                self._fail()
            if requirement.unresolved_variables:
                self._fail()
        AwsIamConditionRenderer().render(requirement.iam_conditions)

    @staticmethod
    def _fail() -> NoReturn:
        message = "AWS permission plan contains invalid or inconsistent requirements."
        raise ValueError(message)
