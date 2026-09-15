from __future__ import annotations  # noqa: D100

import json
from typing import TYPE_CHECKING

from unio_collector.evidence.permission.planning.rendering.aws_iam_policy import (
    AwsIamPolicyRenderer,
    iam_policy_document_options,
    included_policy_requirements,
    policy_rendering_status,
)

if TYPE_CHECKING:
    from unio_collector.evidence.permission.planning.plan import PermissionPlan


class PermissionPlanJsonRenderer:
    """Render the full permission plan as JSON."""

    def render(
        self,
        plan: PermissionPlan,
        *,
        include_conditional_actions: bool = False,
    ) -> str:
        """Return pretty deterministic JSON."""
        payload = plan.convert_to_dict()
        rendering = policy_rendering_status(
            plan,
        )
        payload["policy_rendering"] = rendering
        if rendering["deployable"]:
            payload["iam_policy_document"] = AwsIamPolicyRenderer().render(
                plan,
                include_conditional_actions=include_conditional_actions,
            )
            payload["iam_policy_template"] = None
        else:
            payload["iam_policy_document"] = None
            payload["iam_policy_template"] = [
                {
                    "action": requirement.api_action,
                    "resource_arn_templates": list(
                        requirement.resource_arn_templates,
                    ),
                    "unresolved_variables": list(
                        requirement.unresolved_variables,
                    ),
                }
                for requirement in included_policy_requirements(
                    plan,
                    include_conditional_actions=include_conditional_actions,
                )
                if requirement.scope_status == "unresolved"
            ]
        payload["iam_policy_document_options"] = iam_policy_document_options(
            plan,
            include_conditional_actions=include_conditional_actions,
        )
        return json.dumps(payload, indent=2, sort_keys=True) + "\n"


__all__ = ["PermissionPlanJsonRenderer"]
