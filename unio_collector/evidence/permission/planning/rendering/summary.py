from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.evidence.permission.planning.rendering.aws_iam_policy import (
    conditional_iam_actions,
    non_required_iam_actions,
    optional_enrichment_iam_actions,
    policy_rendering_status,
)

if TYPE_CHECKING:
    from unio_collector.evidence.permission.planning.plan import PermissionPlan


class PermissionPlanSummaryRenderer:
    """Render a concise human-readable permission summary."""

    def render(
        self,
        plan: PermissionPlan,
        *,
        include_conditional_actions: bool = False,
    ) -> str:
        """Return plain text summary output."""
        conditional_actions = conditional_iam_actions(plan)
        optional_enrichment_actions = optional_enrichment_iam_actions(plan)
        non_required_actions = non_required_iam_actions(plan)
        rendering = policy_rendering_status(
            plan,
        )
        lines = [
            f"Provider: {plan.provider_id}",
            f"Policy status: {rendering['status']}",
            f"Deployable IAM policy: {str(rendering['deployable']).lower()}",
            f"Selected scanners: {len(plan.selected_scanner_ids)}",
            f"Required actions: {len([item for item in plan.requirements if item.requirement_type == 'required'])}",
            f"Conditional actions: {len(conditional_actions)}",
            f"Optional enrichment actions: {len(optional_enrichment_actions)}",
            f"Chargeable included actions: {len([item for item in plan.requirements if item.chargeable])}",
            (
                "IAM policy conditional action handling: "
                + ("included in rendered policy document." if include_conditional_actions else "excluded from rendered policy document by default.")
            ),
            f"Chargeable actions excluded: {len(plan.excluded_chargeable_requirements)}",
            "",
            "Wildcard resource justifications:",
        ]
        if rendering["unresolved_actions"]:
            lines.extend(
                [
                    "Unresolved policy actions:",
                    *(f"- {action}" for action in rendering["unresolved_actions"]),
                    ("Use JSON planning output to inspect the unresolved ARN templates and variables."),
                ],
            )
        if non_required_actions and not include_conditional_actions:
            lines.extend(
                [
                    ("Re-run with --include-conditional-actions to include conditional and optional-enrichment actions in the IAM policy document."),
                    ("Omitted non-required actions: " + ", ".join(non_required_actions)),
                ],
            )
        if non_required_actions and include_conditional_actions:
            lines.append(
                "Included non-required actions: " + ", ".join(non_required_actions),
            )
        if not plan.wildcard_justifications:
            lines.append("- none")
        lines.extend(f"- {item['action']}: {item['justification']}" for item in plan.wildcard_justifications)
        lines.extend(["", "Limitations:"])
        lines.extend(f"- {item}" for item in plan.limitations)
        return "\n".join(lines) + "\n"


__all__ = ["PermissionPlanSummaryRenderer"]
