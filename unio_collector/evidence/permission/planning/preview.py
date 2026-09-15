from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Literal

from unio_collector.evidence.permission.planning.validation import AwsPermissionPlanValidator

if TYPE_CHECKING:
    from unio_collector.evidence.permission.planning.plan import PermissionPlan

PreviewState = Literal[
    "expected",
    "confirmed_available",
    "confirmed_denied",
    "conditionally_available",
    "not_exercised",
    "unknown",
]


class PermissionPreviewBuilder:
    """Build metadata-first permission preview output."""

    def build(
        self,
        *,
        plan: PermissionPlan,
        probe: bool = False,
    ) -> dict[str, object]:
        """Return preview expectations and optional bounded observations."""
        AwsPermissionPlanValidator().validate(plan)
        return {
            "schema_version": "2026-07",
            "provider_id": plan.provider_id,
            "probe_requested": probe,
            "aws_scope": plan.aws_scope,
            "policy_status": plan.policy_status,
            "deployable": plan.deployable,
            "unresolved_actions": list(plan.unresolved_actions),
            "authorization_catalogue_version": (plan.authorization_catalogue_version),
            "requirements": [
                {
                    **requirement.convert_to_dict(),
                    "state": "expected",
                    "state_source": "scanner_metadata",
                }
                for requirement in plan.requirements
            ],
            "limitations": [
                *list(plan.limitations),
                ("Permission preview is planning and observation output, not proof of effective AWS runtime permissions."),
            ],
            "observations": [],
        }
