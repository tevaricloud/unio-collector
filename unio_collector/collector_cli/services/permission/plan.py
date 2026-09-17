from __future__ import annotations  # noqa: D100

import json
from pathlib import Path
from typing import Any

from unio_collector.collector_cli.services.config import CollectorConfigResolver
from unio_collector.evidence.permission.planning import (
    AwsIamPolicyRenderer,
    AwsPolicyExecutionScope,
    PermissionPlanBuilder,
    PermissionPlanJsonRenderer,
    PermissionPlanSummaryRenderer,
)


class CollectorPermissionPolicyService:
    """Render collector-safe least-permission planning output."""

    def __init__(self, console: Any) -> None:  # noqa: ANN401
        """Store the output console."""
        self.console = console

    def run(self, args: object) -> int:
        """Build and render a collector permission plan."""
        if getattr(args, "policy_provider", "aws") != "aws":
            msg = "The standalone collector policy planner currently supports AWS only."
            raise ValueError(msg)
        resolved = CollectorConfigResolver(self.console).resolve(args, output=Path())
        plan = PermissionPlanBuilder().build(
            provider_id=resolved.config.provider_id,
            selection=resolved.selection,
            include_platform_billing_baseline=(getattr(resolved.config, "fixture", None) is None),
            aws_scope=AwsPolicyExecutionScope.resolve(
                regions=tuple(getattr(resolved.config, "regions", ()) or ()),
                policy_account_id=getattr(args, "policy_account_id", None),
                policy_partition=getattr(args, "policy_partition", None),
            ),
        )
        output_format = str(getattr(args, "format", "json"))
        include_conditional_actions = bool(
            getattr(args, "include_conditional_actions", False),
        )
        if output_format == "iam-policy":
            payload = AwsIamPolicyRenderer().render(
                plan,
                include_conditional_actions=include_conditional_actions,
                fail_on_excluded_conditional=True,
            )
            text = _json_text(payload)
        elif output_format == "summary":
            text = PermissionPlanSummaryRenderer().render(
                plan,
                include_conditional_actions=include_conditional_actions,
            )
        else:
            text = PermissionPlanJsonRenderer().render(
                plan,
                include_conditional_actions=include_conditional_actions,
            )
        output_path = getattr(args, "output", None)
        if output_path:
            Path(str(output_path)).write_text(text, encoding="utf-8")
        else:
            self.console.print(text, markup=False, end="")
        return 0


def _json_text(payload: object) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


__all__ = ["CollectorPermissionPolicyService"]
