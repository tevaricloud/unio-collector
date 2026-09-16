from __future__ import annotations  # noqa: D100

import json
from pathlib import Path
from typing import Any

from unio_collector.aws.session import AwsSessionConfig, create_boto3_session
from unio_collector.collector_cli.services.config import CollectorConfigResolver
from unio_collector.evidence.permission.planning import (
    AwsPolicyExecutionScope,
    PermissionPlanBuilder,
    PermissionPreviewBuilder,
)


class CollectorPermissionPreviewService:
    """Render metadata-first permission preview output."""

    def __init__(self, console: Any) -> None:  # noqa: ANN401
        """Store the output console."""
        self.console = console

    def run(self, args: object) -> int:
        """Build the permission preview without proving effective access."""
        resolved = CollectorConfigResolver(self.console).resolve(args, output=Path())
        observation: dict[str, str] | None = None
        authenticated_identity: dict[str, str] = {}
        if bool(getattr(args, "probe", False)):
            observation, authenticated_identity = self._identity_probe(
                resolved.config,
            )
        plan = PermissionPlanBuilder().build(
            provider_id=resolved.config.provider_id,
            selection=resolved.selection,
            include_platform_billing_baseline=(getattr(resolved.config, "fixture", None) is None),
            aws_scope=AwsPolicyExecutionScope.resolve(
                regions=tuple(getattr(resolved.config, "regions", ()) or ()),
                policy_account_id=getattr(args, "policy_account_id", None),
                policy_partition=getattr(args, "policy_partition", None),
                authenticated_account_id=authenticated_identity.get("account_id"),
                authenticated_arn=authenticated_identity.get("arn"),
            ),
        )
        payload = PermissionPreviewBuilder().build(
            plan=plan,
            probe=bool(getattr(args, "probe", False)),
        )
        if observation is not None:
            observations = payload.get("observations", [])
            if not isinstance(observations, list):
                observations = []
            payload["observations"] = [
                *observations,
                observation,
            ]
        text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
        output_path = getattr(args, "output", None)
        if output_path:
            Path(str(output_path)).write_text(text, encoding="utf-8")
        else:
            self.console.print(text, markup=False, end="")
        return 0

    def _identity_probe(
        self,
        config: object,
    ) -> tuple[dict[str, str], dict[str, str]]:
        if getattr(config, "fixture", None) is not None:
            return (
                {
                    "api_action": "sts:GetCallerIdentity",
                    "state": "not_exercised",
                    "source": "bounded_read_only_probe",
                    "explanation": "Fixture mode does not require live AWS identity probing.",
                },
                {},
            )
        try:
            session = create_boto3_session(
                AwsSessionConfig(
                    profile=getattr(config, "profile", None),
                    region=(getattr(config, "regions", ()) or (None,))[0],
                ),
            )
            identity = session.client("sts").get_caller_identity()
        except Exception:  # noqa: BLE001
            return (
                {
                    "api_action": "sts:GetCallerIdentity",
                    "state": "unknown",
                    "source": "bounded_read_only_probe",
                    "explanation": ("Read-only identity probe did not complete. Provider diagnostics remain in internal collection telemetry."),
                },
                {},
            )
        return (
            {
                "api_action": "sts:GetCallerIdentity",
                "state": "confirmed_available",
                "source": "bounded_read_only_probe",
                "explanation": ("STS identity lookup succeeded. This confirms only this read-only probe, not the full collector permission set."),
            },
            {
                "account_id": str(identity.get("Account") or ""),
                "arn": str(identity.get("Arn") or ""),
            },
        )


__all__ = ["CollectorPermissionPreviewService"]
