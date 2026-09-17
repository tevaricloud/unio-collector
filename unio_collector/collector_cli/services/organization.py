from __future__ import annotations

# ruff: noqa: ANN401,D100,D102,D107,EM101,TRY003
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from unio_collector.aws.api.call_ledger import ApiCallLedger
from unio_collector.aws.session import AwsSessionConfig, create_audited_session
from unio_collector.collector.minimisation import EvidenceMinimisationOptions
from unio_collector.collector.organization import OrganizationEnvelopeValidator
from unio_collector.collector_cli.services.config import CollectorConfigResolver
from unio_collector.config.organization import AwsOrganizationConfigLoader
from unio_collector.providers.aws.organization import (
    AwsOrganizationDiscovery,
    AwsOrganizationRoleAssumer,
    OrganizationFixtureLoader,
)
from unio_collector.scan_workflow.organization.collection.coordinator import OrganizationCollectionCoordinator
from unio_collector.scanners.registry.definitions import SCANNERS

if TYPE_CHECKING:
    from argparse import Namespace


class CollectorOrganizationService:
    """Run the collector-safe organization command subset."""

    def __init__(self, console: Any) -> None:
        self.console = console

    def run(self, args: Namespace) -> int:
        command = str(getattr(args, "organization_command", ""))
        if command == "validate":
            result = OrganizationEnvelopeValidator().validate(
                Path(str(args.envelope)),
                trusted_public_key=(Path(str(args.trusted_public_key)) if getattr(args, "trusted_public_key", None) else None),
                require_signed=bool(getattr(args, "require_signed", False)),
            )
            self.console.print(json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True))
            return 0 if result.valid else 1
        config_path = getattr(args, "config", None)
        if not config_path:
            raise ValueError("Organization collector workflows require --config.")
        organization_config = AwsOrganizationConfigLoader().load(Path(str(config_path)))
        output = Path(str(getattr(args, "output", "organizations")))
        resolved = CollectorConfigResolver(self.console).resolve(args, output=output)
        fixture = getattr(args, "organization_fixture", None)
        management_session = None
        if fixture:
            discovery = OrganizationFixtureLoader().load(Path(str(fixture)), organization_config)
        else:
            management_session = create_audited_session(
                AwsSessionConfig(profile=resolved.config.profile),
                ApiCallLedger(redact_context=resolved.config.audit_ledger_redaction_enabled),
                runtime_config=resolved.config.runtime,
            )
            discovery = AwsOrganizationDiscovery().discover(management_session, organization_config)
        if command == "plan":
            permissions = sorted({call for scanner_id in resolved.selection.enabled_ids for call in SCANNERS[scanner_id].aws_api_calls})
            partition = discovery.organization.organization_arn.split(":", maxsplit=2)[1]
            role = AwsOrganizationRoleAssumer()
            payload = {
                "schema_version": "2026-08-aws-organization-plan-v1",
                "organization": discovery.organization.model_dump(mode="json"),
                "selected_accounts": [
                    {
                        "account": account.model_dump(mode="json"),
                        "role_arn": role.render_role_arn(organization_config.audit_role, account.account_id, partition),
                        "permission_preview_status": "not_probed",
                    }
                    for account in discovery.selection.selected
                ],
                "excluded_accounts": [item.model_dump(mode="json") for item in discovery.selection.excluded],
                "expected_scanner_permissions": permissions,
                "credential_delegation_actions": ["sts:AssumeRole"],
                "account_max_concurrency": organization_config.execution.max_concurrency,
                "billing_allocation_status": "not_collected",
            }
            output.mkdir(parents=True, exist_ok=True)
            (output / "organization-plan.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            return 0
        envelope, coverage, failures = OrganizationCollectionCoordinator().collect(
            management_session=management_session,
            discovery=discovery,
            organization_config=organization_config,
            scan_config=resolved.config,
            scanner_selection=resolved.selection,
            output=output,
            minimisation=EvidenceMinimisationOptions.from_args(args),
            signing_key=(Path(str(args.organization_signing_private_key)) if getattr(args, "organization_signing_private_key", None) else None),
            signing_key_id=getattr(args, "organization_signing_key_id", None),
            resume=bool(getattr(args, "resume", False)),
            retry_failed_accounts=frozenset(getattr(args, "retry_failed_account", [])),
        )
        self.console.print(f"Wrote AWS organization envelope to {envelope}")
        if coverage.completed + coverage.degraded == 0:
            return 1
        return 2 if failures or coverage.degraded else 0


__all__ = ["CollectorOrganizationService"]
