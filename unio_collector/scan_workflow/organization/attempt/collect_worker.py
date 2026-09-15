"""Collector-safe spawned organization account attempt."""

from __future__ import annotations

from dataclasses import asdict, replace
from typing import TYPE_CHECKING

from unio_collector.aws.api.call_ledger import ApiCallLedger
from unio_collector.aws.session import AwsSessionConfig, create_audited_session
from unio_collector.collector.bundle.checksums import build_sha256
from unio_collector.collector.bundle.collection_writer import CollectorEvidenceBundleWriter
from unio_collector.collector.execution.service import CollectorExecutionService
from unio_collector.providers.aws.organization import AwsOrganizationRoleAssumer
from unio_collector.scan_workflow.organization.attempt.result import OrganizationAttemptResult

if TYPE_CHECKING:
    from multiprocessing.connection import Connection

    from unio_collector.scan_workflow.organization.attempt.request import OrganizationAttemptRequest


def run_collect_attempt(request: OrganizationAttemptRequest[object], connection: Connection) -> None:
    """Collect into staging and serialize the child outcome to the parent."""
    try:
        connection.send(_execute(request))
    except Exception as exc:  # noqa: BLE001
        connection.send(exc)
    finally:
        connection.close()


def _execute(request: OrganizationAttemptRequest[object]) -> OrganizationAttemptResult:
    request.staging_root.mkdir(parents=True, exist_ok=False)
    partition = _partition(request.account.arn)
    account_context: dict[str, object] = {
        "account_id": request.account.account_id,
        "arn": request.account.arn,
        "partition": partition,
        "provider": "aws",
    }
    if request.fixture_path is not None:
        role_audit = _fixture_audit(request, partition)
        result = CollectorExecutionService().execute(
            replace(request.scan_config, fixture=request.fixture_path),
            request.scanner_selection,
            minimisation=request.minimisation,
        )
        result.account_context.update(account_context)
    else:
        management_session = create_audited_session(
            AwsSessionConfig(profile=request.scan_config.profile),
            ApiCallLedger(redact_context=request.scan_config.audit_ledger_redaction_enabled),
            runtime_config=request.scan_config.runtime,
        )
        context = AwsOrganizationRoleAssumer().assume(
            management_session=management_session,
            account=request.account,
            role=request.organization_config.audit_role,
            partition=partition,
            run_id=request.run_id,
        )
        role_audit = asdict(context.role_audit)
        result = CollectorExecutionService().execute_with_context(
            request.scan_config,
            request.scanner_selection,
            session=context.session,
            ledger=context.ledger,
            account_context=account_context,
            minimisation=request.minimisation,
        )
    bundle_path = request.staging_root / "evidence-bundle.zip"
    write_result = CollectorEvidenceBundleWriter().write(
        path=bundle_path,
        result=result,
        minimisation=request.minimisation,
    )
    return OrganizationAttemptResult(
        account_reference=request.account.alias,
        bundle_sha256=build_sha256(bundle_path.read_bytes()),
        bundle_schema_version=str(write_result.manifest["bundle_schema_version"]),
        bundle_purpose=str(write_result.manifest["bundle_purpose"]),
        degraded=result.collection_status != "complete",
        role_audit=role_audit,
    )


def _fixture_audit(request: OrganizationAttemptRequest[object], partition: str) -> dict[str, object]:
    return {
        "account_reference": request.account.alias,
        "role_arn": AwsOrganizationRoleAssumer().render_role_arn(
            request.organization_config.audit_role,
            request.account.account_id,
            partition,
        ),
        "duration_seconds": request.organization_config.audit_role.duration_seconds,
        "external_id_present": request.organization_config.audit_role.external_id is not None,
        "external_id_source_kind": "synthetic_fixture",
        "request_id": None,
        "outcome": "synthetic_not_assumed",
        "failure_category": None,
    }


def _partition(arn: str) -> str:
    return arn.split(":", maxsplit=2)[1] if arn.startswith("arn:") else "aws"


__all__ = ["run_collect_attempt"]
