from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from importlib import import_module
from typing import TYPE_CHECKING, Any

from unio_collector.aws.audit import ApiCallLedger, AuditedAwsSession, AwsAuditContext

if TYPE_CHECKING:
    from unio_collector.aws.client.config import AwsRuntimeConfig


@dataclass(frozen=True)
class AwsSessionConfig:  # noqa: D101
    profile: str | None = None
    region: str | None = None


def create_boto3_session(config: AwsSessionConfig) -> Any:  # noqa: ANN401
    """Create a boto3 session without performing any AWS operation."""
    boto3 = import_module("boto3")

    kwargs: dict[str, str] = {}
    if config.profile:
        kwargs["profile_name"] = config.profile
    if config.region:
        kwargs["region_name"] = config.region
    return boto3.Session(**kwargs)


def create_audited_session(  # noqa: D103
    config: AwsSessionConfig,
    ledger: ApiCallLedger,
    *,
    runtime_config: AwsRuntimeConfig | None = None,
) -> AuditedAwsSession:
    return AuditedAwsSession(
        create_boto3_session(config),
        ledger,
        runtime_config=runtime_config,
    )


def get_account_context(session: AuditedAwsSession) -> dict[str, Any]:
    """Return read-only identity context for report organization."""
    audit_context = AwsAuditContext(
        scanner_id="unio-collector-preflight-identity",
        collector="AwsSession",
        allowed_api_calls=("sts:GetCallerIdentity",),
    )
    identity = session.create_client(
        "sts",
        region_name=session.get_region_name() or "us-east-1",
        audit_context=audit_context,
    ).get_caller_identity()
    session.ledger.set_identity(identity)
    account_id = identity.get("Account", "unknown-account")
    arn = identity.get("Arn")
    partition = None
    if isinstance(arn, str) and arn.startswith("arn:"):
        partition = arn.split(":", maxsplit=2)[1]
    return {
        "account_id": account_id,
        "arn": arn,
        "partition": partition,
        "user_id": identity.get("UserId"),
    }
