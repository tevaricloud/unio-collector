"""Synthetic finite SDK session for the actual commitment collector."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from botocore.exceptions import ClientError

from tools.collector_audit_fixture import SyntheticAuditSession
from tools.collector_commitment.responses import RESPONSES
from tools.collector_commitment.scenario import CommitmentResponseScenario

if TYPE_CHECKING:
    from collections.abc import Callable


class SyntheticCommitmentSession(SyntheticAuditSession):
    """Serve finite local provider facts and retain exact synthetic requests."""

    def __init__(self, variant: str, *, service: str = "ec2", calls: list[dict[str, Any]] | None = None) -> None:
        """Bind finite provider service and shared synthetic call evidence."""
        super().__init__(service, variant)
        self.calls = [] if calls is None else calls

    def get_region_name(self) -> str:
        """Return a deterministic selected region."""
        return "eu-west-2"

    def create_client(self, service: str, **kwargs: object) -> SyntheticCommitmentSession:
        """Forbid non-declared endpoints without constructing an AWS client."""
        if service not in {"ec2", "savingsplans", "ce"} or kwargs.get("region_name") not in {"eu-west-2", "us-east-1"}:
            message = "Unexpected synthetic commitment endpoint"
            raise AssertionError(message)
        return SyntheticCommitmentSession(self.variant, service=service, calls=self.calls)

    def __getattr__(self, operation: str) -> Callable[..., dict[str, Any]]:
        """Serve an exact declared SDK operation and preserve error outcomes."""
        if operation not in RESPONSES:
            raise AttributeError(operation)

        def invoke(**parameters: object) -> dict[str, Any]:
            """Retain actual SDK requests and vary only synthetic provider responses."""
            self.calls.append({"operation": operation, "parameters": parameters})
            code = {"denied": "AccessDenied", "unavailable": "ServiceUnavailable", "unsupported": "UnsupportedOperation", "failure": "InternalFailure"}.get(
                self.variant
            )
            if self.variant == "partial" and operation == "describe_savings_plans":
                code = "AccessDenied"
            if code:
                raise ClientError({"Error": {"Code": code, "Message": "synthetic-customer-provider-failure"}}, operation)
            return CommitmentResponseScenario(self.variant, self.service).response(operation, parameters)

        return invoke
