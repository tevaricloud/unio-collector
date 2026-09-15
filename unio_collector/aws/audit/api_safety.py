from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import Literal

AwsOperationSafetyStatus = Literal[
    "read_only",
    "credential_delegation",
    "mutating",
    "unknown",
]

READ_ONLY_OPERATION_PREFIXES = (
    "BatchGet",
    "Describe",
    "Get",
    "List",
    "Lookup",
    "Search",
    "Select",
)

MUTATING_OPERATION_PREFIXES = (
    "Accept",
    "Add",
    "Allocate",
    "Apply",
    "Associate",
    "Attach",
    "Authorize",
    "Cancel",
    "Create",
    "Delete",
    "Deregister",
    "Detach",
    "Disable",
    "Disassociate",
    "Enable",
    "Execute",
    "Invoke",
    "Modify",
    "Publish",
    "Put",
    "Reboot",
    "Register",
    "Release",
    "Remove",
    "Revoke",
    "Run",
    "Send",
    "Set",
    "Start",
    "Stop",
    "Subscribe",
    "Tag",
    "Terminate",
    "Untag",
    "Update",
)

READ_ONLY_OPERATION_ALLOWLIST: dict[str, str] = {
    "ce:GetCostAndUsage": "Cost Explorer cost query used for read-only billing analysis.",
    "logs:StartQuery": (
        "CloudWatch Logs Insights StartQuery starts a read-only query over log events. It does not mutate resources, but AWS can charge for scanned log data."
    ),
    "sts:GetCallerIdentity": "STS identity lookup used for read-only account context.",
}

CREDENTIAL_DELEGATION_OPERATION_ALLOWLIST: dict[str, str] = {
    "sts:AssumeRole": ("STS role assumption returns temporary credentials without mutating AWS resources; it is credential delegation, not a read operation."),
}


@dataclass(frozen=True)
class AwsOperationSafetyClassification:
    """Deterministic safety classification for one AWS API operation."""

    service_name: str
    operation_name: str
    status: AwsOperationSafetyStatus
    reason: str

    @property
    def declared_call(self) -> str:
        """Return the canonical service:operation call name."""
        return f"{self.service_name}:{self.operation_name}"

    @property
    def is_read_only(self) -> bool:
        """Return whether the operation is approved as read-only."""
        return self.status == "read_only"

    @property
    def is_runtime_safe(self) -> bool:
        """Return whether the audited runtime may execute the operation."""
        return self.status in {"read_only", "credential_delegation"}


def classify_aws_operation(
    service_name: str,
    operation_name: str,
) -> AwsOperationSafetyClassification:
    """Classify an AWS operation at the audited runtime boundary."""
    declared_call = f"{service_name}:{operation_name}"
    delegation_reason = CREDENTIAL_DELEGATION_OPERATION_ALLOWLIST.get(declared_call)
    if delegation_reason is not None:
        return AwsOperationSafetyClassification(
            service_name=service_name,
            operation_name=operation_name,
            status="credential_delegation",
            reason=delegation_reason,
        )
    allowlist_reason = READ_ONLY_OPERATION_ALLOWLIST.get(declared_call)
    if allowlist_reason is not None:
        return AwsOperationSafetyClassification(
            service_name=service_name,
            operation_name=operation_name,
            status="read_only",
            reason=allowlist_reason,
        )
    if operation_name.startswith(READ_ONLY_OPERATION_PREFIXES):
        return AwsOperationSafetyClassification(
            service_name=service_name,
            operation_name=operation_name,
            status="read_only",
            reason="Operation name uses an approved read-only prefix.",
        )
    if operation_name.startswith(MUTATING_OPERATION_PREFIXES):
        return AwsOperationSafetyClassification(
            service_name=service_name,
            operation_name=operation_name,
            status="mutating",
            reason="Operation name uses a mutating AWS API prefix.",
        )
    return AwsOperationSafetyClassification(
        service_name=service_name,
        operation_name=operation_name,
        status="unknown",
        reason="Operation does not match an approved read-only prefix or documented allowlist entry.",
    )


def classify_operation_read_only(
    service_name: str,
    operation_name: str,
) -> bool | None:
    """Compatibility boolean view of the central AWS operation classifier."""
    classification = classify_aws_operation(service_name, operation_name)
    if classification.status == "read_only":
        return True
    if classification.status == "mutating":
        return False
    return None
