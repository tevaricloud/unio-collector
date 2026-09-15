"""Sanitized, compatibility-preserving organization account failure records."""

from __future__ import annotations

from unio_collector.aws import errors as aws_errors
from unio_collector.scan_workflow.organization.attempt.cancelled_error import OrganizationAttemptCancelledError
from unio_collector.scan_workflow.organization.attempt.timeout_error import OrganizationAttemptTimeoutError
from unio_collector.scan_workflow.organization.commit.error import OrganizationAccountReportError
from unio_collector.scan_workflow.organization.model.failure import AccountFailure


def build_account_failure(alias: str, exc: Exception, attempts: int) -> AccountFailure:
    """Build one sanitized stable account failure."""
    if isinstance(exc, OrganizationAttemptTimeoutError):
        return AccountFailure(
            account_reference=alias,
            stage="account_timeout",
            code="account_timeout",
            category="timeout",
            sanitized_detail="Account execution exceeded its configured hard timeout and was terminated.",
            retryable=True,
            attempts=attempts,
        )
    if isinstance(exc, OrganizationAttemptCancelledError):
        return AccountFailure(
            account_reference=alias,
            stage="user_cancellation",
            code="cancelled",
            category="cancelled",
            sanitized_detail="Account execution authority was revoked by user cancellation.",
            retryable=True,
            attempts=attempts,
        )
    if isinstance(exc, OrganizationAccountReportError):
        return AccountFailure(
            account_reference=alias,
            stage="account_report",
            code=exc.code,
            category="report_failure",
            sanitized_detail="The result bundle is authoritative and reusable, but account report generation failed.",
            retryable=True,
            attempts=attempts,
        )
    classification = aws_errors.classify_aws_error(exc, service_name="sts", operation_name="AssumeRole")
    code = aws_errors.get_aws_error_code(exc) or exc.__class__.__name__
    return AccountFailure(
        account_reference=alias,
        stage="account_execution",
        code=str(code),
        category=str(classification.category),
        sanitized_detail="Account execution failed; inspect local diagnostics and role-assumption audit evidence.",
        retryable=aws_errors.is_retryable_error(exc),
        attempts=attempts,
    )
