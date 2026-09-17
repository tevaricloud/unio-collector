from __future__ import annotations  # noqa: D100

from dataclasses import dataclass

from unio_collector.aws import errors as aws_errors


@dataclass(frozen=True)
class FreeTierApiErrorRecorder:
    """Classify Free Tier API exceptions into scanner-visible warnings."""

    def record_error(  # noqa: D102
        self,
        exc: Exception,
        *,
        operation: str,
        permission_errors: list[str],
        api_errors: list[str],
    ) -> None:
        code = aws_errors.get_aws_error_code(exc) or exc.__class__.__name__
        message = aws_errors.get_aws_error_message(exc)
        detail = f"{operation}: {code}: {message}".strip()
        if aws_errors.is_permission_error(exc):
            permission_errors.append(detail)
        else:
            api_errors.append(detail)
