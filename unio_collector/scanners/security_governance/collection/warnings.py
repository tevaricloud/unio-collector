from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.aws import errors as aws_errors

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


def record_context_warning(  # noqa: D103
    context: ScannerContext,
    warnings: list[str],
    region: str,
    label: str,
    error: Exception,
) -> None:
    del context
    message = build_context_warning(region, label, error)
    warnings.append(message)


def append_warning(  # noqa: D103
    warnings: list[str],
    label: str,
    error: Exception,
) -> None:
    code = aws_errors.get_aws_error_code(error) or error.__class__.__name__
    warnings.append(f"{label} evidence was unavailable ({code}).")


def build_context_warning(region: str, label: str, error: Exception) -> str:  # noqa: D103
    code = aws_errors.get_aws_error_code(error) or error.__class__.__name__
    return f"{label} evidence was unavailable in {region} ({code})."
