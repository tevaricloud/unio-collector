from __future__ import annotations  # noqa: D100


class UndeclaredAwsOperationError(RuntimeError):
    """Raised before an AWS call when a scanner uses an undeclared operation."""
