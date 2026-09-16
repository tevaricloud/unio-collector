from __future__ import annotations  # noqa: D100


class UnsafeAwsOperationError(RuntimeError):
    """Raised before an AWS call when an operation is not approved read-only."""
