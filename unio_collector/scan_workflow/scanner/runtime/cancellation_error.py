from __future__ import annotations  # noqa: D100


class ScannerDeadlineExceededError(RuntimeError):
    """Raised when scanner work observes an expired deadline."""
