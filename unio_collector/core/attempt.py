from __future__ import annotations  # noqa: D100

from typing import Protocol


class AttemptDeadlineContract(Protocol):
    """Authority and deadline surface used by bounded runtime operations."""

    @property
    def attempt_id(self) -> str:
        """Return the stable identifier for this execution attempt."""
        ...

    @property
    def scanner_id(self) -> str:
        """Return the scanner that owns this attempt."""
        ...

    def raise_if_cancelled(self) -> None:
        """Raise when the attempt is cancelled or past its deadline."""
        ...

    def time_remaining_seconds(self) -> float | None:
        """Return remaining monotonic deadline budget."""
        ...

    def wait_for_cancellation(self, timeout_seconds: float) -> bool:
        """Wait for cancellation and return whether it was observed."""
        ...

    def has_commit_authority(self) -> bool:
        """Return whether scanner-owned state may still be committed."""
        ...

    def get_completion_classification(self) -> str:
        """Return committed or late for a completed bounded operation."""
        ...

    def get_outcome_reason(self) -> str:
        """Return the current typed outcome reason value."""
        ...
