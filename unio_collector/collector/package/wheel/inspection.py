from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class CollectorWheelInspectionResult:
    """Deterministic collector wheel member inspection details."""

    members: tuple[str, ...]
    required_members: tuple[str, ...]
    missing_required_members: tuple[str, ...]
    unexpected_wheel_members: tuple[str, ...]
    unexpected_application_members: tuple[str, ...]
    prohibited_members: tuple[str, ...]
    provider_implementation_members: tuple[str, ...]
    metadata_errors: tuple[str, ...]
    entrypoint_errors: tuple[str, ...]

    @property
    def status(self) -> str:
        """Return the aggregate wheel inspection status."""
        failures = (
            self.missing_required_members,
            self.unexpected_wheel_members,
            self.unexpected_application_members,
            self.prohibited_members,
            self.provider_implementation_members,
            self.metadata_errors,
            self.entrypoint_errors,
        )
        return "valid" if not any(failures) else "invalid"
