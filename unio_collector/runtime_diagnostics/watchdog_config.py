from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class RuntimeWatchdogConfig:  # noqa: D101
    warning_threshold_seconds: int = 60
    critical_threshold_seconds: int = 120

    def validate(self) -> None:  # noqa: D102
        if self.warning_threshold_seconds <= 0:
            msg = "Runtime diagnostics watchdog warning threshold must be positive."
            raise ValueError(
                msg,
            )
        if self.critical_threshold_seconds <= 0:
            msg = "Runtime diagnostics watchdog critical threshold must be positive."
            raise ValueError(
                msg,
            )
        if self.critical_threshold_seconds < self.warning_threshold_seconds:
            msg = "Runtime diagnostics watchdog critical threshold must be greater than or equal to the warning threshold."
            raise ValueError(
                msg,
            )

    def convert_to_dict(self) -> dict[str, int]:  # noqa: D102
        return {
            "warning_threshold_seconds": self.warning_threshold_seconds,
            "critical_threshold_seconds": self.critical_threshold_seconds,
        }
