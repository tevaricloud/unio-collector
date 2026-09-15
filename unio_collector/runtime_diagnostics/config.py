from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field

from unio_collector.runtime_diagnostics.watchdog_config import RuntimeWatchdogConfig


@dataclass(frozen=True)
class RuntimeDiagnosticsConfig:  # noqa: D101
    enabled: bool = False
    watchdog: RuntimeWatchdogConfig = field(default_factory=RuntimeWatchdogConfig)

    def validate(self) -> None:  # noqa: D102
        self.watchdog.validate()

    def convert_to_dict(self) -> dict[str, object]:  # noqa: D102
        return {
            "enabled": self.enabled,
            "watchdog": self.watchdog.convert_to_dict(),
        }
