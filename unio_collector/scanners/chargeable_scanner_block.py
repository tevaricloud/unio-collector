from __future__ import annotations  # noqa: D100

from dataclasses import dataclass

CHARGEABLE_SCANNER_CONFIG_KEY = "scan.allow_chargeable_scanners"
CHARGEABLE_SCANNER_CLI_OPTION = "--allow-chargeable-scanners"


@dataclass(frozen=True)
class ChargeableScannerBlock:
    """Selected scanner blocked by the chargeable-scanner safety gate."""

    scanner_id: str
    reason: str
    config_key: str = CHARGEABLE_SCANNER_CONFIG_KEY
    cli_option: str = CHARGEABLE_SCANNER_CLI_OPTION

    def convert_to_dict(self) -> dict[str, str]:  # noqa: D102
        return {
            "scanner_id": self.scanner_id,
            "reason": self.reason,
            "config_key": self.config_key,
            "cli_option": self.cli_option,
        }
