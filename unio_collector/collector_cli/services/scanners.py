from __future__ import annotations  # noqa: D100

import json
from typing import TYPE_CHECKING, Any

from unio_collector.scanners.pillars import DEFAULT_SCANNER_PILLAR_POLICY
from unio_collector.scanners.registry.catalog import list_scanners
from unio_collector.scanners.scanner.version import SCANNER_REGISTRY_VERSION

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.definition import ScannerDefinition


class CollectorScannersService:
    """Render canonical AWS collector scanner metadata."""

    def __init__(self, console: Any) -> None:  # noqa: ANN401
        """Store the output console."""
        self.console = console

    def run(self, args: object) -> int:
        """Print the scanner catalogue without constructing collectors."""
        scanners = [self._record(definition) for definition in list_scanners()]
        if bool(getattr(args, "json", False)):
            payload = {
                "provider": "aws",
                "registry_version": SCANNER_REGISTRY_VERSION,
                "scanners": scanners,
                "schema_version": 1,
            }
            self.console.print(json.dumps(payload, indent=2, sort_keys=True), markup=False, soft_wrap=True)
            return 0
        for scanner in scanners:
            chargeable = " [chargeable]" if scanner["may_incur_charges"] else ""
            self.console.print(f"{scanner['scanner_id']}: {scanner['display_name']}{chargeable}")
        return 0

    def _record(self, definition: ScannerDefinition) -> dict[str, object]:
        scanner_id = definition.scanner_id
        return {
            "aws_services": list(definition.aws_services),
            "chargeable_reason": definition.chargeable_reason,
            "default_enabled": definition.default_enabled,
            "description": definition.description,
            "display_name": definition.display_name,
            "may_incur_charges": definition.may_incur_charges,
            "pillars": list(DEFAULT_SCANNER_PILLAR_POLICY.get_pillars(scanner_id)),
            "scanner_id": scanner_id,
        }


__all__ = ["CollectorScannersService"]
