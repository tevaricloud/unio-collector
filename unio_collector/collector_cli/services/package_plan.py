from __future__ import annotations  # noqa: D100

import json
from pathlib import Path
from typing import Any

from unio_collector.collector.package.manifest import build_collector_package_file_plan


class CollectorPackagePlanService:
    """Emit deterministic collector package-plan JSON."""

    def __init__(self, console: Any) -> None:  # noqa: ANN401
        """Store the output console."""
        self.console = console

    def run(self, args: object) -> int:
        """Write or print the collector package plan."""
        plan = build_collector_package_file_plan()
        errors = plan.validate()
        payload = {
            **plan.convert_to_dict(),
            "validation_errors": errors,
        }
        output = str(getattr(args, "output", "") or "")
        if output:
            output_path = Path(output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(
                json.dumps(payload, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            self.console.print(f"Wrote collector package plan to {output_path}")
        else:
            self.console.print(json.dumps(payload, indent=2, sort_keys=True))
        if errors:
            self.console.print("Collector package plan validation failed.")
            for error in errors:
                self.console.print(f"- {error}")
            return 1
        self.console.print(
            f"Collector package plan validation passed: {len(plan.source_files)} source files, {len(plan.metadata_files)} metadata files.",
        )
        return 0


__all__ = ["CollectorPackagePlanService"]
