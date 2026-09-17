from __future__ import annotations  # noqa: D100

import json
import os
from typing import Any

from unio_collector import __version__
from unio_collector.collector_cli.services.versioning.checker import CollectorVersionChecker
from unio_collector.collector_cli.services.versioning.options import VersionCheckOptions


class CollectorVersionService:
    """Print collector version information."""

    def __init__(self, console: Any) -> None:  # noqa: ANN401
        """Store the output console."""
        self.console = console

    def run(self, args: object) -> int:
        """Print the collector CLI version."""
        if not bool(getattr(args, "check", False)):
            self.console.print(f"unio-collector {__version__}")
            return 0
        options = VersionCheckOptions(
            metadata_location=str(getattr(args, "metadata_url", None) or os.getenv("UNIO_COLLECTOR_RELEASE_METADATA_URL", "")),
            public_key_path=str(getattr(args, "public_key", None) or os.getenv("UNIO_COLLECTOR_RELEASE_PUBLIC_KEY", "")),
            signature_location=str(getattr(args, "signature_url", None) or os.getenv("UNIO_COLLECTOR_RELEASE_SIGNATURE_URL", "")),
        )
        result = CollectorVersionChecker().check(current_version=__version__, options=options)
        if bool(getattr(args, "json", False)):
            self.console.print(json.dumps(result, indent=2, sort_keys=True), markup=False, soft_wrap=True)
        else:
            self.console.print(f"Installed: {result['installed_version']}")
            self.console.print(f"Available: {result['available_version']}")
            self.console.print(f"Status: {result['status']}")
        if result["status"] == "verification_failed":
            return 1
        return 0


__all__ = ["CollectorVersionService"]
