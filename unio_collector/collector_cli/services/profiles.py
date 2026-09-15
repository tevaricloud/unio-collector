from __future__ import annotations  # noqa: D100

import json
from typing import Any

import boto3


class CollectorProfilesService:
    """List local AWS profile names without exposing credential material."""

    def __init__(self, console: Any) -> None:  # noqa: ANN401
        """Store the output console."""
        self.console = console

    def run(self, args: object) -> int:
        """Print deterministic local profile metadata."""
        names = tuple(sorted(set(boto3.Session().available_profiles)))
        if bool(getattr(args, "json", False)):
            payload = {
                "profiles": list(names),
                "provider": "aws",
                "schema_version": 1,
            }
            self.console.print(json.dumps(payload, indent=2, sort_keys=True), markup=False, soft_wrap=True)
            return 0
        if not names:
            self.console.print("No named AWS profiles were found; the default credential chain remains available.")
            return 0
        for name in names:
            self.console.print(name)
        return 0


__all__ = ["CollectorProfilesService"]
