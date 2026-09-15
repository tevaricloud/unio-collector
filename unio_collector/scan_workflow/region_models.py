"""Region-scope data contracts for AWS scanner execution."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AwsRegionAvailability:
    """Account-level availability for one AWS region."""

    region_name: str
    opt_in_status: str
    status: str
    reason: str = ""

    def convert_to_dict(self) -> dict[str, str]:
        """Return a JSON-safe region availability record."""
        payload = {
            "region_name": self.region_name,
            "opt_in_status": self.opt_in_status,
            "status": self.status,
        }
        if self.reason:
            payload["reason"] = self.reason
        return payload
