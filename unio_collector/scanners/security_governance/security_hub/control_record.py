from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class SecurityHubControlRecord:  # noqa: D101
    region: str
    control_id: str
    title: str
    severity_label: str
    failed_finding_count: int
    standard_arns: tuple[str, ...] = ()
    resource_types: tuple[str, ...] = ()
