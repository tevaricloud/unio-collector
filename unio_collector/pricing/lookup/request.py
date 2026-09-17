from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class PricingLookupRequest:  # noqa: D101
    request_type: Literal[
        "ebs_volume",
        "snapshot",
        "logs_storage",
        "public_ipv4",
    ]
    region: str
    location: str
    volume_type: str | None = None
