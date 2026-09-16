from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import Literal

type HeaderMatchState = Literal["matched", "not_matched", "control_present", "unknown"]


@dataclass(frozen=True)
class OriginHeaderVerificationRecord:
    """Derived header-control state that never contains a header value."""

    distribution_id: str
    origin_id: str
    listener_arn: str
    rule_priority: str
    header_name: str
    control_present: bool
    match_state: HeaderMatchState
    forward_action: bool
    evidence_ref: str = ""
