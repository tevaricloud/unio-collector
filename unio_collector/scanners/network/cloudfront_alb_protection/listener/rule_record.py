from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class AlbOriginListenerRuleRecord:
    """Listener-rule evidence with condition values removed."""

    listener_arn: str
    priority: str
    action_types: tuple[str, ...] = ()
    default_rule: bool = False
    fixed_response_status: str = ""
    default_deny: bool = False
    host_header_control_present: bool = False
    host_header_matches_origin: bool = False
    http_header_control_names: tuple[str, ...] = ()
    evidence_ref: str = ""
