from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class AlbOriginListenerRecord:
    """Listener evidence collected for a matched ALB."""

    load_balancer_arn: str
    region: str
    port: int
    protocol: str
    evidence_ref: str = ""
    listener_arn: str = ""
    default_action_types: tuple[str, ...] = ()
    default_fixed_response_status: str = ""
    default_deny: bool = False
