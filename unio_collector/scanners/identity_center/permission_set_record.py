from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class IdentityCenterPermissionSetRecord:  # noqa: D101
    instance_arn: str
    identity_store_id: str | None
    permission_set_arn: str
    name: str
    description: str | None = None
    session_duration: str | None = None
    relay_state: str | None = None
    managed_policy_arns: tuple[str, ...] = ()
    customer_managed_policy_names: tuple[str, ...] = ()
