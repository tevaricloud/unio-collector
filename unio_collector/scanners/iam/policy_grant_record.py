from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class IamPolicyGrantRecord:  # noqa: D101
    principal_type: str
    principal_name: str
    policy_source: str
    policy_name: str
    principal_arn: str | None = None
    policy_arn: str | None = None
    policy_document: dict[str, Any] | None = None
