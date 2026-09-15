from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class IamAccountSecurityCollectionOptions:  # noqa: D101
    policy_detail_mode: str = "administrator-access-only"
