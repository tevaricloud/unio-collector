from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class ServiceQuotaCheckSpec:  # noqa: D101
    check_id: str
    service: str
    quota_service_code: str
    quota_code: str
    quota_name_terms: tuple[str, ...]
    resource_type: str
    usage_method: str
