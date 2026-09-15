from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

from unio_collector.scanners.service_quota.parsing import normalize_quota_text

if TYPE_CHECKING:
    from unio_collector.scanners.service_quota.check_spec import (
        ServiceQuotaCheckSpec,
    )


class ServiceQuotaMatcher:
    """Match named Service Quotas records to conservative usage checks."""

    def select_quota(  # noqa: D102
        self,
        quotas: list[dict[str, Any]],
        spec: ServiceQuotaCheckSpec,
    ) -> dict[str, Any] | None:
        terms = tuple(normalize_quota_text(term) for term in spec.quota_name_terms)
        exact_candidates: list[dict[str, Any]] = []
        partial_candidates: list[dict[str, Any]] = []
        for quota in quotas:
            name = str(quota.get("QuotaName") or "")
            normalized_name = normalize_quota_text(name)
            if not normalized_name:
                continue
            if normalized_name in terms:
                exact_candidates.append(quota)
                continue
            if any(term in normalized_name for term in terms):
                partial_candidates.append(quota)
        candidates = exact_candidates or partial_candidates
        if len(candidates) != 1:
            return None
        return candidates[0]
