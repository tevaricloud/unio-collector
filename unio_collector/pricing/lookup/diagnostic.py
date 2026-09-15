from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class PricingLookupDiagnostic:  # noqa: D101
    request_type: str
    region: str
    location: str
    service_code: str
    lookup_key: str | None
    status: str
    page_count: int
    product_count: int
    matched: bool
    filters: tuple[dict[str, str], ...] = ()
    error: str | None = None

    def convert_to_dict(self) -> dict[str, Any]:  # noqa: D102
        payload: dict[str, Any] = {
            "request_type": self.request_type,
            "region": self.region,
            "location": self.location,
            "service_code": self.service_code,
            "lookup_key": self.lookup_key,
            "status": self.status,
            "page_count": self.page_count,
            "product_count": self.product_count,
            "matched": self.matched,
            "filters": [dict(item) for item in self.filters],
        }
        if self.error:
            payload["error"] = self.error
        return payload
