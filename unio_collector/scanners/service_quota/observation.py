"""Provider quota and resource-count observations without advisory policy."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from decimal import Decimal


@dataclass(frozen=True)
class ServiceQuotaObservation:
    """Retain one whole quota read and its corresponding usage-count outcome."""

    check_id: str
    region: str
    service: str
    resource_type: str
    quota_name: str
    quota_code: str | None
    quota_value: Decimal | None
    quota_found: bool
    current_usage: int | None
    confidence: str
    resource_count_method: str
    limitation: str | None = None

    def convert_to_dict(self) -> dict[str, Any]:
        """Serialize factual fields without classifying quota headroom."""
        return {
            "check_id": self.check_id,
            "region": self.region,
            "service": self.service,
            "resource_type": self.resource_type,
            "quota_name": self.quota_name,
            "quota_code": self.quota_code,
            "quota_value": str(self.quota_value) if self.quota_value is not None else None,
            "quota_found": self.quota_found,
            "current_usage": self.current_usage,
            "confidence": self.confidence,
            "resource_count_method": self.resource_count_method,
            "limitation": self.limitation,
        }
