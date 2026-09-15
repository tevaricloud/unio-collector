from __future__ import annotations  # noqa: D100

from datetime import datetime  # noqa: TC003
from typing import Any, Literal

from pydantic import Field

from unio_collector.core.base_model import UnioBaseModel

EvidenceConfidence = Literal["low", "medium", "high", "unknown"]


class EvidenceRecord(UnioBaseModel):  # noqa: D101
    evidence_id: str
    source_scanner_id: str
    collector_id: str
    account_id: str | None = None
    region: str = "global"
    service: str
    resource_type: str | None = None
    resource_id: str | None = None
    resource_name: str | None = None
    arn: str | None = None
    tags: dict[str, str] = Field(default_factory=dict)
    relationships: list[dict[str, Any]] = Field(default_factory=list)
    metrics: list[dict[str, Any]] = Field(default_factory=list)
    costs: list[dict[str, Any]] = Field(default_factory=list)
    timestamps: dict[str, str] = Field(default_factory=dict)
    raw_reference_id: str | None = None
    collection_time: datetime
    confidence: EvidenceConfidence = "unknown"
    limitations: list[str] = Field(default_factory=list)
