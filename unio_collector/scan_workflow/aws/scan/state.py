from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from unio_collector.aws.cache import AwsScanCache

if TYPE_CHECKING:
    from unio_collector.aws.audit import ApiCallLedger
    from unio_collector.aws.session import AuditedAwsSession
    from unio_collector.collector.config.protocol import CollectionConfigProtocol
    from unio_collector.scan_workflow.regions import AwsRegionScope


@dataclass
class AwsScanState:
    """Mutable runtime state shared across read-only scanner execution."""

    config: CollectionConfigProtocol
    session: AuditedAwsSession
    account_id: str
    ledger: ApiCallLedger
    cache: AwsScanCache = field(default_factory=AwsScanCache)
    region_scope: AwsRegionScope | None = None
