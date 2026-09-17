from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field

from unio_collector.aws.client.config import AwsRuntimeConfig
from unio_collector.config.scan.profiles import FULL_SCAN_DETAIL_PROFILE
from unio_collector.evidence.tagging.defaults import DEFAULT_COST_GROUP_TAGS


@dataclass(frozen=True)
class CollectorFileConfig:
    """Collector-safe subset of YAML configuration."""

    provider_id: str = "aws"
    azure_subscription_id: str | None = None
    entra_tenant_id: str | None = None
    gcp_project_id: str | None = None
    preset: str | None = None
    scan_mode: str | None = None
    product_id: str | None = None
    pillars: tuple[str, ...] = ()
    regions: tuple[str, ...] = ()
    regions_from_billing: bool = False
    mode: str | None = None
    detail_profile: str = FULL_SCAN_DETAIL_PROFILE
    allow_chargeable_scanners: bool = False
    service_usage_precheck_enabled: bool = True
    force_service_scanners: bool = False
    required_tags: tuple[str, ...] = ()
    scanner_states: dict[str, bool] = field(default_factory=dict)
    scanner_options: dict[str, dict[str, object]] = field(default_factory=dict)
    cost_grouping_enabled: bool = True
    cost_grouping_tags: tuple[str, ...] = DEFAULT_COST_GROUP_TAGS
    cur_paths: tuple[str, ...] = ()
    currency: str = "USD"
    date_format: str = "DD/MM/YYYY"
    pricing_enrichment_enabled: bool = True
    pricing_enrichment_timeout_seconds: int = 30
    pricing_api_call_timeout_seconds: int = 2
    pricing_max_api_calls: int = 500
    pricing_worker_count: int = 4
    runtime: AwsRuntimeConfig = field(default_factory=AwsRuntimeConfig)
    configured_keys: frozenset[str] = frozenset()
    diagnostics: tuple[str, ...] = ()

    def has_configured_value(self, key: str) -> bool:
        """Return whether YAML explicitly supplied a collector-safe key."""
        return key in self.configured_keys


__all__ = ["CollectorFileConfig"]
