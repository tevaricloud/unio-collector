"""Pricing and currency package.

Public imports from ``unio_collector.pricing`` remain supported. New implementation
code should live in focused modules under this package instead of root-level
pricing modules. Application-only exports remain lazy until an explicit
versioned public import migration retires their compatibility names.
"""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING

from unio_collector.pricing.enrich.constants import (
    EXPECTED_PRICING_STOP_REASONS,
    REGION_LOCATION_NAMES,
)
from unio_collector.pricing.enrich.status import PricingEnrichmentStatus
from unio_collector.pricing.enrich.utils import (
    decimal_or_none,
    extract_on_demand_rate,
    first_signal,
    format_status_label,
    int_or_zero,
    normalize_to_monthly,
    term_match_filter,
)
from unio_collector.pricing.lookup.budget_estimate import PricingLookupBudgetEstimate
from unio_collector.pricing.lookup.diagnostic import PricingLookupDiagnostic
from unio_collector.pricing.lookup.plan import PricingLookupPlan
from unio_collector.pricing.lookup.request import PricingLookupRequest
from unio_collector.pricing.product_finder import PricingApiProductFinder
from unio_collector.pricing.progress import PricingRateProgress
from unio_collector.pricing.provider_protocol import PricingRateProvider
from unio_collector.pricing.rates import PricingRates
from unio_collector.pricing.stops import (
    PricingLookupStopped,
    PricingLookupStoppedError,
    is_expected_pricing_stop,
)
from unio_collector.pricing.unit_rate import UnitRate

if TYPE_CHECKING:
    from unio_collector.aws.pricing.client_config import build_pricing_client_config
    from unio_collector.aws.pricing.rate.provider import AwsPricingRateProvider
    from unio_collector.pricing.estimate_enricher import PricingEstimateEnricher
    from unio_collector.pricing.status import PricingEnrichmentStatusInterpreter
    from unio_collector.pricing.usage_cost_pools import UsageCostPools


def __getattr__(name: str) -> object:
    if name == "UsageCostPools":
        return import_module("unio_collector.pricing.usage_cost_pools").UsageCostPools
    if name == "PricingEnrichmentStatusInterpreter":
        return import_module("unio_collector.pricing.status").PricingEnrichmentStatusInterpreter
    if name == "PricingEstimateEnricher":
        return import_module("unio_collector.pricing.estimate_enricher").PricingEstimateEnricher
    if name == "AwsPricingRateProvider":
        return import_module("unio_collector.aws.pricing.rate.provider").AwsPricingRateProvider
    if name == "build_pricing_client_config":
        return import_module("unio_collector.aws.pricing.client_config").build_pricing_client_config
    msg = f"module 'unio_collector.pricing' has no attribute {name!r}"
    raise AttributeError(msg)


__all__ = [
    "EXPECTED_PRICING_STOP_REASONS",
    "REGION_LOCATION_NAMES",
    "AwsPricingRateProvider",
    "PricingApiProductFinder",
    "PricingEnrichmentStatus",
    "PricingEnrichmentStatusInterpreter",
    "PricingEstimateEnricher",
    "PricingLookupBudgetEstimate",
    "PricingLookupDiagnostic",
    "PricingLookupPlan",
    "PricingLookupRequest",
    "PricingLookupStopped",
    "PricingLookupStoppedError",
    "PricingRateProgress",
    "PricingRateProvider",
    "PricingRates",
    "UnitRate",
    "UsageCostPools",
    "build_pricing_client_config",
    "decimal_or_none",
    "extract_on_demand_rate",
    "first_signal",
    "format_status_label",
    "int_or_zero",
    "is_expected_pricing_stop",
    "normalize_to_monthly",
    "term_match_filter",
]
