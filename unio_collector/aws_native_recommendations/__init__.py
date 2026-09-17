from __future__ import annotations  # noqa: D104

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.aws_native_recommendations.builder import (
        AwsNativeRecommendationEnricher,
    )
    from unio_collector.aws_native_recommendations.reports import (
        AwsNativeRecommendationReportRenderer,
        render_action_plan_aws_native_recommendation_summary,
        render_business_aws_native_recommendation_summary,
        render_start_here_aws_native_recommendation_summary,
        render_technical_aws_native_recommendation_summary,
    )

_EXPORTS = {
    "AwsNativeRecommendationEnricher": ("unio_collector.aws_native_recommendations.builder"),
    "AwsNativeRecommendationReportRenderer": ("unio_collector.aws_native_recommendations.reports"),
    "render_action_plan_aws_native_recommendation_summary": ("unio_collector.aws_native_recommendations.reports"),
    "render_business_aws_native_recommendation_summary": ("unio_collector.aws_native_recommendations.reports"),
    "render_start_here_aws_native_recommendation_summary": ("unio_collector.aws_native_recommendations.reports"),
    "render_technical_aws_native_recommendation_summary": ("unio_collector.aws_native_recommendations.reports"),
}

__all__ = [
    "AwsNativeRecommendationEnricher",
    "AwsNativeRecommendationReportRenderer",
    "render_action_plan_aws_native_recommendation_summary",
    "render_business_aws_native_recommendation_summary",
    "render_start_here_aws_native_recommendation_summary",
    "render_technical_aws_native_recommendation_summary",
]


def __getattr__(name: str) -> Any:  # noqa: ANN401
    """Resolve recommendation exports without loading report code eagerly."""
    module_name = _EXPORTS.get(name)
    if module_name is None:
        raise AttributeError(name)
    value = getattr(import_module(module_name), name)
    globals()[name] = value
    return value
