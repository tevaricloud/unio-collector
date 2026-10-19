"""Finite explicit provider record-view selection; no decoder imports."""

from __future__ import annotations

from typing import TYPE_CHECKING

from unio_collector.privacy.recommendation.ebs import EbsRecommendationContract
from unio_collector.privacy.recommendation.ec2 import Ec2RecommendationContract
from unio_collector.privacy.recommendation.ecs import EcsRecommendationContract
from unio_collector.privacy.recommendation.hub_record import HubRecommendationRecordContract
from unio_collector.privacy.recommendation.idle import IdleRecommendationContract
from unio_collector.privacy.recommendation.lambda_ import LambdaRecommendationContract
from unio_collector.privacy.recommendation.rds import RdsRecommendationContract

if TYPE_CHECKING:
    from unio_collector.privacy.recommendation.record import RecommendationRecordContract

RECORD_CONTRACTS = {
    "ec2_instance": Ec2RecommendationContract,
    "ebs_volume": EbsRecommendationContract,
    "lambda_function": LambdaRecommendationContract,
    "rds_database": RdsRecommendationContract,
    "ecs_service": EcsRecommendationContract,
    "idle": IdleRecommendationContract,
    "hub": HubRecommendationRecordContract,
}


def select_recommendation_record(kind: str) -> RecommendationRecordContract:
    """Instantiate only an enumerated reviewed provider resource contract."""
    return RECORD_CONTRACTS[kind]()
