"""Finite actual-resource field catalogue; no observed-key or wildcard admission."""

from unio_collector.privacy.recommendation.sdk.ebs import EBS_VOLUME
from unio_collector.privacy.recommendation.sdk.ec2 import EC2_INSTANCE
from unio_collector.privacy.recommendation.sdk.ecs import ECS_SERVICE
from unio_collector.privacy.recommendation.sdk.hub import HUB
from unio_collector.privacy.recommendation.sdk.idle import IDLE
from unio_collector.privacy.recommendation.sdk.lambda_ import LAMBDA_FUNCTION
from unio_collector.privacy.recommendation.sdk.rds import RDS_DATABASE
from unio_collector.privacy.recommendation.sdk.summary import COMPUTE_OPTIMIZER_SUMMARY, COST_OPTIMIZATION_HUB_SUMMARY

RECORD_FIELDS = {
    "ec2_instance": EC2_INSTANCE,
    "ebs_volume": EBS_VOLUME,
    "lambda_function": LAMBDA_FUNCTION,
    "rds_database": RDS_DATABASE,
    "ecs_service": ECS_SERVICE,
    "idle": IDLE,
    "hub": HUB,
}

SUMMARY_FIELDS = {"compute_optimizer": COMPUTE_OPTIMIZER_SUMMARY, "cost_optimization_hub": COST_OPTIMIZATION_HUB_SUMMARY}
