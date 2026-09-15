"""Stable numeric identities for provider metric collection contexts."""

from enum import IntEnum


class MetricCollectionContext(IntEnum):
    """Identify the resource inventory that requested provider observations."""

    EC2_INSTANCE = 1
    RDS_INSTANCE = 2
    LOAD_BALANCER = 3
    ELASTICACHE_CLUSTER = 4
    DYNAMODB_TABLE = 5
    LOG_GROUP = 6
    NAT_GATEWAY = 7
