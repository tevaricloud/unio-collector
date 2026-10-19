"""Finite producer controls and semantic public versions, never arbitrary resource labels."""

from __future__ import annotations

import re
from functools import lru_cache

from botocore.loaders import Loader

CONTROLS = {
    "Amazon RDS": ("RDS instance", "rds:DescribeDBInstances"),
    "AWS Lambda": ("Lambda function", "lambda:ListFunctions"),
    "Amazon EC2": ("EC2 instance AMI", "ec2:DescribeInstances/ec2:DescribeImages"),
    "Amazon ElastiCache": ("ElastiCache cluster", "elasticache:DescribeCacheClusters"),
    "Amazon OpenSearch Service": ("OpenSearch domain", "opensearch:ListDomainNames/opensearch:DescribeDomains"),
    "Amazon EKS": ("EKS cluster", "eks:ListClusters/eks:DescribeCluster"),
}
RDS_ENGINES = frozenset(
    {
        "mysql",
        "postgres",
        "mariadb",
        "aurora",
        "aurora-mysql",
        "aurora-postgresql",
        "oracle-ee",
        "oracle-se2",
        "sqlserver-ee",
        "sqlserver-se",
        "sqlserver-ex",
        "sqlserver-web",
    }
)
ENGINES = {
    "Amazon RDS": RDS_ENGINES,
    "Amazon EC2": {"ami"},
    "Amazon ElastiCache": {"redis", "memcached", "valkey"},
    "Amazon OpenSearch Service": {"opensearch"},
    "Amazon EKS": {"kubernetes"},
}


@lru_cache(maxsize=1)
def lambda_runtimes() -> frozenset[str]:
    """Read the installed SDK's finite public runtime vocabulary without creating clients."""
    model = Loader().load_service_model("lambda", "service-2")
    return frozenset(model["shapes"]["Runtime"]["enum"])


def public_engine(service: str, value: object) -> bool:
    """Only complete finite engine/runtime identities are public metadata."""
    return isinstance(value, str) and value in (lambda_runtimes() if service == "AWS Lambda" else ENGINES.get(service, set()))


def public_version(service: str, engine: object, value: object) -> bool:
    """Retain semantic versions only under their supported public engine; AMI IDs protect."""
    if not isinstance(value, str) or not public_engine(service, engine):
        return False
    if service == "AWS Lambda":
        return value == engine and value in lambda_runtimes()
    if service in {"Amazon RDS", "Amazon ElastiCache", "Amazon EKS"}:
        return re.fullmatch(r"[0-9]{1,4}(?:\.[0-9]{1,4}){0,5}", value) is not None
    return service == "Amazon OpenSearch Service" and re.fullmatch(r"(?:OpenSearch|Elasticsearch)_[0-9]{1,3}(?:\.[0-9]{1,3}){1,2}", value) is not None
