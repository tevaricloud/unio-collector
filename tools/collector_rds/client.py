"""Finite RDS and CloudWatch response branches; never make network calls."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

from botocore.exceptions import ClientError

VARIANTS = (
    "success",
    "optional",
    "empty",
    "denied",
    "unavailable",
    "unsupported",
    "failure",
    "partial_region",
    "partial_page",
    "tag_denied",
    "metrics_denied",
    "metrics_partial",
    "metrics_empty",
    "metrics_malformed",
    "metrics_missing",
    "statistics_fallback",
    "collision",
    "stopped",
    "stopping",
    "custom_status",
)
STAMP = datetime(2026, 7, 1, tzinfo=UTC)


class SyntheticRdsClient:
    """Serve only the declared read operations with recorded request arguments."""

    def __init__(self, service: str, region: str, variant: str, calls: list[dict[str, Any]]) -> None:
        """Bind the exact offline service, region and scenario."""
        self.service, self.region, self.variant, self.calls = service, region, variant, calls

    def _record(self, operation: str, parameters: dict[str, Any]) -> None:
        self.calls.append({"service": self.service, "region": self.region, "operation": operation, "parameters": parameters})
        codes = {"denied": "AccessDenied", "unavailable": "ServiceUnavailable", "unsupported": "UnsupportedOperation", "failure": "InternalFailure"}
        code = codes.get(self.variant)
        if self.variant == "partial_region" and self.region == "eu-west-1":
            code = "AccessDenied"
        if self.variant == "partial_page" and parameters.get("Marker"):
            code = "ThrottlingException"
        if self.variant == "tag_denied" and operation == "ListTagsForResource":
            code = "AccessDenied"
        if self.service == "cloudwatch" and (self.variant == "metrics_denied" or (self.variant == "statistics_fallback" and operation == "GetMetricData")):
            code = "AccessDenied"
        if code:
            raise ClientError({"Error": {"Code": code, "Message": "Synthetic RDS provider limitation"}}, operation)

    def describe_db_instances(self, **parameters: object) -> dict[str, Any]:
        """Return actual instance response fields and optional defaults."""
        self._record("DescribeDBInstances", parameters)
        self._require(condition=self.service == "rds")
        name = "available" if self.variant == "collision" else "synthetic-customer-db"
        row = {
            "DBInstanceIdentifier": name,
            "DBInstanceClass": "db.m6g.large",
            "Engine": "postgres",
            "DBInstanceStatus": self.variant
            if self.variant in {"stopped", "stopping"}
            else "synthetic-customer-status"
            if self.variant == "custom_status"
            else "available",
            "DBInstanceArn": self._arn("db", name),
            "AllocatedStorage": 100,
        }
        if self.variant == "optional":
            row = {"DBInstanceIdentifier": name}
        return {"DBInstances": [] if self.variant == "empty" else [row], **({"Marker": "synthetic-page"} if self.variant == "partial_page" else {})}

    def _arn(self, kind: str, name: str) -> str:
        prefix = "arn"
        return f"{prefix}:aws:rds:{self.region}:123456789012:{kind}:{name}"

    def _snapshots(self, *, cluster: bool, parameters: dict[str, object]) -> dict[str, Any]:
        self._record("DescribeDBClusterSnapshots" if cluster else "DescribeDBSnapshots", parameters)
        self._require(condition=self.service == "rds" and parameters["SnapshotType"] == "manual")
        prefix = "DBCluster" if cluster else "DB"
        name = "available" if self.variant == "collision" else "synthetic-customer-snapshot"
        row = {
            prefix + "SnapshotIdentifier": name,
            prefix + "SnapshotArn": self._arn("cluster-snapshot" if cluster else "snapshot", name),
            ("DBClusterIdentifier" if cluster else "DBInstanceIdentifier"): "synthetic-customer-source",
            "SnapshotCreateTime": STAMP,
            "SnapshotType": "manual",
            "Engine": "postgres",
            "Status": "available",
            "AllocatedStorage": 100,
        }
        if self.variant == "optional":
            row = {"SnapshotCreateTime": STAMP, "Engine": None, "Status": None, "AllocatedStorage": None}
        rows = [] if self.variant == "empty" else [row, {prefix + "SnapshotIdentifier": "synthetic-missing-time"}]
        return {prefix + "Snapshots": rows, **({"Marker": "synthetic-page"} if self.variant == "partial_page" else {})}

    def describe_db_snapshots(self, **parameters: object) -> dict[str, Any]:
        """Return DB snapshots including a missing-time row the producer skips."""
        return self._snapshots(cluster=False, parameters=parameters)

    def describe_db_cluster_snapshots(self, **parameters: object) -> dict[str, Any]:
        """Return cluster snapshots through the actual snapshot plan."""
        return self._snapshots(cluster=True, parameters=parameters)

    def list_tags_for_resource(self, **parameters: object) -> dict[str, Any]:
        """Return arbitrary tag keys/values for real tag conversion."""
        self._record("ListTagsForResource", parameters)
        self._require(condition=self.service == "rds")
        return {"TagList": [{"Key": "Owner", "Value": "synthetic-customer-owner"}, {"Key": "Name", "Value": "synthetic-customer-resource"}]}

    def get_metric_data(self, **parameters: object) -> dict[str, Any]:
        """Exercise real query grouping, completeness and sample parsing."""
        self._record("GetMetricData", parameters)
        self._require(condition=self.service == "cloudwatch")
        rows = []
        for query in cast("list[dict[str, Any]]", parameters["MetricDataQueries"]):
            self._require(condition=query["MetricStat"]["Metric"]["Namespace"] == "AWS/RDS")
            values = [] if self.variant == "metrics_empty" else [12.0, 20.0]
            times = [] if self.variant == "metrics_empty" else [STAMP, STAMP.replace(day=2)]
            if self.variant == "metrics_malformed":
                times = []
            rows.append(
                {"Id": query["Id"], "Values": values, "Timestamps": times, "StatusCode": "PartialData" if self.variant == "metrics_partial" else "Complete"}
            )
        return {"MetricDataResults": [] if self.variant == "metrics_missing" else rows}

    def get_metric_statistics(self, **parameters: object) -> dict[str, Any]:
        """Exercise the actual single-statistic fallback path."""
        self._record("GetMetricStatistics", parameters)
        self._require(condition=self.service == "cloudwatch")
        return {"Datapoints": [{"Timestamp": STAMP, "Average": 12.0}, {"Timestamp": STAMP.replace(day=2), "Average": 20.0}]}

    def _require(self, *, condition: bool) -> None:
        if not condition:
            message = "Unexpected synthetic RDS request"
            raise AssertionError(message)
