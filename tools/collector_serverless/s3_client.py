"""Synthetic bucket index and complete Lambda notification response envelopes."""

from __future__ import annotations

from typing import Any

from tools.collector_serverless.base import SyntheticServerlessClient, synthetic_arn


class SyntheticNotificationClient(SyntheticServerlessClient):
    """Feed actual S3 index construction, selection and notification serialization."""

    def list_buckets(self, **_kwargs: object) -> dict[str, Any]:
        """Populate two real index inputs with declared regions and no location lookup."""
        return self._response(
            "list_buckets",
            "Buckets",
            [{"Name": name, "BucketRegion": "eu-west-2"} for name in ("synthetic-customer-bucket", "synthetic-customer-second-bucket")],
        )

    def get_bucket_location(self, **_kwargs: object) -> dict[str, Any]:
        """Keep the actual supported fallback local if requested."""
        self._fail("get_bucket_location")
        return {"LocationConstraint": "eu-west-2"}

    def get_bucket_notification_configuration(self, **_kwargs: object) -> dict[str, Any]:
        """Drive populated events/filter rules through the real notification builder."""
        self._fail("get_bucket_notification_configuration")
        return {
            "LambdaFunctionConfigurations": [
                {
                    "LambdaFunctionArn": synthetic_arn("lambda", "function:synthetic-customer-function"),
                    "Events": ["s3:ObjectCreated:*"],
                    "Filter": {"Key": {"FilterRules": [{"Name": "prefix", "Value": "synthetic-customer-prefix/"}, {"Name": "suffix", "Value": ".json"}]}},
                }
            ]
        }
