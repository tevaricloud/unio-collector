"""Synthetic SDK function, mapping, configuration and tag responses."""

from __future__ import annotations

from typing import Any

from tools.collector_serverless.base import SyntheticServerlessClient, synthetic_arn


class SyntheticLambdaClient(SyntheticServerlessClient):
    """Drive actual inventory caching, event topology and optional configuration."""

    def _function(self, name: str) -> dict[str, Any]:
        row = {
            "FunctionName": name,
            "FunctionArn": synthetic_arn("lambda", "function:" + name),
            "Runtime": "python3.12",
            "MemorySize": 256,
            "Timeout": 30,
            "Architectures": ["arm64"],
            "Environment": {"Variables": {"TARGET_BUCKET": "synthetic-customer-bucket", "CUSTOMER_HINT": "synthetic-customer-prose"}},
        }
        if self.session.variant in {"url_environment", "case_environment", "unrelated_environment", "native"}:
            target = {
                "url_environment": "s3://synthetic-customer-bucket/synthetic-private-output",
                "case_environment": "SYNTHETIC-CUSTOMER-BUCKET",
                "unrelated_environment": "synthetic-customer-unrelated",
                "native": "s3://synthetic-customer-bucket/synthetic-private-output",
            }[self.session.variant]
            row["Environment"]["Variables"]["TARGET_BUCKET"] = target
        if self.session.variant == "nullable":
            row.update(Runtime=None, MemorySize=None, Timeout=None, Architectures=None, Environment=None)
        return row

    def list_functions(self, **_kwargs: object) -> dict[str, Any]:
        """Return two populated actual SDK functions or the declared empty shape."""
        return self._response("list_functions", "Functions", [self._function(name) for name in ("synthetic-customer-function", "synthetic-customer-second")])

    def list_event_source_mappings(self, **_kwargs: object) -> dict[str, Any]:
        """Exercise SQS and non-SQS filtering, nullable fields and operational caps."""
        rows = [
            {
                "UUID": "synthetic-customer-mapping-" + str(index),
                "FunctionArn": synthetic_arn("lambda", "function:synthetic-customer-function"),
                "EventSourceArn": synthetic_arn("sqs", "synthetic-customer-queue-" + str(index)),
                "State": "Enabled",
                "BatchSize": 10,
            }
            for index in (1, 2)
        ]
        if self.session.variant == "nullable":
            rows[0].update(FunctionArn=None, State=None, BatchSize=None)
        rows.append(
            {
                "UUID": "synthetic-customer-stream",
                "FunctionArn": synthetic_arn("lambda", "function:synthetic-customer-second"),
                "EventSourceArn": synthetic_arn("dynamodb", "table/synthetic-customer-table/stream/synthetic"),
                "State": "Disabled",
                "BatchSize": 1,
            }
        )
        return self._response("list_event_source_mappings", "EventSourceMappings", rows)

    def get_function_configuration(self, **kwargs: object) -> dict[str, Any]:
        """Drive actual additional configuration only when topology requires it."""
        self._fail("get_function_configuration")
        return self._function(str(kwargs["FunctionName"]))

    def get_function_event_invoke_config(self, **_kwargs: object) -> dict[str, Any]:
        """Populate both exact destination branches and nullable absence."""
        self._fail("get_function_event_invoke_config")
        return {
            "DestinationConfig": {}
            if self.session.variant == "nullable"
            else {
                "OnSuccess": {"Destination": synthetic_arn("sqs", "synthetic-customer-success")},
                "OnFailure": {"Destination": synthetic_arn("sqs", "synthetic-customer-failure")},
            }
        }

    def list_tags(self, **_kwargs: object) -> dict[str, Any]:
        """Retain actual known/unavailable tag evidence and dynamic customer keys."""
        self._fail("list_tags")
        tags = {"synthetic-customer-key": "synthetic-customer-value"}
        if self.session.variant in {"environment_tags", "native"}:
            tags.update(Environment="production", Owner="production")
        return {"Tags": tags}
