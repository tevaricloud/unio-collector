from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field


@dataclass(frozen=True)
class S3LambdaNotificationRecord:  # noqa: D101
    bucket_name: str
    lambda_function_arn: str
    events: list[str] = field(default_factory=list)
    filter_rules: list[dict[str, str]] = field(default_factory=list)

    def convert_to_dict(self) -> dict[str, object]:  # noqa: D102
        return {
            "bucket_name": self.bucket_name,
            "lambda_function_arn": self.lambda_function_arn,
            "events": list(self.events),
            "filter_rules": list(self.filter_rules),
        }
