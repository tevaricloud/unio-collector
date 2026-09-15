from __future__ import annotations  # noqa: D100

from dataclasses import dataclass

from unio_collector.aws.lambda_cost.function.policy import LambdaFunctionPolicyTarget


@dataclass(frozen=True)
class LambdaFunctionInventoryRecord:  # noqa: D101
    function_name: str
    function_arn: str
    region: str
    function: dict[str, object]

    def get_policy_target(self) -> LambdaFunctionPolicyTarget | None:  # noqa: D102
        if not self.function_name or not self.function_arn:
            return None
        return LambdaFunctionPolicyTarget(
            function_name=self.function_name,
            function_arn=self.function_arn,
            region=self.region,
        )
