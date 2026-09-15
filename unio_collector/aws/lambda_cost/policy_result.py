from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.lambda_cost.function.policy import LambdaFunctionPolicyTarget


@dataclass(frozen=True)
class LambdaPolicyTargetCollectionResult:  # noqa: D101
    targets: list[LambdaFunctionPolicyTarget]
    error_count: int = 0
