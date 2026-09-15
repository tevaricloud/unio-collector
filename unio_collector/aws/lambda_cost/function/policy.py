from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class LambdaFunctionPolicyTarget:  # noqa: D101
    function_name: str
    function_arn: str
    region: str
