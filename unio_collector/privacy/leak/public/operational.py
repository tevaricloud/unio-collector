"""Reproduced operational counter collisions; no financial or arbitrary numeric exemptions."""

from __future__ import annotations

from math import isfinite
from typing import TYPE_CHECKING

from unio_collector.privacy.account_risk import AccountRiskPrivacyContract
from unio_collector.privacy.analytics.glue import GluePrivacyContract
from unio_collector.privacy.platform.ecs import EcsPrivacyContract

if TYPE_CHECKING:
    from unio_collector.privacy.closed_schema import ClosedProducerContract


class OperationalScanPolicy:
    """Keep exact ECS memory, IAM quota and Glue configuration roles separate from customer values."""

    @staticmethod
    def number(contract: ClosedProducerContract, suffix: str, value: object) -> bool:
        """Normalize only the reproduced identity-bound nonfinancial counter positions."""
        if isinstance(contract, GluePrivacyContract) and suffix == "records[].configured_run_dpu":
            return (
                contract.fields.get(suffix) == ("number", "safe_metadata", True)
                and isinstance(value, int | float)
                and not isinstance(value, bool)
                and isfinite(value)
            )
        expected = (
            ("count", "summary_count", False)
            if isinstance(contract, EcsPrivacyContract) and suffix == "records[].task_definition_memory_mb_total"
            else ("count", "safe_metadata", False)
            if isinstance(contract, AccountRiskPrivacyContract) and suffix == "account_risk.iam_summary.RolePolicySizeQuota"
            else None
        )
        return expected is not None and contract.fields.get(suffix) == expected and type(value) is int and value >= 0

    @staticmethod
    def container_invalid(value: object, contract: ClosedProducerContract, suffix: str) -> bool | None:
        """Require the independently closed parent before public-counter normalization."""
        if isinstance(contract, AccountRiskPrivacyContract) and suffix == "account_risk.iam_summary":
            return bool(contract.unknown_paths(value, "", suffix))
        if isinstance(contract, GluePrivacyContract) and suffix == "records[]":
            return OperationalScanPolicy.glue_invalid(value, contract, suffix)
        if isinstance(contract, EcsPrivacyContract) and suffix == "records[]":
            if not isinstance(value, dict) or not {"account_id", "region", "task_definition_memory_mb_total"}.issubset(value):
                return True
            checked = dict(value)
            for key, child in value.items():
                spec = contract.fields.get(suffix + "." + key)
                if spec is not None and spec[1] == "cost" and spec[2] and child == "":
                    checked[key] = None
            return bool(contract.unknown_paths(checked, "", suffix))
        return None

    @staticmethod
    def glue_invalid(value: object, contract: GluePrivacyContract, suffix: str) -> bool:
        """Require the complete typed parent, recognizing only existing strict financial omissions."""
        if not isinstance(value, dict) or not {"account_id", "region", "configured_run_dpu"}.issubset(value):
            return True
        checked = dict(value)
        for key, child in value.items():
            spec = contract.fields.get(suffix + "." + key)
            if spec is not None and spec[1] == "cost":
                if child is None and spec[0] == "array":
                    checked[key] = []
                elif child == "" and spec[2]:
                    checked[key] = None
        return bool(contract.unknown_paths(checked, "", suffix))
