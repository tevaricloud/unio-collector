from __future__ import annotations  # noqa: D104

# pyright: reportUnsupportedDunderAll=false
from importlib import import_module
from typing import Any

_EXPORTS = {
    "AwsConfigComplianceReviewScanner": (
        "unio_collector.scanners.config.compliance.scanner",
        "AwsConfigComplianceReviewScanner",
    ),
    "ConfigComplianceEvidence": (
        "unio_collector.scanners.config.compliance.evidence",
        "ConfigComplianceEvidence",
    ),
    "ConfigComplianceRuleRecord": (
        "unio_collector.scanners.config.compliance.rule_record",
        "ConfigComplianceRuleRecord",
    ),
}

__all__ = (
    "AwsConfigComplianceReviewScanner",
    "ConfigComplianceEvidence",
    "ConfigComplianceRuleRecord",
)


def __getattr__(name: str) -> Any:  # noqa: ANN401
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as exc:
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg) from exc
    module = import_module(module_name)
    return getattr(module, attribute_name)
