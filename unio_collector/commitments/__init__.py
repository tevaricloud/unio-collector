"""Commitment contracts with lazy historical application exports.

Use canonical modules internally. Retain historical exports until an approved
public import-path migration.
"""

from importlib import import_module
from typing import Any

from unio_collector.commitments.identity import CommitmentIdentity
from unio_collector.commitments.inventory import CommitmentInventoryItem
from unio_collector.commitments.observed_metric import ObservedCommitmentMetric
from unio_collector.commitments.payment import CommitmentPayment
from unio_collector.commitments.rollup import CommitmentCurrencyRollup
from unio_collector.commitments.source import CommitmentSourceOutcome
from unio_collector.commitments.specification import CommitmentSpecification
from unio_collector.commitments.term import CommitmentTerm
from unio_collector.commitments.types import CommitmentValueNature

__all__ = (
    "CalculatedCommitmentMetric",
    "CommitmentAssessment",
    "CommitmentCurrencyRollup",
    "CommitmentIdentity",
    "CommitmentInventoryItem",
    "CommitmentPayment",
    "CommitmentPortfolio",
    "CommitmentSourceOutcome",
    "CommitmentSpecification",
    "CommitmentTerm",
    "CommitmentValueNature",
    "ObservedCommitmentMetric",
)


def __getattr__(name: str) -> Any:  # noqa: ANN401
    """Resolve private application contracts only on explicit access."""
    modules = {
        "CommitmentAssessment": "unio_collector.commitments.assessment",
        "CalculatedCommitmentMetric": "unio_collector.commitments.calculated_metric",
        "CommitmentPortfolio": "unio_collector.commitments.portfolio",
    }
    if name not in modules:
        raise AttributeError(name)
    return getattr(import_module(modules[name]), name)
