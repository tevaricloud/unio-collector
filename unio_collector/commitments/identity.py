"""Commitment source identity contract."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CommitmentIdentity:
    """Identify a commitment without assuming identifiers match across APIs."""

    provider: str
    service: str
    commitment_type: str
    source_namespace: str
    source_id: str
    account_id: str
    arn: str | None = None
