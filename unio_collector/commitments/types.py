"""Shared commitment enumerations."""

from __future__ import annotations

from enum import StrEnum


class CommitmentValueNature(StrEnum):
    """Describe whether a value came from AWS or a Unio calculation."""

    AWS_OBSERVED = "aws_observed"
    AWS_CALCULATED = "aws_calculated"
    UNIO_CALCULATED = "unio_calculated"
    UNIO_ANNUALIZED = "unio_annualized"
    UNKNOWN = "unknown"
