"""Finite, non-secret protection work stages."""

from enum import StrEnum


class ProtectionStage(StrEnum):
    """Actual child operations, never elapsed-time estimates."""

    PROTECT = "Protecting and verifying local artifacts"
    VALIDATE = "Independently validating protected bundle"
    RECEIPT = "Verifying completion receipt"
