"""Service-bound synthetic billing endpoint, with no SDK client or AWS session."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from tools.collector_billing.response import OPERATIONS

if TYPE_CHECKING:
    from collections.abc import Callable

    from tools.collector_billing.session import SyntheticBillingSession


class SyntheticBillingClient:
    """Reject cross-service operations so the fixture cannot conceal wrong endpoints."""

    def __init__(self, session: SyntheticBillingSession, service: str) -> None:
        """Bind the endpoint selected by the actual collector."""
        self.session = session
        self.service = service

    def can_paginate(self, operation: str) -> bool:
        """Use actual token pagination rather than a manually rewritten result."""
        del operation
        return False

    def __getattr__(self, operation: str) -> Callable[..., dict[str, Any]]:
        """Expose only the SDK operation supported at this service endpoint."""
        if operation not in OPERATIONS or OPERATIONS[operation][0] != self.service:
            raise AttributeError(operation)
        return lambda **params: self.session.response(operation, params)
