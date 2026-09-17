"""Read-only structural metadata supplied across the collection boundary."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from decimal import Decimal


class ServiceSpendObservation(Protocol):
    """Expose supplied values without importing their private implementation."""

    @property
    def service_name(self) -> str:
        """Return the supplied service name."""
        ...

    @property
    def region(self) -> str:
        """Return the supplied region."""
        ...

    @property
    def previous_cost(self) -> Decimal:
        """Return the supplied previous cost."""
        ...

    @property
    def current_cost(self) -> Decimal:
        """Return the supplied current cost."""
        ...

    @property
    def absolute_delta(self) -> Decimal:
        """Return the supplied absolute delta."""
        ...

    @property
    def percent_delta(self) -> Decimal | None:
        """Return the supplied percent delta."""
        ...

    @property
    def currency(self) -> str:
        """Return the supplied currency."""
        ...

    @property
    def rank(self) -> int:
        """Return the supplied rank."""
        ...
