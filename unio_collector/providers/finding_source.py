"""Read-only structural metadata supplied across the collection boundary."""

from __future__ import annotations

from typing import Protocol


class FindingSource(Protocol):
    """Expose supplied values without importing their private implementation."""

    @property
    def title(self) -> str:
        """Return the supplied display title."""
        ...

    @property
    def id(self) -> str:
        """Return the supplied id."""
        ...

    @property
    def account_id(self) -> str | None:
        """Return the supplied account id."""
        ...

    @property
    def region(self) -> str:
        """Return the supplied region."""
        ...

    @property
    def resource_type(self) -> str | None:
        """Return the supplied resource type."""
        ...

    @property
    def resource_id(self) -> str | None:
        """Return the supplied resource id."""
        ...

    @property
    def resource_name(self) -> str | None:
        """Return the supplied resource name."""
        ...

    @property
    def arn(self) -> str | None:
        """Return the supplied arn."""
        ...

    @property
    def tags(self) -> dict[str, str]:
        """Return the supplied tags."""
        ...

    @property
    def service(self) -> str:
        """Return the supplied service."""
        ...

    @property
    def finding_type(self) -> str:
        """Return the supplied finding type."""
        ...

    @property
    def scanner_id(self) -> str | None:
        """Return the supplied scanner id."""
        ...
