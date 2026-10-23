"""The actual managed-prefix-list coverage scope is a location, not a customer ID."""

from typing import ClassVar

from unio_collector.privacy.edge.coverage import EdgeCoverageContract


class EdgeRegionalCoverageContract(EdgeCoverageContract):
    """Bind typed location handling only after the exact parent discriminator admits it."""

    fields: ClassVar = {**EdgeCoverageContract.fields, "coverage[].scope_id": ("string", "region", False)}
