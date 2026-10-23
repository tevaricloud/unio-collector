"""Route association subnet identities versus finite association categories."""

from typing import ClassVar

from unio_collector.privacy.flow.pair import FlowPairContract
from unio_collector.privacy.flow.topology_fields import ROUTE_FIELDS


class FlowAssociationPairContract(FlowPairContract):
    """Retain the actual empty main-VPC subnet marker without inventing an identity."""

    fields: ClassVar = {path: spec for path, spec in ROUTE_FIELDS.items() if ".associations[]" in path}

    def is_literal(self, suffix: str, value: object) -> bool:
        """Only the declared absent-subnet cell may preserve its empty string."""
        return super().is_literal(suffix, value) or (suffix in self.fields and suffix.endswith("[0]") and value == "")
