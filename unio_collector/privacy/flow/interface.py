"""Only interface facts may contain the interface producer's explicit field set."""

from typing import ClassVar

from unio_collector.privacy.flow.base import FlowPrivacyBase
from unio_collector.privacy.flow.topology_fields import INTERFACE_FIELDS


class FlowInterfaceContract(FlowPrivacyBase):
    """Protect interface identifiers and tags with independently typed optional values."""

    fields: ClassVar = INTERFACE_FIELDS
