from __future__ import annotations  # noqa: D100

from unio_collector.core.base_model import UnioBaseModel


class OrganizationalUnit(UnioBaseModel):
    """Persist one normalized AWS Organizations OU."""

    organizational_unit_id: str
    arn: str
    name: str
    parent_id: str
    root_id: str
    ancestor_path: tuple[str, ...]
