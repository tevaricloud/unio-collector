from __future__ import annotations  # noqa: D100

import re
from dataclasses import dataclass

_ACCOUNT_ID_PATTERN = re.compile(r"^\d{12}$")
_KNOWN_PARTITIONS = frozenset(
    {"aws", "aws-cn", "aws-iso", "aws-iso-b", "aws-iso-e", "aws-iso-f", "aws-us-gov"},
)


@dataclass(frozen=True)
class AwsPolicyExecutionScope:
    """Resolved and unresolved AWS policy-planning scope."""

    account_id: str | None = None
    partition: str | None = None
    regions: tuple[str, ...] = ()
    account_source: str = "unresolved"
    partition_source: str = "unresolved"
    region_source: str = "unresolved"
    authenticated: bool = False

    @classmethod
    def resolve(
        cls,
        *,
        regions: tuple[str, ...] = (),
        policy_account_id: str | None = None,
        policy_partition: str | None = None,
        authenticated_account_id: str | None = None,
        authenticated_arn: str | None = None,
    ) -> AwsPolicyExecutionScope:
        """Resolve authoritative runtime values and planning-only fallbacks."""
        _validate_account_id(policy_account_id)
        _validate_account_id(authenticated_account_id)
        _validate_partition(policy_partition)
        authenticated_partition = _partition_from_arn(authenticated_arn)
        if authenticated_account_id and policy_account_id and authenticated_account_id != policy_account_id:
            msg = "Planning account ID conflicts with authenticated AWS identity."
            raise ValueError(msg)
        if authenticated_partition and policy_partition and authenticated_partition != policy_partition:
            msg = "Planning partition conflicts with authenticated AWS identity."
            raise ValueError(msg)
        normalized_regions = tuple(sorted(dict.fromkeys(region for region in regions if region)))
        region_partition, region_partition_ambiguous = _partition_from_regions(
            normalized_regions,
        )
        if authenticated_partition and region_partition and authenticated_partition != region_partition:
            msg = "Configured AWS regions conflict with authenticated AWS partition."
            raise ValueError(msg)
        if authenticated_partition and region_partition_ambiguous:
            msg = "Configured AWS regions span partitions for authenticated planning."
            raise ValueError(msg)
        partition = authenticated_partition or region_partition
        if partition is None and not region_partition_ambiguous:
            partition = policy_partition
        partition_source = "unresolved"
        if authenticated_partition:
            partition_source = "authenticated"
        elif region_partition:
            partition_source = "configuration"
        elif partition and policy_partition:
            partition_source = "planning_override"
        account_id = authenticated_account_id or policy_account_id
        return cls(
            account_id=account_id,
            partition=partition,
            regions=normalized_regions,
            account_source=("authenticated" if authenticated_account_id else "planning_override" if policy_account_id else "unresolved"),
            partition_source=partition_source,
            region_source="configuration" if normalized_regions else "unresolved",
            authenticated=bool(authenticated_account_id or authenticated_partition),
        )

    def variables(self) -> dict[str, object]:
        """Return template variables that are safely resolved."""
        return {
            "account_id": self.account_id,
            "partition": self.partition,
            "regions": self.regions,
        }


def _validate_account_id(value: str | None) -> None:
    if value is not None and not _ACCOUNT_ID_PATTERN.fullmatch(value):
        msg = "AWS policy account ID must contain exactly 12 digits."
        raise ValueError(msg)


def _validate_partition(value: str | None) -> None:
    if value is not None and value not in _KNOWN_PARTITIONS:
        msg = f"Unknown AWS partition for policy planning: {value}."
        raise ValueError(msg)


def _partition_from_arn(value: str | None) -> str | None:
    if not value or not value.startswith("arn:"):
        return None
    partition = value.split(":", maxsplit=2)[1]
    _validate_partition(partition)
    return partition


def _partition_from_regions(
    regions: tuple[str, ...],
) -> tuple[str | None, bool]:
    if not regions:
        return None, False
    partitions = {_partition_for_region(region) for region in regions}
    if len(partitions) != 1:
        return None, True
    return partitions.pop(), False


def _partition_for_region(region: str) -> str:
    if region.startswith("cn-"):
        return "aws-cn"
    if region.startswith("us-gov-"):
        return "aws-us-gov"
    if region.startswith("us-iso-"):
        return "aws-iso"
    if region.startswith("us-isob-"):
        return "aws-iso-b"
    if region.startswith("eu-isoe-"):
        return "aws-iso-e"
    if region.startswith("us-isof-"):
        return "aws-iso-f"
    return "aws"


__all__ = ["AwsPolicyExecutionScope"]
