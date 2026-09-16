from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.scanners.audit_cost.cloudtrail.trail_record import CloudTrailSecurityTrailRecord


def dedupe_cloudtrail_security_trails(  # noqa: D103
    trails: list[CloudTrailSecurityTrailRecord],
) -> list[CloudTrailSecurityTrailRecord]:
    seen: set[str] = set()
    deduped: list[CloudTrailSecurityTrailRecord] = []
    for trail in trails:
        key = trail.arn or f"{trail.region}:{trail.name}"
        if key in seen:
            continue
        seen.add(key)
        deduped.append(trail)
    return deduped


def count_cloudtrail_organization_trails(trails: object) -> int:  # noqa: D103
    if not isinstance(trails, list):
        return 0
    return sum(1 for trail in trails if isinstance(trail, dict) and bool(trail.get("IsOrganizationTrail")))


def count_cloudtrail_multi_region_trails(trails: object) -> int:  # noqa: D103
    if not isinstance(trails, list):
        return 0
    return sum(1 for trail in trails if isinstance(trail, dict) and bool(trail.get("IsMultiRegionTrail")))
