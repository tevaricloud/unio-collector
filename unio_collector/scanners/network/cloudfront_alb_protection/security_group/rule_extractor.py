from __future__ import annotations  # noqa: D100

from typing import Any

from unio_collector.scanners.network.cloudfront_alb_protection.security_group.record import (
    AlbOriginSecurityGroupRuleRecord,
)


class SecurityGroupIngressRuleExtractor:
    """Convert EC2 security-group ingress permissions into ALB-origin evidence."""

    def build(
        self,
        region: str,
        group_id: str,
        group: dict[str, Any],
        verified_cloudfront_prefix_list_ids: set[str] | None = None,
    ) -> list[AlbOriginSecurityGroupRuleRecord]:
        """Build typed ingress records for CIDR and source-restriction rules."""
        records: list[AlbOriginSecurityGroupRuleRecord] = []
        permissions = group.get("IpPermissions", [])
        if not isinstance(permissions, list):
            return records
        for permission in permissions:
            if not isinstance(permission, dict):
                continue
            records.extend(self._cidr_rules(region, group_id, permission, "IpRanges"))
            records.extend(self._cidr_rules(region, group_id, permission, "Ipv6Ranges"))
            records.extend(self._prefix_list_rules(region, group_id, permission, verified_cloudfront_prefix_list_ids or set()))
            records.extend(self._source_security_group_rules(region, group_id, permission))
        return records

    def _cidr_rules(
        self,
        region: str,
        group_id: str,
        permission: dict[str, Any],
        key: str,
    ) -> list[AlbOriginSecurityGroupRuleRecord]:
        ranges = permission.get(key, [])
        if not isinstance(ranges, list):
            return []
        records: list[AlbOriginSecurityGroupRuleRecord] = []
        for item in ranges:
            if not isinstance(item, dict):
                continue
            cidr = str(item.get("CidrIp") or item.get("CidrIpv6") or "")
            if not cidr:
                continue
            records.append(
                AlbOriginSecurityGroupRuleRecord(
                    group_id=group_id,
                    region=region,
                    protocol=str(permission.get("IpProtocol") or ""),
                    from_port=self._to_int(permission.get("FromPort")),
                    to_port=self._to_int(permission.get("ToPort")),
                    cidr=cidr,
                    public=cidr in {"0.0.0.0/0", "::/0"},
                    source_type="cidr",
                    source_value=cidr,
                    evidence_ref=f"ec2-sg:{region}:{group_id}:{cidr}",
                ),
            )
        return records

    def _prefix_list_rules(
        self,
        region: str,
        group_id: str,
        permission: dict[str, Any],
        verified_cloudfront_prefix_list_ids: set[str],
    ) -> list[AlbOriginSecurityGroupRuleRecord]:
        ranges = permission.get("PrefixListIds", [])
        if not isinstance(ranges, list):
            return []
        records: list[AlbOriginSecurityGroupRuleRecord] = []
        for item in ranges:
            if not isinstance(item, dict):
                continue
            prefix_list_id = str(item.get("PrefixListId") or "")
            if not prefix_list_id:
                continue
            description = str(item.get("Description") or "")
            records.append(
                AlbOriginSecurityGroupRuleRecord(
                    group_id=group_id,
                    region=region,
                    protocol=str(permission.get("IpProtocol") or ""),
                    from_port=self._to_int(permission.get("FromPort")),
                    to_port=self._to_int(permission.get("ToPort")),
                    cidr="",
                    public=False,
                    source_type="prefix_list",
                    source_value=prefix_list_id,
                    source_description=description,
                    source_control=self._prefix_list_control(prefix_list_id, description),
                    evidence_ref=f"ec2-sg:{region}:{group_id}:prefix-list:{prefix_list_id}",
                    source_control_verification=("verified" if prefix_list_id in verified_cloudfront_prefix_list_ids else "legacy_unverified"),
                ),
            )
        return records

    def _source_security_group_rules(
        self,
        region: str,
        group_id: str,
        permission: dict[str, Any],
    ) -> list[AlbOriginSecurityGroupRuleRecord]:
        ranges = permission.get("UserIdGroupPairs", [])
        if not isinstance(ranges, list):
            return []
        records: list[AlbOriginSecurityGroupRuleRecord] = []
        for item in ranges:
            if not isinstance(item, dict):
                continue
            source_group_id = str(item.get("GroupId") or "")
            if not source_group_id:
                continue
            description = str(item.get("Description") or "")
            records.append(
                AlbOriginSecurityGroupRuleRecord(
                    group_id=group_id,
                    region=region,
                    protocol=str(permission.get("IpProtocol") or ""),
                    from_port=self._to_int(permission.get("FromPort")),
                    to_port=self._to_int(permission.get("ToPort")),
                    cidr="",
                    public=False,
                    source_type="security_group",
                    source_value=source_group_id,
                    source_description=description,
                    source_control=f"source_security_group:{source_group_id}",
                    evidence_ref=f"ec2-sg:{region}:{group_id}:source-sg:{source_group_id}",
                ),
            )
        return records

    def _prefix_list_control(self, prefix_list_id: str, description: str) -> str:
        if "cloudfront" in description.lower():
            return f"cloudfront_managed_prefix_list:{prefix_list_id}"
        return f"prefix_list:{prefix_list_id}"

    def _to_int(self, value: object) -> int | None:
        if value is None:
            return None
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            try:
                return int(value)
            except ValueError:
                return None
        return None
