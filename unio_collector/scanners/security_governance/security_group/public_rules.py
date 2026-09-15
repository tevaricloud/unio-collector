"""Neutral public ingress facts from existing security group responses."""

from __future__ import annotations

from typing import Any

from unio_collector.scanners.security_governance.security_group.ingress_rule import SecurityGroupIngressRule


def collect_public_ingress_rules(  # noqa: D103
    security_group: dict[str, Any],
    region: str,
) -> list[SecurityGroupIngressRule]:
    group_id = str(security_group.get("GroupId", ""))
    group_name = str(security_group.get("GroupName", ""))
    vpc_id = security_group.get("VpcId")
    rules: list[SecurityGroupIngressRule] = []
    for permission in security_group.get("IpPermissions", []):
        if not isinstance(permission, dict):
            continue
        protocol = str(permission.get("IpProtocol", ""))
        from_port = permission.get("FromPort")
        to_port = permission.get("ToPort")
        public_cidrs = [str(item.get("CidrIp")) for item in permission.get("IpRanges", []) if isinstance(item, dict) and item.get("CidrIp") == "0.0.0.0/0"]
        public_cidrs.extend(str(item.get("CidrIpv6")) for item in permission.get("Ipv6Ranges", []) if isinstance(item, dict) and item.get("CidrIpv6") == "::/0")
        rules.extend(
            SecurityGroupIngressRule(
                group_id=group_id,
                group_name=group_name,
                vpc_id=str(vpc_id) if vpc_id else None,
                region=region,
                protocol=protocol,
                from_port=from_port if isinstance(from_port, int) else None,
                to_port=to_port if isinstance(to_port, int) else None,
                cidr=cidr,
                name_contains_lightsail="lightsail" in f"{group_id} {group_name}".lower(),
            )
            for cidr in public_cidrs
        )
    return rules
