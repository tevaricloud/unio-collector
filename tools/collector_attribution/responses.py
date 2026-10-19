"""Synthetic topology/association SDK data, not evidence DTO fixtures."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

ACCOUNT = "123456789012"
REGION = "eu-west-2"
ALB = f"arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:loadbalancer/app/synthetic-attribution/1234"
TARGET = f"arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:targetgroup/synthetic-attribution/1234"


def responses(service: str, operation: str, variant: str, parameters: dict[str, Any]) -> dict[str, Any]:
    """Populate actual provider contracts with relationships, optional values and collisions."""
    name = "ACCEPT" if variant == "collision" else "1024" if variant == "numeric_collision" else "synthetic-customer-attribution"
    tags = [
        {"Key": "Name", "Value": name},
        {"Key": "Owner", "Value": "synthetic-customer-owner"},
        {"Key": "Environment", "Value": "synthetic-customer-environment"},
    ]
    nullable = variant == "nullable"
    vpc = {"VpcId": "vpc-synthetic", "Tags": tags}
    subnet = {"SubnetId": "subnet-synthetic", "VpcId": "vpc-synthetic", "Tags": tags}
    instance = {"InstanceId": "i-synthetic", "VpcId": "vpc-synthetic", "SubnetId": "subnet-synthetic", "State": {"Name": "running"}, "Tags": tags}
    interface = {
        "NetworkInterfaceId": "eni-synthetic",
        "PrivateIpAddress": "10.23.0.10",
        "PrivateIpAddresses": [{"PrivateIpAddress": "10.23.0.10"}],
        "OwnerId": ACCOUNT,
        "VpcId": "vpc-synthetic",
        "SubnetId": "subnet-synthetic",
        "AvailabilityZone": "eu-west-2a",
        "Description": name,
        "InterfaceType": "interface",
        "Attachment": {"InstanceId": "i-synthetic"},
        "PrivateDnsName": "synthetic-customer.internal",
        "TagSet": tags,
    }
    if nullable:
        interface = {"NetworkInterfaceId": "eni-synthetic", "PrivateIpAddress": "10.23.0.10"}
        vpc = {"VpcId": "vpc-synthetic"}
        subnet = {"SubnetId": "subnet-synthetic", "VpcId": "vpc-synthetic"}
        instance = {"InstanceId": "i-synthetic"}
    route = {
        "RouteTableId": "rtb-synthetic",
        "VpcId": "vpc-synthetic",
        "Associations": [{"SubnetId": "subnet-synthetic"}, {"Main": True}],
        "Routes": [
            {"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-synthetic", "State": "active", "Origin": "CreateRoute"},
            {"DestinationIpv6CidrBlock": "::/0", "EgressOnlyInternetGatewayId": "eigw-synthetic", "State": "active", "Origin": "CreateRoute"},
        ],
    }
    flow = {
        "FlowLogId": "fl-synthetic",
        "ResourceId": "vpc-synthetic",
        "ResourceType": "VPC",
        "LogGroupName": "/aws/vpc/synthetic-customer-flow",
        "LogDestinationType": "s3" if variant == "destination" else "cloud-watch-logs",
        "TrafficType": "ALL",
    }
    if variant == "format":
        flow["LogFormat"] = "${srcaddr} ${dstaddr}"
    data: dict[str, dict[str, Any]] = {
        "ec2:describe_flow_logs": {"FlowLogs": [flow]},
        "ec2:describe_network_interfaces": {"NetworkInterfaces": [interface]},
        "ec2:describe_route_tables": {"RouteTables": [route]},
        "ec2:describe_vpcs": {"Vpcs": [vpc]},
        "ec2:describe_subnets": {"Subnets": [subnet]},
        "ec2:describe_instances": {"Reservations": [{"Instances": [instance]}]},
        "ec2:describe_volumes": {"Volumes": [{"VolumeId": "vol-synthetic", "Attachments": [{"InstanceId": "i-synthetic"}], "Tags": tags}]},
        "ec2:describe_addresses": {"Addresses": [{"AllocationId": "eipalloc-synthetic", "PublicIp": "192.0.2.23", "Tags": tags}]},
        "ec2:describe_nat_gateways": {
            "NatGateways": [
                {
                    "NatGatewayId": "nat-synthetic",
                    "SubnetId": "subnet-synthetic",
                    "VpcId": "vpc-synthetic",
                    "State": "available",
                    "ConnectivityType": "public",
                    "Tags": tags,
                }
            ]
        },
        "logs:start_query": {"queryId": "synthetic-query"},
        "logs:get_query_results": {
            "status": "Failed" if variant == "query_failure" else "Complete",
            "results": [
                [
                    {"field": key, "value": value}
                    for key, value in {
                        "srcaddr": "10.23.0.10",
                        "dstaddr": "10.23.0.11",
                        "action": "ACCEPT",
                        "totalBytes": "1024",
                        "totalPackets": "7",
                        "flowCount": "3",
                    }.items()
                ]
            ],
        },
        "elbv2:describe_load_balancers": {"LoadBalancers": [{"LoadBalancerArn": ALB, "LoadBalancerName": name}]},
        "elbv2:describe_tags": {"TagDescriptions": [{"ResourceArn": parameters.get("ResourceArns", [ALB])[0], "Tags": tags}]},
        "elbv2:describe_target_groups": {"TargetGroups": [{"TargetGroupArn": TARGET, "TargetGroupName": name, "TargetType": "instance"}]},
        "elbv2:describe_target_health": {"TargetHealthDescriptions": [{"Target": {"Id": "i-synthetic"}, "TargetHealth": {"State": "healthy"}}]},
        "autoscaling:describe_auto_scaling_groups": {
            "AutoScalingGroups": [
                {
                    "AutoScalingGroupName": name,
                    "AutoScalingGroupARN": f"arn:aws:autoscaling:{REGION}:{ACCOUNT}:autoScalingGroup:1234:autoScalingGroupName/synthetic-customer-attribution",
                    "Tags": tags,
                    "Instances": [{"InstanceId": "i-synthetic"}],
                }
            ]
        },
        "resourcegroupstaggingapi:get_resources": {
            "ResourceTagMappingList": [{"ResourceARN": f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-synthetic", "Tags": tags}]
        },
    }
    if operation == "describe_network_interfaces":
        second: dict[str, Any] = deepcopy(interface)
        second.update(NetworkInterfaceId="eni-synthetic-destination", PrivateIpAddress="10.23.0.11", PrivateIpAddresses=[{"PrivateIpAddress": "10.23.0.11"}])
        interfaces = [interface, second]
        if variant == "ambiguous":
            interfaces.append(dict(interface, NetworkInterfaceId="eni-synthetic-other", VpcId="vpc-synthetic-other"))
        requested = {
            address for item in parameters.get("Filters", []) if item.get("Name") == "addresses.private-ip-address" for address in item.get("Values", [])
        }
        data["ec2:describe_network_interfaces"]["NetworkInterfaces"] = [
            item for item in interfaces if not requested or item.get("PrivateIpAddress") in requested
        ]
    if operation == "get_query_results" and variant in {"ipv6", "public"}:
        addresses = ("fd00::10", "fd00::11") if variant == "ipv6" else ("8.8.8.8", "1.1.1.1")
        for item in data["logs:get_query_results"]["results"][0]:
            if item["field"] in {"srcaddr", "dstaddr"}:
                item["value"] = addresses[0 if item["field"] == "srcaddr" else 1]
    if operation == "describe_flow_logs" and variant == "definitions_cap":
        data["ec2:describe_flow_logs"]["FlowLogs"] = [
            dict(flow, FlowLogId="fl-synthetic-" + str(index), LogGroupName="/aws/vpc/synthetic-customer-flow-" + str(index)) for index in range(4)
        ]
    value = data[service + ":" + operation]
    if variant == "empty":
        return {key: [] if isinstance(child, list) else child for key, child in value.items()}
    return value
