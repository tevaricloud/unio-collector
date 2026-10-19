"""Finite synthetic SDK responses, never hand-written serialized evidence."""

from __future__ import annotations

from copy import deepcopy
from typing import Any


def responses(service: str, variant: str, parameters: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return provider wire data for actual collectors, with fixed synthetic IDs."""
    collision = "ENHANCED" if service == "ecr" else "application" if parameters.get("scanner") == "public-service-exposure-review" else "tcp"
    name = collision if variant == "collision" else "synthetic-customer"
    account = "123456789012"
    arn = "arn:" + "aws:"
    return {
        "ec2": {
            "describe_security_groups": {
                "SecurityGroups": [
                    {
                        "GroupId": "sg-00000000000000000",
                        "GroupName": name,
                        "VpcId": "vpc-00000000000000000",
                        "IpPermissions": [
                            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": [{"CidrIpv6": "::/0"}]},
                            {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                            {"IpProtocol": "17", "FromPort": 53, "ToPort": 53, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                        ],
                    }
                ]
            }
        },
        "ecr": {
            "describe_repositories": {
                "repositories": [
                    {
                        "repositoryName": name,
                        "repositoryArn": arn + "ecr:eu-west-2:" + account + ":repository/" + name,
                        "imageScanningConfiguration": {"scanOnPush": True},
                        "imageTagMutability": "IMMUTABLE",
                        "encryptionConfiguration": {
                            "encryptionType": "KMS",
                            "kmsKey": arn + "kms:eu-west-2:" + account + ":key/00000000-0000-0000-0000-000000000000",
                        },
                    }
                ]
            },
            "get_registry_scanning_configuration": {"scanningConfiguration": {"scanType": "ENHANCED", "rules": [{"scanFrequency": "CONTINUOUS_SCAN"}]}},
        },
        "rds": {
            "describe_db_instances": {
                "DBInstances": [{"PubliclyAccessible": True, "DBInstanceIdentifier": name, "DBInstanceArn": arn + "rds:eu-west-2:" + account + ":db:" + name}]
            }
        },
        "es": {"list_domain_names": {"DomainNames": [{"DomainName": name}]}, "describe_domain_config": {"DomainConfig": {"VPCOptions": {"Options": {}}}}},
        "redshift": {"describe_clusters": {"Clusters": [{"PubliclyAccessible": True, "ClusterIdentifier": name}]}},
        "elbv2": {
            "describe_load_balancers": {
                "LoadBalancers": [
                    {
                        "Scheme": "internet-facing",
                        "LoadBalancerName": name,
                        "LoadBalancerArn": arn + "elasticloadbalancing:eu-west-2:" + account + ":loadbalancer/app/" + name + "/0000000000000000",
                        "Type": "application",
                    }
                ]
            }
        },
        "apigateway": {"get_rest_apis": {"items": [{"id": "synthetic-api", "name": name, "endpointConfiguration": {"types": ["REGIONAL", "EDGE"]}}]}},
        "apigatewayv2": {"get_apis": {"Items": [{"ApiId": "synthetic-api-v2", "Name": name, "ProtocolType": "HTTP"}]}},
        "cloudfront": {
            "list_distributions": {"DistributionList": {"Items": [{"Id": "SYNTHETIC-DISTRIBUTION", "Origins": {"Items": [{"DomainName": name + ".invalid"}]}}]}}
        },
        "iam": {},
    }[service]


def shape_response(value: dict[str, Any], variant: str, operation: str, scanner: str) -> dict[str, Any]:
    """Exercise empty, nullable and malformed SDK shapes before serialization."""
    del scanner
    result = deepcopy(value)
    if variant == "empty":
        for key, child in result.items():
            if isinstance(child, list):
                result[key] = []
        if operation == "list_distributions":
            result["DistributionList"]["Items"] = []
    if variant == "nullable" and operation == "describe_repositories":
        result["repositories"][0] = {"repositoryName": "synthetic-customer"}
    if variant == "nullable" and operation == "describe_security_groups":
        result["SecurityGroups"][0].pop("VpcId")
    if variant == "nullable" and operation == "describe_load_balancers":
        result["LoadBalancers"][0].pop("Type")
    if variant == "nullable" and operation == "get_apis":
        result["Items"][0].pop("ProtocolType")
    _extra_response(result, variant, operation)
    return result


def _extra_response(result: dict[str, Any], variant: str, operation: str) -> None:
    """Drive bounded protocol and scan-configuration branches in actual providers."""
    if variant == "port_collision" and operation == "describe_security_groups":
        result["SecurityGroups"][0]["GroupName"] = "443"
    if variant == "protocols" and operation == "describe_security_groups":
        group = result["SecurityGroups"][0]
        group["GroupName"] = "synthetic-customer-lightsail"
        group["IpPermissions"].extend(
            {"IpProtocol": protocol, "FromPort": -1, "ToPort": -1, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]} for protocol in ("udp", "icmp", "icmpv6", "0", "255")
        )
    if variant == "basic" and operation == "describe_repositories":
        repository = result["repositories"][0]
        repository["imageScanningConfiguration"]["scanOnPush"] = False
        repository["imageTagMutability"] = "MUTABLE"
        repository["encryptionConfiguration"] = {"encryptionType": "AES256"}
    if variant == "basic" and operation == "get_registry_scanning_configuration":
        result["scanningConfiguration"] = {"scanType": "BASIC", "rules": []}
    if variant == "malformed" and operation == "describe_repositories":
        result["repositories"][0]["imageScanningConfiguration"]["scanOnPush"] = "not-a-boolean"
