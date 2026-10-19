"""Finite synthetic edge SDK shapes, never derived or rewritten evidence DTOs."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

ALB = "arn:aws:elasticloadbalancing:eu-west-2:123456789012:loadbalancer/app/synthetic-edge/1234"
LISTENER = "arn:aws:elasticloadbalancing:eu-west-2:123456789012:listener/app/synthetic-edge/1234/5678"
DOMAIN = "synthetic-edge-123.eu-west-2.elb.amazonaws.com"


def responses(operation: str, variant: str) -> dict[str, Any]:
    """Return provider shapes; all derived DTOs are built by production collectors."""
    name = "HTTPS" if variant == "collision" else "synthetic-customer-origin"
    origin: dict[str, Any] = {
        "Id": name,
        "DomainName": DOMAIN,
        "CustomHeaders": {"Items": [{"HeaderName": "x-customer-verify", "HeaderValue": "synthetic-transient-header-only"}]},
        "CustomOriginConfig": {"HTTPPort": 80, "HTTPSPort": 443, "OriginProtocolPolicy": "https-only"},
    }
    if variant == "vpc":
        origin["VpcOriginConfig"] = {"VpcOriginId": "vpco-synthetic"}
    if variant == "nullable":
        origin.pop("CustomHeaders")
        origin["CustomOriginConfig"] = {}
    behavior = {
        "TargetOriginId": name,
        "OriginRequestPolicyId": "synthetic-policy",
        "CachePolicyId": "synthetic-cache",
        "ViewerProtocolPolicy": "redirect-to-https",
        "AllowedMethods": {"Items": ["GET", "HEAD"]},
        "Compress": True,
        "DefaultTTL": 60,
    }
    distribution = {
        "Id": "HTTPS" if variant == "collision" else "EDISTSYNTHETIC",
        "ARN": "arn:aws:cloudfront::123456789012:distribution/" + ("HTTPS" if variant == "collision" else "EDISTSYNTHETIC"),
        "DomainName": "dsynthetic.cloudfront.net",
        "Enabled": True,
        "WebACLId": "synthetic-webacl",
        "PriceClass": "PriceClass_100",
        "Origins": {"Quantity": 1, "Items": [origin]},
        "DefaultCacheBehavior": behavior,
        "CacheBehaviors": {"Quantity": 0, "Items": []},
        "Logging": {"Enabled": True, "Bucket": "synthetic-customer-logs.s3.amazonaws.com"},
    }
    values: dict[str, dict[str, Any]] = {
        "list_distributions": {"DistributionList": {"IsTruncated": False, "Items": [] if variant == "empty" else [distribution]}},
        "list_tags_for_resource": {"Tags": {"Items": [{"Key": "Owner", "Value": "synthetic-customer-team"}]}},
        "list_invalidations": {
            "InvalidationList": {
                "IsTruncated": False,
                "Items": [
                    {
                        "Id": "synthetic-invalidation",
                        "CreateTime": datetime(2026, 1, 1, tzinfo=UTC),
                        "InvalidationBatch": {"Paths": {"Quantity": 2, "Items": ["/synthetic/*", "/synthetic"]}},
                    }
                ],
            }
        },
        "get_origin_request_policy": {"OriginRequestPolicy": {"OriginRequestPolicyConfig": {"HeadersConfig": {"HeaderBehavior": "none"}}}},
        "get_vpc_origin": {
            "VpcOrigin": {"Status": "Deployed", "VpcOriginEndpointConfig": {"Arn": ALB, "HTTPPort": 80, "HTTPSPort": 443, "OriginProtocolPolicy": "https-only"}}
        },
        "describe_load_balancers": {
            "LoadBalancers": []
            if variant == "empty"
            else [
                {
                    "LoadBalancerArn": ALB,
                    "LoadBalancerName": name,
                    "DNSName": DOMAIN,
                    "Scheme": "internet-facing",
                    "Type": "application",
                    "SecurityGroups": ["sg-synthetic"],
                }
            ]
        },
        "describe_listeners": {
            "Listeners": [
                {
                    "ListenerArn": LISTENER,
                    "Port": 443,
                    "Protocol": "HTTPS",
                    "DefaultActions": [{"Type": "fixed-response", "FixedResponseConfig": {"StatusCode": "403"}}],
                }
            ]
        },
        "describe_rules": {
            "Rules": [
                {
                    "RuleArn": LISTENER + "/rule/synthetic",
                    "Priority": "1",
                    "Conditions": [
                        {"Field": "host-header", "Values": [DOMAIN]},
                        {"Field": "http-header", "HttpHeaderConfig": {"HttpHeaderName": "x-customer-verify", "Values": ["synthetic-transient-header-only"]}},
                    ],
                    "Actions": [{"Type": "forward"}],
                }
            ]
        },
        "describe_security_groups": {
            "SecurityGroups": [
                {
                    "GroupId": "sg-synthetic",
                    "IpPermissions": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 443,
                            "ToPort": 443,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "synthetic-customer-ingress"}],
                            "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                            "PrefixListIds": [{"PrefixListId": "pl-synthetic"}],
                            "UserIdGroupPairs": [{"GroupId": "sg-synthetic-peer", "UserId": "123456789012"}],
                        }
                    ],
                }
            ]
        },
        "describe_managed_prefix_lists": {
            "PrefixLists": [{"PrefixListId": "pl-synthetic", "OwnerId": "AWS", "PrefixListName": "com.amazonaws.global.cloudfront.origin-facing"}]
        },
        "get_web_acl_for_resource": {"WebACL": {"ARN": "arn:aws:wafv2:eu-west-2:123456789012:regional/webacl/synthetic/1234"}},
        "get_metric_data": {
            "MetricDataResults": [{"Id": "requests", "Values": [17.0], "Timestamps": [datetime(2026, 1, 1, tzinfo=UTC)], "StatusCode": "Complete"}]
        },
    }
    return values[operation]
