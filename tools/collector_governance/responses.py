"""Finite synthetic provider responses consumed by actual governance collectors."""

from __future__ import annotations

from typing import Any


def responses(service: str, variant: str) -> dict[str, dict[str, Any]]:
    """Provide populated service shapes, without constructing a provider session."""
    name = "ENABLED" if variant == "collision" else "synthetic-customer-resource"
    if variant == "identity_collision":
        name = {
            "config": "config-cost-governance-review",
            "guardduty": "guardduty-cost-governance-review",
            "securityhub": "securityhub-inspector-macie-cost-review",
            "inspector2": "securityhub-inspector-macie-cost-review",
            "macie2": "securityhub-inspector-macie-cost-review",
            "wafv2": "waf-cost-governance-review",
        }[service]
    nullable = variant == "nullable"
    if service == "config":
        recorders = [
            {
                "name": name,
                "recordingGroup": {
                    "allSupported": True,
                    "includeGlobalResourceTypes": True,
                    "resourceTypes": ["AWS::EC2::Instance"],
                    "exclusionByResourceTypes": {"resourceTypes": ["AWS::S3::Bucket"]},
                    "recordingStrategy": {"useOnly": strategy},
                },
                "recordingMode": {"recordingFrequency": frequency},
            }
            for strategy, frequency in [
                ("ALL_SUPPORTED_RESOURCE_TYPES", "CONTINUOUS"),
                ("INCLUSION_BY_RESOURCE_TYPES", "DAILY"),
                ("EXCLUSION_BY_RESOURCE_TYPES", "DAILY"),
            ]
        ]
        return {
            "describe_configuration_recorders": {"ConfigurationRecorders": [{"name": name}] if nullable else recorders},
            "describe_delivery_channels": {
                "DeliveryChannels": [
                    {
                        "name": name,
                        "s3BucketName": "synthetic-customer-bucket",
                        "snsTopicARN": "arn:aws:sns:eu-west-2:123456789012:synthetic-topic",
                        "configSnapshotDeliveryProperties": {"deliveryFrequency": value},
                    }
                    for value in ["One_Hour", "Three_Hours", "Six_Hours", "Twelve_Hours", "TwentyFour_Hours"]
                ]
            },
            "describe_configuration_recorder_status": {
                "ConfigurationRecordersStatus": []
                if nullable
                else [
                    {"name": name, "recording": i % 2 == 0, "lastStatus": value, "lastErrorCode": "synthetic-customer-code" if i else None}
                    for i, value in enumerate(["Pending", "Success", "Failure", "NotApplicable"])
                ]
            },
            "describe_config_rules": {
                "ConfigRules": [
                    {"ConfigRuleName": name, "Source": {"Owner": owner, "SourceDetails": [{"MessageType": message}]}}
                    for owner, message in [
                        ("AWS", "ScheduledNotification"),
                        ("CUSTOM_LAMBDA", "ConfigurationItemChangeNotification"),
                        ("CUSTOM_POLICY", "OversizedConfigurationItemChangeNotification"),
                    ]
                ]
            },
            "describe_conformance_packs": {"ConformancePackDetails": [{"ConformancePackName": name}]},
        }
    if service == "guardduty":
        return {
            "list_detectors": {"DetectorIds": [name, "synthetic-customer-detector"]},
            "get_detector": {}
            if nullable
            else {
                "Status": "ENABLED",
                "FindingPublishingFrequency": "SIX_HOURS",
                "Features": [{"Name": "S3_DATA_EVENTS", "Status": "ENABLED"}, {"Name": "EKS_AUDIT_LOGS", "Status": "DISABLED"}, {"Name": "RUNTIME_MONITORING"}],
            },
        }
    if service == "securityhub":
        return {
            "describe_hub": {},
            "get_enabled_standards": {
                "StandardsSubscriptions": [
                    {"StandardsStatus": status, "StandardsArn": "arn:aws:securityhub:eu-west-2:123456789012:standards/synthetic"}
                    for status in ["PENDING", "READY", "FAILED", "DELETING", "INCOMPLETE"]
                ]
            },
        }
    if service == "inspector2":
        status = {
            "ENABLED": {"status": "ENABLED"},
            "ENABLING": "ENABLING",
            "DISABLING": {"status": "DISABLING"},
            "DISABLED": "DISABLED",
            "SUSPENDING": {"status": "SUSPENDING"},
            "SUSPENDED": "SUSPENDED",
        }
        account = {"status": "DISABLED", "resourceState": status} if variant == "legacy" else {"state": {"status": "ENABLED"}, "resourceState": status}
        return {"batch_get_account_status": {"accounts": [] if nullable else [account]}}
    if service == "macie2":
        return {
            "get_macie_session": {}
            if nullable
            else {"status": "PAUSED" if variant == "legacy" else "ENABLED", "findingPublishingFrequency": "FIFTEEN_MINUTES"},
            "list_classification_jobs": {
                "items": [
                    {"jobStatus": status, "jobId": name if i == 0 else f"synthetic-customer-job-{i}"}
                    for i, status in enumerate(["RUNNING", "PAUSED", "CANCELLED", "COMPLETE", "IDLE", "USER_PAUSED"])
                ]
                + [{"jobName": "synthetic-customer-no-status"}]
            },
        }
    if service == "wafv2":
        visibility = {"CloudWatchMetricsEnabled": True, "SampledRequestsEnabled": True, "MetricName": name}
        rules = [
            {
                "Name": name,
                "Action": {action: {}},
                "VisibilityConfig": visibility,
                "Statement": {"RateBasedStatement": {"Limit": 1234}}
                if action == "Block"
                else {"ManagedRuleGroupStatement": {"VendorName": "AWS", "Name": "synthetic-customer-rule-group"}},
            }
            for action in ["Allow", "Block", "Count", "Captcha", "Challenge"]
        ]
        rules.append({"Name": name, "OverrideAction": {"None": {}}, "Statement": {}, "VisibilityConfig": visibility})
        return {
            "list_web_acls": {
                "WebACLs": [{"Name": name, "Id": "synthetic-customer-acl", "ARN": "arn:aws:wafv2:eu-west-2:123456789012:regional/webacl/synthetic/id"}]
            },
            "get_web_acl": {"WebACL": {"Capacity": 50, "Rules": [] if nullable else rules, "DefaultAction": {"Allow": {}}, "VisibilityConfig": visibility}},
            "list_resources_for_web_acl": {
                "ResourceArns": [
                    "arn:aws:elasticloadbalancing:eu-west-2:123456789012:loadbalancer/app/synthetic/id",
                    "arn:aws:apigateway:eu-west-2::/restapis/synthetic/stages/test",
                ]
            },
        }
    message = "Unexpected synthetic governance service."
    raise AssertionError(message)
