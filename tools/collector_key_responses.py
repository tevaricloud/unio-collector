"""Finite synthetic provider responses for actual KMS and encryption collectors."""

from __future__ import annotations

from typing import Any


def responses(service: str, variant: str, parameters: dict[str, object]) -> dict[str, dict[str, Any]]:
    """Emit SDK-shaped input, never a hand-written evidence DTO."""
    name = "Enabled" if variant == "collision" else "synthetic-customer-key"
    if variant == "identity_collision":
        name = str(parameters.pop("scanner"))
    nullable = variant == "nullable"
    if service == "kms":
        key_id = str(parameters.get("KeyId", name))
        metadata: dict[str, Any] = {"KeyId": key_id}
        if not nullable:
            metadata.update(
                Arn=f"arn:aws:kms:eu-west-2:123456789012:key/{key_id}",
                KeyManager="AWS" if key_id == "synthetic-aws-key" else "CUSTOMER",
                KeyState="Disabled" if key_id.endswith("disabled") else "PendingDeletion" if key_id.endswith("deletion") else "Enabled",
                KeySpec="RSA_2048" if key_id.endswith("asymmetric") else "HMAC_256" if key_id.endswith("hmac") else "SYMMETRIC_DEFAULT",
                KeyUsage="SIGN_VERIFY" if key_id.endswith("asymmetric") else "GENERATE_VERIFY_MAC" if key_id.endswith("hmac") else "ENCRYPT_DECRYPT",
                Origin="EXTERNAL" if key_id.endswith("external") else "AWS_KMS",
                MultiRegion=True,
                MultiRegionConfiguration={"MultiRegionKeyType": "REPLICA" if key_id.endswith("replica") else "PRIMARY"},
            )
        if variant == "rotation_off":
            name = "synthetic-customer-rotation-off"
            if "KeyId" not in parameters:
                metadata["KeyId"] = name
        keys = [
            name,
            "synthetic-customer-disabled",
            "synthetic-customer-deletion",
            "synthetic-customer-asymmetric",
            "synthetic-customer-hmac",
            "synthetic-customer-external",
            "synthetic-customer-replica",
            "synthetic-aws-key",
            "synthetic-alias-aws",
        ]
        return {
            "list_keys": {"Keys": [{"KeyId": key} for key in keys]},
            "list_aliases": {
                "Aliases": [
                    {"AliasName": "alias/synthetic-customer-alias", "TargetKeyId": name},
                    {"AliasName": "alias/aws/synthetic", "TargetKeyId": "synthetic-alias-aws"},
                ]
            },
            "describe_key": {"KeyMetadata": metadata},
            "get_key_rotation_status": {"KeyRotationEnabled": not key_id.endswith(("disabled", "rotation-off"))},
            "list_resource_tags": {"Tags": [] if key_id.endswith("replica") else [{"TagKey": "Name", "TagValue": "synthetic-customer-tag"}]},
        }
    if service == "ec2":
        return {
            "get_ebs_encryption_by_default": {"EbsEncryptionByDefault": True},
            "get_ebs_default_kms_key_id": {"KmsKeyId": name},
            "describe_volumes": {
                "Volumes": [
                    {"VolumeId": name, "Encrypted": True, **({} if nullable else {"KmsKeyId": name})},
                    {"VolumeId": "synthetic-customer-volume", "Encrypted": False},
                ]
            },
            "describe_snapshots": {"Snapshots": [{"SnapshotId": name, "Encrypted": True, **({} if nullable else {"KmsKeyId": name})}]},
        }
    if service == "s3":
        return {
            "list_buckets": {"Buckets": [{"Name": name}, {"Name": "synthetic-customer-absent"}, {"Name": "synthetic-customer-empty"}]},
            "get_bucket_encryption": {
                "ServerSideEncryptionConfiguration": {
                    "Rules": []
                    if str(parameters.get("Bucket", "")).endswith("empty")
                    else [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": algorithm}} for algorithm in ("AES256", "aws:kms", "aws:kms:dsse")]
                }
            },
        }
    if service == "securityhub":
        finding = {
            "Compliance": {"SecurityControlId": name},
            "GeneratorId": "synthetic-customer-generator",
            "Title": "synthetic-customer-title",
            "Severity": {"Label": "HIGH"},
            "ProductFields": {"StandardsArn": "arn:aws:securityhub:eu-west-2:123456789012:standards/synthetic-customer"},
            "Resources": [{"Type": "AwsS3Bucket"}, {"Type": "AwsKmsKey"}],
        }
        if nullable:
            finding = {"GeneratorId": name}
        return {
            "describe_hub": {},
            "get_findings": {
                "Findings": [finding, finding.copy(), {"Compliance": {"SecurityControlId": "synthetic-customer-other"}, "Severity": {"Label": "UNKNOWN"}}]
            },
        }
    message = "Unexpected offline endpoint"
    raise AssertionError(message)


def shape_response(value: dict[str, Any], variant: str, operation: str, scanner: str) -> dict[str, Any]:
    """Simulate finite empty, malformed and incomplete provider page branches."""
    if variant == "empty":
        value = {key: [] if isinstance(child, list) else child for key, child in value.items()}
    if variant == "malformed" and operation in {"list_keys", "describe_volumes", "describe_snapshots", "get_findings"}:
        value = {key: [*child, {}] if isinstance(child, list) else child for key, child in value.items()}
    if variant == "malformed" and operation == "list_keys" and scanner == "kms-cost-governance-review":
        value = dict(value, NextMarker=["synthetic-customer-invalid-cursor"])
    if variant == "truncated" and operation in {"list_keys", "describe_volumes", "describe_snapshots", "get_findings"}:
        cursor_key = "NextMarker" if operation == "list_keys" else "NextToken"
        value = dict(value, **{cursor_key: "synthetic-customer-cursor", "Truncated": True})
    return value
