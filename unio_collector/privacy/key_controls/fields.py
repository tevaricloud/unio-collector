"""Complete finite contracts for actual key and encryption producer DTOs."""

from __future__ import annotations

from unio_collector.privacy.audit.fields import BILLING, COMMON
from unio_collector.privacy.s3.fields import fields

VOCABULARIES = {
    "manager": {"", "AWS", "CUSTOMER"},
    "state": {"", "Creating", "Enabled", "Disabled", "PendingDeletion", "PendingImport", "PendingReplicaDeletion", "Unavailable", "Updating"},
    "spec": {
        "",
        "RSA_2048",
        "RSA_3072",
        "RSA_4096",
        "ECC_NIST_P256",
        "ECC_NIST_P384",
        "ECC_NIST_P521",
        "ECC_SECG_P256K1",
        "SYMMETRIC_DEFAULT",
        "HMAC_224",
        "HMAC_256",
        "HMAC_384",
        "HMAC_512",
        "SM2",
        "ML_DSA_44",
        "ML_DSA_65",
        "ML_DSA_87",
        "ECC_NIST_EDWARDS25519",
    },
    "usage": {"", "SIGN_VERIFY", "ENCRYPT_DECRYPT", "GENERATE_VERIFY_MAC", "KEY_AGREEMENT"},
    "origin": {"", "AWS_KMS", "EXTERNAL", "AWS_CLOUDHSM", "EXTERNAL_KEY_STORE"},
    "multi_kind": {"", "PRIMARY", "REPLICA"},
    "tag_state": {"known_tagged", "known_untagged", "unknown"},
    "algorithm": {"AES256", "aws:kms", "aws:kms:dsse"},
    "severity": {"INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"},
}
for _kind in ("manager", "state", "spec", "usage", "origin", "multi_kind"):
    VOCABULARIES["raw_" + _kind] = VOCABULARIES[_kind]
    VOCABULARIES[_kind] = VOCABULARIES[_kind] - {""}

ROOT = {
    "": ("object", "safe_metadata", False),
    **fields("regions warnings", "array"),
    **fields("regions[]", "string", "region"),
    **fields("warnings[]", "string", "free_text"),
}
KMS_COST = {
    **COMMON,
    **BILLING,
    **fields(
        " ".join(
            "records[]." + name
            for name in [
                "listed_key_count",
                "key_count",
                "inaccessible_key_count",
                "customer_managed_key_count",
                "aws_managed_key_count",
                "alias_classified_aws_managed_key_count",
                "enabled_customer_key_count",
                "disabled_customer_key_count",
                "pending_deletion_key_count",
                "multi_region_key_count",
                "multi_region_primary_key_count",
                "multi_region_replica_key_count",
                "symmetric_key_count",
                "asymmetric_key_count",
                "hmac_key_count",
                "external_origin_key_count",
                "rotation_enabled_key_count",
                "rotation_disabled_key_count",
                "tagged_key_count",
                "untagged_key_count",
                "alias_count",
                "customer_alias_count",
            ]
        ),
        "count",
        "summary_count",
    ),
    **fields(
        " ".join(
            "records[]." + name
            for name in [
                "sample_key_ids",
                "sample_inaccessible_key_ids",
                "sample_alias_classified_aws_managed_key_ids",
                "sample_alias_names",
                "sample_key_states",
                "sample_key_specs",
                "sample_key_usages",
                "sample_key_origins",
                "sample_multi_region_key_types",
                "sample_disabled_key_ids",
                "sample_pending_deletion_key_ids",
                "sample_rotation_disabled_key_ids",
            ]
        ),
        "array",
    ),
    **fields(
        " ".join(
            "records[]." + name + "[]"
            for name in [
                "sample_key_ids",
                "sample_inaccessible_key_ids",
                "sample_alias_classified_aws_managed_key_ids",
                "sample_disabled_key_ids",
                "sample_pending_deletion_key_ids",
                "sample_rotation_disabled_key_ids",
            ]
        ),
        "string",
        "resource_id",
    ),
    **fields("records[].sample_alias_names[]", "string", "resource_name"),
    **fields("records[].raw_keys", "array", nullable=True),
    **fields("records[].raw_keys[]", "object"),
    **fields("records[].raw_keys[].key_id", "string", "resource_id"),
    **fields("records[].raw_keys[].multi_region records[].raw_keys[].rotation_applicable", "boolean"),
    **fields("records[].raw_keys[].rotation_enabled", "boolean", nullable=True),
    **fields("records[].raw_keys[].tag_count", "count", "summary_count", nullable=True),
    **fields("records[].raw_keys[].tag_read_state", "tag_state"),
}
for sample, raw, kind in (
    ("sample_key_states", "key_state", "state"),
    ("sample_key_specs", "key_spec", "spec"),
    ("sample_key_usages", "key_usage", "usage"),
    ("sample_key_origins", "origin", "origin"),
    ("sample_multi_region_key_types", "multi_region_key_type", "multi_kind"),
):
    KMS_COST.update(fields(f"records[].{sample}[]", kind))
    KMS_COST.update(fields(f"records[].raw_keys[].{raw}", "raw_" + kind))
KMS_COST.update(fields("records[].raw_keys[].key_manager", "raw_manager"))
KMS_POSTURE = {
    **ROOT,
    **fields("keys", "array"),
    **fields("keys[]", "object"),
    **fields("keys[].key_id", "string", "resource_id"),
    **fields("keys[].arn", "string", "arn", nullable=True),
    **fields("keys[].region", "string", "region"),
    **fields("keys[].rotation_enabled keys[].multi_region", "boolean", nullable=True),
    **{
        f"keys[].{name}": (kind, "safe_metadata", True)
        for name, kind in (("key_manager", "manager"), ("key_state", "state"), ("key_usage", "usage"), ("key_spec", "spec"), ("origin", "origin"))
    },
}
ENCRYPTION = {
    **ROOT,
    **fields("ebs_region_settings ebs_volumes ebs_snapshots s3_buckets", "array"),
    **fields("ebs_region_settings[] ebs_volumes[] ebs_snapshots[] s3_buckets[]", "object"),
    **fields("ebs_region_settings[].region ebs_volumes[].region ebs_snapshots[].region", "string", "region"),
    **fields("ebs_region_settings[].enabled_by_default s3_buckets[].encryption_configured", "boolean", nullable=True),
    **fields("ebs_volumes[].encrypted ebs_snapshots[].encrypted", "boolean"),
    **fields("ebs_region_settings[].default_kms_key_id ebs_volumes[].kms_key_id ebs_snapshots[].kms_key_id", "string", "arn_or_name", nullable=True),
    **fields("ebs_volumes[].volume_id ebs_snapshots[].snapshot_id", "string", "resource_id"),
    **fields("s3_buckets[].bucket_name", "string", "bucket_name"),
    **fields("s3_buckets[].encryption_rules", "array"),
    **fields("s3_buckets[].encryption_rules[]", "algorithm"),
}
CONTROL_SUMMARY = {
    **ROOT,
    **fields("records enabled_regions unavailable_regions not_enabled_regions", "array"),
    **fields("enabled_regions[] unavailable_regions[] not_enabled_regions[] records[].region", "string", "region"),
    **fields("records[]", "object"),
    **fields("records[].control_id", "string", "resource_id"),
    **fields("records[].title", "string", "free_text"),
    **fields("records[].severity_label", "severity"),
    **fields("records[].failed_finding_count", "count", "summary_count"),
    **fields("records[].standard_arns records[].resource_types", "array"),
    **fields("records[].standard_arns[]", "string", "arn"),
    **fields("records[].resource_types[]", "string", "free_text"),
}
SCANNERS = {
    "kms-cost-governance-review": ("kms.cost_governance.evidence", "KmsCostGovernanceEvidence", KMS_COST),
    "kms-key-posture-review": ("kms.key_posture.evidence", "KmsKeyPostureEvidence", KMS_POSTURE),
    "encryption-baseline-review": ("security_governance.encryption.evidence", "EncryptionBaselineEvidence", ENCRYPTION),
    "securityhub-control-summary-review": ("security_governance.security_hub.summary.evidence", "SecurityHubControlSummaryEvidence", CONTROL_SUMMARY),
}
