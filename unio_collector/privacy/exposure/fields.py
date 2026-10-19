"""Explicit field, type and finite-vocabulary bindings for emitted exposure DTOs."""

from unio_collector.privacy.s3.fields import fields

VOCABULARIES = {
    "ingress_cidr": {"0.0.0.0/0", "::/0"},
    "exposure_kind": {"publicly_accessible", "public_endpoint_review", "internet_facing", "origin_exposure_review"},
    "exposure_confidence": {"high", "medium"},
    "exposure_service": {"Amazon RDS", "Amazon OpenSearch Service", "Amazon Redshift", "Elastic Load Balancing", "Amazon API Gateway", "Amazon CloudFront"},
    "exposure_resource": {
        "RDS DB instance",
        "OpenSearch domain",
        "Redshift cluster",
        "Application or Network Load Balancer",
        "API Gateway REST API",
        "API Gateway HTTP/WebSocket API",
        "CloudFront origin",
    },
    "balancer_type": {"application", "network", "gateway"},
    "endpoint_type": {"REGIONAL", "EDGE", "PRIVATE"},
    "api_protocol": {"HTTP", "WEBSOCKET"},
    "tag_mutability": {"MUTABLE", "IMMUTABLE", "MUTABLE_WITH_EXCLUSION", "IMMUTABLE_WITH_EXCLUSION"},
    "repository_encryption": {"AES256", "KMS", "KMS_DSSE"},
    "registry_scan": {"BASIC", "ENHANCED"},
}
ROOT = {"": ("object", "safe_metadata", False)}
REGIONAL = {**ROOT, **fields("regions warnings", "array"), **fields("regions[]", "string", "region"), **fields("warnings[]", "string", "free_text")}
GROUP = {
    **REGIONAL,
    **fields("collection_evidence_version", "count", "summary_count"),
    **fields("public_ingress_rules", "array"),
    **fields("public_ingress_rules[]", "object"),
    **fields("public_ingress_rules[].group_id", "string", "resource_id"),
    **fields("public_ingress_rules[].group_name", "string", "resource_name"),
    **fields("public_ingress_rules[].vpc_id", "string", "resource_id", nullable=True),
    **fields("public_ingress_rules[].region", "string", "region"),
    **fields("public_ingress_rules[].protocol", "ingress_protocol"),
    **fields("public_ingress_rules[].from_port public_ingress_rules[].to_port", "port", nullable=True),
    **fields("public_ingress_rules[].cidr", "ingress_cidr"),
    **fields("public_ingress_rules[].associated_platform public_ingress_rules[].association_reason", "null", nullable=True),
    **fields("public_ingress_rules[].name_contains_lightsail", "boolean", nullable=True),
}
PUBLIC = {**REGIONAL, **fields("records global_records", "array"), **fields("records[] global_records[]", "object")}
for prefix in ("records[]", "global_records[]"):
    PUBLIC.update(
        {
            **fields(prefix + ".region", "string", "region"),
            **fields(prefix + ".resource_id", "string", "resource_id"),
            **fields(prefix + ".resource_name", "string", "resource_name", nullable=True),
            **fields(prefix + ".arn", "string", "arn", nullable=True),
            **fields(prefix + ".detail", "string", "free_text"),
            **fields(prefix + ".metadata", "object"),
            **fields(prefix + ".metadata.type", "balancer_type", nullable=True),
            **fields(prefix + ".metadata.protocol_type", "api_protocol", nullable=True),
            **fields(prefix + ".metadata.endpoint_types", "array"),
            **fields(prefix + ".metadata.endpoint_types[]", "endpoint_type"),
            **fields(prefix + ".metadata.distribution_id", "string", "resource_id"),
            **fields(prefix + ".service_name", "exposure_service"),
            **fields(prefix + ".resource_type", "exposure_resource"),
            **fields(prefix + ".exposure_type", "exposure_kind"),
            **fields(prefix + ".confidence", "exposure_confidence"),
        }
    )
ECR = {
    **REGIONAL,
    **fields("account_id", "string", "aws_account_id"),
    **fields("repositories registries", "array"),
    **fields("repositories[] registries[]", "object"),
    **fields("repositories[].repository_name", "string", "resource_name"),
    **fields("repositories[].repository_arn", "string", "arn", nullable=True),
    **fields("repositories[].region registries[].region", "string", "region"),
    **fields("repositories[].scan_on_push", "boolean", nullable=True),
    **fields("repositories[].image_tag_mutability", "tag_mutability", nullable=True),
    **fields("repositories[].encryption_type", "repository_encryption", nullable=True),
    **fields("repositories[].kms_key", "string", "arn_or_name", nullable=True),
    **fields("registries[].scan_type", "registry_scan", nullable=True),
    **fields("registries[].rule_count", "count", "summary_count"),
}
SCANNERS = {
    "ec2-security-group-exposure-review": ("security_governance.security_group.evidence", "SecurityGroupExposureEvidence", GROUP),
    "public-service-exposure-review": ("security_governance.public_exposure.evidence", "PublicServiceExposureEvidence", PUBLIC),
    "ecr-image-scan-posture-review": ("ecr.image_scan.evidence", "EcrImageScanPostureEvidence", ECR),
    "root-account-recovery-advisory": (
        "account_risk.root.recovery.evidence",
        "RootAccountRecoveryAdvisoryEvidence",
        {**ROOT, **fields("account_id", "string", "aws_account_id")},
    ),
}
