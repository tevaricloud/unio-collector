from __future__ import annotations  # noqa: D100

SERVICE_EVIDENCE_FILE_BY_SERVICE = {
    "amazon-ec2": "evidence/ec2.json",
    "ec2": "evidence/ec2.json",
    "ebs": "evidence/ebs.json",
    "amazon-s3": "evidence/s3.json",
    "s3": "evidence/s3.json",
    "rds": "evidence/rds.json",
    "lambda": "evidence/lambda.json",
    "aws-lambda": "evidence/lambda.json",
    "iam": "evidence/iam.json",
    "cloudwatch": "evidence/cloudwatch.json",
    "amazon-cloudwatch": "evidence/cloudwatch.json",
    "cloudfront": "evidence/cloudfront.json",
    "dynamodb": "evidence/dynamodb.json",
    "aws-config": "evidence/config.json",
    "config": "evidence/config.json",
    "cloudtrail": "evidence/cloudtrail.json",
    "securityhub": "evidence/security-services.json",
    "guardduty": "evidence/security-services.json",
    "service-quotas": "evidence/service-quotas.json",
    "free-tier": "evidence/free-tier.json",
    "cost-explorer": "evidence/cost-explorer.json",
    "ce": "evidence/cost-explorer.json",
}


def get_service_evidence_file(service: str) -> str:  # noqa: D103
    return SERVICE_EVIDENCE_FILE_BY_SERVICE.get(service, "evidence/account.json")
