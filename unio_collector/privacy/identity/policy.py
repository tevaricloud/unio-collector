"""Closed IAM policy document positions admitted by the full-detail producer."""

from unio_collector.privacy.s3.fields import fields

OPERATORS = {
    "StringEquals",
    "StringNotEquals",
    "StringEqualsIgnoreCase",
    "StringNotEqualsIgnoreCase",
    "StringLike",
    "StringNotLike",
    "NumericEquals",
    "NumericNotEquals",
    "NumericLessThan",
    "NumericLessThanEquals",
    "NumericGreaterThan",
    "NumericGreaterThanEquals",
    "DateEquals",
    "DateNotEquals",
    "DateLessThan",
    "DateLessThanEquals",
    "DateGreaterThan",
    "DateGreaterThanEquals",
    "Bool",
    "BinaryEquals",
    "IpAddress",
    "NotIpAddress",
    "ArnEquals",
    "ArnLike",
    "ArnNotEquals",
    "ArnNotLike",
    "Null",
}
BASE_OPERATORS = set(OPERATORS)
OPERATORS |= {operator + "IfExists" for operator in BASE_OPERATORS if operator != "Null"}
OPERATORS |= {prefix + operator for prefix in ("ForAllValues:", "ForAnyValue:") for operator in tuple(OPERATORS) if operator != "Null"}
CONDITION_KEYS = {
    "aws:PrincipalArn",
    "aws:PrincipalAccount",
    "aws:SourceArn",
    "aws:SourceAccount",
    "aws:SourceIp",
    "aws:SecureTransport",
    "aws:MultiFactorAuthPresent",
    "aws:MultiFactorAuthAge",
    "aws:CurrentTime",
    "aws:EpochTime",
    "aws:RequestedRegion",
    "aws:username",
    "aws:userid",
    "aws:SourceVpc",
    "aws:SourceVpce",
    "aws:ViaAWSService",
    "aws:CalledVia",
    "aws:PrincipalOrgID",
    "s3:prefix",
    "s3:delimiter",
    "kms:ViaService",
    "kms:CallerAccount",
}
PREFIX = "policy_grants[].policy_document"
POLICY_FIELDS = {
    **fields(PREFIX + ".Version", "policy_version"),
    **fields(PREFIX + ".Id", "string", "resource_id"),
    **fields(PREFIX + ".Statement", "statement"),
}
for statement in (PREFIX + ".Statement", PREFIX + ".Statement[]"):
    if statement.endswith("[]"):
        POLICY_FIELDS.update(fields(statement, "object"))
    POLICY_FIELDS.update(fields(statement + ".Sid", "string", "resource_id"))
    POLICY_FIELDS.update(fields(statement + ".Effect", "effect"))
    for key in ("Action", "NotAction", "Resource", "NotResource"):
        POLICY_FIELDS.update(fields(statement + "." + key, "strings", "free_text"))
        POLICY_FIELDS.update(fields(statement + "." + key + "[]", "string", "free_text"))
    POLICY_FIELDS.update(fields(statement + ".Condition", "object"))
    for operator in sorted(OPERATORS):
        position = statement + ".Condition." + operator
        POLICY_FIELDS.update(fields(position, "object"))
        for key in sorted(CONDITION_KEYS):
            POLICY_FIELDS.update(fields(position + "." + key, "strings", "free_text"))
            POLICY_FIELDS.update(fields(position + "." + key + "[]", "string", "free_text"))


def invalid_policy_shape(value: object, suffix: str) -> bool:
    """Require real producer statement discriminants and exclusive action/resource pairs."""
    if not isinstance(value, dict):
        return False
    if suffix == PREFIX:
        return "Statement" not in value
    if suffix not in {PREFIX + ".Statement", PREFIX + ".Statement[]"}:
        return False
    return value.get("Effect") not in {"Allow", "Deny"} or any(
        (positive in value) == (negative in value) for positive, negative in (("Action", "NotAction"), ("Resource", "NotResource"))
    )
