"""AWS organization envelope schema constants."""

ORGANIZATION_ENVELOPE_SCHEMA_VERSION = "2026-08-aws-organization-envelope-v1"
ORGANIZATION_REQUIRED_FILES = {
    "organization-manifest.json",
    "organization-request.json",
    "organization-scope.json",
    "organization-coverage.json",
    "organization-run-summary.json",
    "role-assumption-audit.jsonl",
    "checksums.json",
    "signature.json",
}
