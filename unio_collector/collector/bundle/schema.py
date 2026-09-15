from __future__ import annotations  # noqa: D100

from dataclasses import dataclass

RESULT_BUNDLE_SCHEMA_VERSION = "2026-01"
COLLECTOR_BUNDLE_SCHEMA_VERSION = "2026-02"
PROTECTED_BUNDLE_SCHEMA_VERSION = "2026-03"
BUNDLE_SCHEMA_VERSION = RESULT_BUNDLE_SCHEMA_VERSION
COLLECTION_MODE = "read_only"
EVIDENCE_BUNDLE_FORMAT = "unio-result-evidence-bundle"

SERVICE_EVIDENCE_FILES = (
    "evidence/account.json",
    "evidence/regions.json",
    "evidence/cost-explorer.json",
    "evidence/ec2.json",
    "evidence/ebs.json",
    "evidence/s3.json",
    "evidence/rds.json",
    "evidence/lambda.json",
    "evidence/iam.json",
    "evidence/cloudwatch.json",
    "evidence/cloudfront.json",
    "evidence/dynamodb.json",
    "evidence/config.json",
    "evidence/cloudtrail.json",
    "evidence/security-services.json",
    "evidence/service-quotas.json",
    "evidence/free-tier.json",
)

REQUIRED_BUNDLE_FILES = (
    "manifest.json",
    "bundle-schema.json",
    "analysis-contract.json",
    "collector-version.json",
    "account-scope.json",
    "permissions-summary.json",
    "collection-summary.json",
    "collection-log.jsonl",
    "scan-result/report-bundle.json",
    "scan-result/scanner-results.json",
    "scan-result/evidence-records.json",
    "scan-result/api-runtime-summary.json",
    "evidence/normalized-evidence.json",
    *SERVICE_EVIDENCE_FILES,
    "checksums.json",
    "signature.json",
)

OPTIONAL_BUNDLE_FILES = (
    "analysis-readiness.json",
    "permissions/degradation-records.json",
    "scan-result/scanner-evidence.json",
    "scan-result/pricing-context.json",
)

PROTECTED_PRIVACY_FILES = (
    "privacy/protection-policy.json",
    "privacy/classification-summary.json",
    "privacy/preview-summary.json",
    "privacy/leak-scan-summary.json",
    "privacy/token-metadata.json",
)

SUPPORTED_SCHEMA_VERSIONS = (
    RESULT_BUNDLE_SCHEMA_VERSION,
    COLLECTOR_BUNDLE_SCHEMA_VERSION,
    PROTECTED_BUNDLE_SCHEMA_VERSION,
)

MANIFEST_FIELDS = (
    "bundle_schema_version",
    "bundle_purpose",
    "analysis_state",
    "collector_version",
    "collection_mode",
    "collection_status",
    "generated_at",
    "evidence_generated_at",
    "account_id",
    "partition",
    "regions",
    "region_scope",
    "services_attempted",
    "services_collected",
    "services_unavailable",
    "permission_limitations",
    "permission_degradation_record_count",
    "evidence_files",
    "checksums",
    "redaction_or_minimisation",
    "privacy_protection",
    "source",
    "product_execution",
)


@dataclass(frozen=True)
class BundleSchema:
    """Stable evidence-bundle schema metadata shared by writers and validators."""

    schema_version: str = BUNDLE_SCHEMA_VERSION
    format_name: str = EVIDENCE_BUNDLE_FORMAT
    required_files: tuple[str, ...] = REQUIRED_BUNDLE_FILES
    optional_files: tuple[str, ...] = OPTIONAL_BUNDLE_FILES
    service_files: tuple[str, ...] = SERVICE_EVIDENCE_FILES

    def convert_to_dict(self) -> dict[str, object]:
        """Return the schema payload written into evidence bundles."""
        return {
            "format": self.format_name,
            "bundle_schema_version": self.schema_version,
            "required_files": list(self.required_files),
            "optional_files": list(self.optional_files),
            "service_evidence_files": list(self.service_files),
            "path_format": "posix",
            "encoding": "utf-8",
        }


def schema_version_for_bundle_purpose(bundle_purpose: str) -> str:
    """Return the evidence-bundle schema version for a bundle purpose."""
    if bundle_purpose == "collector_evidence":
        return COLLECTOR_BUNDLE_SCHEMA_VERSION
    return RESULT_BUNDLE_SCHEMA_VERSION


def required_files_for_schema_version(schema_version: object) -> tuple[str, ...]:
    """Return required internal files for a supported evidence-bundle schema."""
    if schema_version == PROTECTED_BUNDLE_SCHEMA_VERSION:
        return (*REQUIRED_BUNDLE_FILES, *PROTECTED_PRIVACY_FILES)
    return REQUIRED_BUNDLE_FILES
