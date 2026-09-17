from __future__ import annotations  # noqa: D100

# ruff: noqa: S105

PRIVACY_POLICY_VERSION = "2026-03"
TOKEN_FORMAT_VERSION = "unio-token-v1"
LEGACY_VAULT_FORMAT_VERSION = "unio-vault-v1"
VAULT_FORMAT_VERSION = "unio-vault-v2"
VAULT_PLAINTEXT_SCHEMA_VERSION = "2026-08-v2"
PRIVACY_PREVIEW_SCHEMA_VERSION = "2026-08-privacy-preview-v2"
PROTECTED_BUNDLE_SCHEMA_VERSION = "2026-03"
PROTECTED_EXPORT_RECEIPT_SCHEMA_VERSION = "2026-03-protected-export-receipt-v1"
RESTORATION_COMPLETION_SCHEMA_VERSION = "2026-03-restoration-completion-v1"

PRIVACY_POLICY_FILE = "privacy/protection-policy.json"
PRIVACY_CLASSIFICATION_FILE = "privacy/classification-summary.json"
PRIVACY_PREVIEW_FILE = "privacy/preview-summary.json"
PRIVACY_LEAK_SCAN_FILE = "privacy/leak-scan-summary.json"
PRIVACY_TOKEN_METADATA_FILE = "privacy/token-metadata.json"

PRIVACY_BUNDLE_FILES = (
    PRIVACY_POLICY_FILE,
    PRIVACY_CLASSIFICATION_FILE,
    PRIVACY_PREVIEW_FILE,
    PRIVACY_LEAK_SCAN_FILE,
    PRIVACY_TOKEN_METADATA_FILE,
)

SUPPORTED_TOKEN_SCOPES = ("bundle", "engagement", "client")
SUPPORTED_PRIVACY_PROFILES = ("standard", "strict", "custom")
