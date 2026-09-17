from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field

from unio_collector.privacy.registry_entry import PrivacyRegistryEntry
from unio_collector.privacy.terms import (
    FALLBACK_SAFE_STRING_KEYS,
    FALLBACK_SENSITIVE_KEY_CATEGORIES,
    FALLBACK_TEXT_KEYS,
    PROHIBITED_KEY_CATEGORIES,
    REMOVED_KEY_CATEGORIES,
    STRICT_GENERALISE_KEYS,
    STRICT_REMOVE_KEYS,
    STRICT_TOPOLOGY_KEYS,
)

TREATMENTS = (
    "preserve",
    "tokenise",
    "remove",
    "generalise",
    "derive_then_tokenise",
    "profile_configurable",
    "prohibited",
)

REGISTRY_DOMAINS = (
    "protected_bundle_input",
    "protected_bundle_privacy_metadata",
    "protected_report_package_json",
    "local_restored_output",
)


SUPPORTED_JSON_FILES = {
    "account-scope.json",
    "analysis-contract.json",
    "analysis-readiness.json",
    "bundle-schema.json",
    "checksums.json",
    "collection-summary.json",
    "collector-version.json",
    "permissions-summary.json",
    "permissions/degradation-records.json",
    "collection-log.jsonl",
    "manifest.json",
    "scan-result/api-runtime-summary.json",
    "scan-result/scanner-results.json",
    "scan-result/scanner-evidence.json",
    "scan-result/pricing-context.json",
    "scan-result/evidence-records.json",
    "scan-result/report-bundle.json",
    "signature.json",
    "evidence/normalized-evidence.json",
}

SUPPORTED_JSON_PREFIXES = ("evidence/",)

FALLBACK_ENABLED_INPUT_PATHS = {
    "scan-result/scanner-evidence.json",
    "scan-result/pricing-context.json",
    "scan-result/evidence-records.json",
    "evidence/*.json",
}

PROTECTED_BUNDLE_INPUT_PATHS = tuple(
    sorted(
        {
            *SUPPORTED_JSON_FILES,
            "scan-result/report-bundle.json",
            "evidence/*.json",
        },
    ),
)

PROTECTED_BUNDLE_PRIVACY_METADATA_PATHS = (
    "privacy/protection-policy.json",
    "privacy/classification-summary.json",
    "privacy/preview-summary.json",
    "privacy/leak-scan-summary.json",
    "privacy/token-metadata.json",
)

PROTECTED_REPORT_PACKAGE_JSON_PATHS = ("data/privacy/protected-report-package.json",)

LOCAL_RESTORED_OUTPUT_PATHS = (
    "restored-report.json",
    "restored-report.md",
    "restored-report.html",
    "data/findings.csv",
    "workbooks/findings.xlsx",
    "report-index.json",
    "diagrams/resources.mmd",
    "restoration-audit.json",
)

_BASE_PATH_REGISTRY: tuple[PrivacyRegistryEntry, ...] = (
    *(
        PrivacyRegistryEntry(
            domain="protected_bundle_input",
            member_pattern=path,
            json_path_pattern="$..*",
            value_category="mixed_evidence",
            treatment="profile_configurable",
            canonicaliser_id="schema-aware-v1",
            canonicaliser_version="2026-03",
            fallback_allowed=path in FALLBACK_ENABLED_INPUT_PATHS,
            limitations=("Path is transformed structurally before leak scanning.",),
        )
        for path in PROTECTED_BUNDLE_INPUT_PATHS
    ),
    *(
        PrivacyRegistryEntry(
            domain="protected_bundle_privacy_metadata",
            member_pattern=path,
            json_path_pattern="$..*",
            value_category="privacy_metadata",
            treatment="preserve",
            filename_allowed=True,
            limitations=("Metadata must remain non-secret and pass deep validation.",),
        )
        for path in PROTECTED_BUNDLE_PRIVACY_METADATA_PATHS
    ),
    PrivacyRegistryEntry(
        domain="protected_report_package_json",
        member_pattern="data/privacy/protected-report-package.json",
        json_path_pattern="$",
        value_category="protected_report_json_v1",
        treatment="preserve",
        limitations=("Signed structured JSON package, not a ZIP archive or restored report.",),
    ),
    *(
        PrivacyRegistryEntry(
            domain="local_restored_output",
            member_pattern=path,
            json_path_pattern="$",
            value_category="local_restored_report_output",
            treatment="preserve",
            filename_allowed=True,
            limitations=("Created only after local vault-backed restoration.",),
        )
        for path in LOCAL_RESTORED_OUTPUT_PATHS
    ),
    PrivacyRegistryEntry(
        domain="protected_bundle_input",
        member_pattern="*",
        json_path_pattern="$..account_id",
        value_category="aws_account_id",
        treatment="tokenise",
        canonicaliser_id="aws-account-id",
        canonicaliser_version="2026-03",
    ),
    PrivacyRegistryEntry(
        domain="protected_bundle_input",
        member_pattern="*",
        json_path_pattern="$..arn",
        value_category="arn",
        treatment="derive_then_tokenise",
        canonicaliser_id="aws-arn",
        canonicaliser_version="2026-03",
    ),
    PrivacyRegistryEntry(
        domain="protected_bundle_input",
        member_pattern="*",
        json_path_pattern="$..source_id",
        value_category="resource_id",
        treatment="tokenise",
        canonicaliser_id="resource-id",
        canonicaliser_version="2026-03",
    ),
    PrivacyRegistryEntry(
        domain="protected_bundle_input",
        member_pattern="*",
        json_path_pattern="$..tags",
        value_category="tag",
        treatment="profile_configurable",
        canonicaliser_id="tag-value",
        canonicaliser_version="2026-03",
    ),
    PrivacyRegistryEntry(
        domain="protected_bundle_input",
        member_pattern="*",
        json_path_pattern="$..cost",
        value_category="cost",
        treatment="profile_configurable",
        limitations=("Strict profile removes or nulls cost precision.",),
    ),
    PrivacyRegistryEntry(
        domain="protected_bundle_input",
        member_pattern="*",
        json_path_pattern="$..timestamp",
        value_category="timestamp",
        treatment="profile_configurable",
        limitations=("Strict profile generalises to month precision.",),
    ),
    PrivacyRegistryEntry(
        domain="protected_bundle_input",
        member_pattern="scan-result/report-bundle.json",
        json_path_pattern="$..id",
        value_category="finding_id",
        treatment="preserve",
        limitations=("Report-bundle finding IDs are deterministic Unio identifiers.",),
    ),
    *(
        PrivacyRegistryEntry(
            domain="protected_bundle_input",
            member_pattern="*",
            json_path_pattern=f"$..{key}",
            value_category="product_execution_metadata",
            treatment="preserve",
            limitations=("Value is public contract metadata and must not contain local execution references.",),
        )
        for key in (
            "product_execution",
            "product_id",
            "product_definition_version",
            "definition_version",
            "registry_version",
            "selection_source",
            "report_label",
            "report_set_id",
            "primary_report_order",
            "out_of_product_overrides",
        )
    ),
)

SENSITIVE_KEY_CATEGORIES = FALLBACK_SENSITIVE_KEY_CATEGORIES
TEXT_KEYS = FALLBACK_TEXT_KEYS
SAFE_STRING_KEYS = FALLBACK_SAFE_STRING_KEYS

_REMOVED_KEY_CATEGORIES = REMOVED_KEY_CATEGORIES
_PROHIBITED_KEY_CATEGORIES = PROHIBITED_KEY_CATEGORIES
_STRICT_REMOVE_KEYS = STRICT_REMOVE_KEYS
_STRICT_GENERALISE_KEYS = STRICT_GENERALISE_KEYS
_STRICT_TOPOLOGY_KEYS = STRICT_TOPOLOGY_KEYS


def _key_suffix_entry(
    *,
    key: str,
    category: str,
    treatment: str,
    allowed_profiles: tuple[str, ...] = ("standard", "strict", "custom"),
    canonicaliser_id: str | None = None,
    canonicaliser_version: str | None = None,
    limitations: tuple[str, ...] = (),
) -> PrivacyRegistryEntry:
    return PrivacyRegistryEntry(
        domain="protected_bundle_input",
        member_pattern="*",
        json_path_pattern=f"$..{key}",
        value_category=category,
        treatment=treatment,
        canonicaliser_id=canonicaliser_id,
        canonicaliser_version=canonicaliser_version,
        allowed_profiles=allowed_profiles,
        limitations=limitations,
    )


def _generated_key_entries() -> tuple[PrivacyRegistryEntry, ...]:
    sensitive_entries = tuple(
        _key_suffix_entry(
            key=key,
            category=category,
            treatment="derive_then_tokenise" if category == "arn" else "tokenise",
            canonicaliser_id=category.replace("_", "-"),
            canonicaliser_version="2026-03",
        )
        for key, category in sorted(FALLBACK_SENSITIVE_KEY_CATEGORIES.items())
    )
    prohibited_entries = tuple(
        _key_suffix_entry(
            key=key,
            category=category,
            treatment="prohibited",
            limitations=("Private recovery or vault material must never be exported.",),
        )
        for key, category in sorted(_PROHIBITED_KEY_CATEGORIES.items())
    )
    remove_entries = tuple(
        _key_suffix_entry(
            key=key,
            category=category,
            treatment="remove",
            limitations=("Local-only execution metadata is removed from protected exports.",),
        )
        for key, category in sorted(_REMOVED_KEY_CATEGORIES.items())
    )
    strict_remove_entries = tuple(
        _key_suffix_entry(
            key=key,
            category="cost",
            treatment="remove",
            allowed_profiles=("strict",),
            limitations=("Strict profile removes or nulls cost precision.",),
        )
        for key in sorted(_STRICT_REMOVE_KEYS)
    )
    strict_generalise_entries = tuple(
        _key_suffix_entry(
            key=key,
            category=category,
            treatment="generalise",
            allowed_profiles=("strict",),
            limitations=("Strict profile generalises this field.",),
        )
        for key, category in sorted(_STRICT_GENERALISE_KEYS.items())
    )
    strict_topology_entries = tuple(
        _key_suffix_entry(
            key=key,
            category="topology",
            treatment="generalise",
            allowed_profiles=("strict",),
            limitations=("Strict profile reduces detailed topology.",),
        )
        for key in sorted(_STRICT_TOPOLOGY_KEYS)
    )
    profile_configurable_entries = tuple(
        _key_suffix_entry(
            key=key,
            category=category,
            treatment="profile_configurable",
        )
        for key, category in sorted(
            {
                **dict.fromkeys(_STRICT_REMOVE_KEYS, "cost"),
                **_STRICT_GENERALISE_KEYS,
                **dict.fromkeys(_STRICT_TOPOLOGY_KEYS, "topology"),
            }.items(),
        )
    )
    text_entries = tuple(
        _key_suffix_entry(
            key=key,
            category="free_text",
            treatment="profile_configurable",
            limitations=("Free text is scanned structurally for embedded sensitive values.",),
        )
        for key in sorted(FALLBACK_TEXT_KEYS)
    )
    configured_keys = {
        *FALLBACK_SENSITIVE_KEY_CATEGORIES,
        *FALLBACK_TEXT_KEYS,
        *_REMOVED_KEY_CATEGORIES,
        *_PROHIBITED_KEY_CATEGORIES,
        *_STRICT_REMOVE_KEYS,
        *_STRICT_GENERALISE_KEYS,
        *_STRICT_TOPOLOGY_KEYS,
    }
    safe_entries = tuple(
        _key_suffix_entry(
            key=key,
            category="safe_metadata",
            treatment="preserve",
        )
        for key in sorted(FALLBACK_SAFE_STRING_KEYS - configured_keys)
    )
    return (
        *prohibited_entries,
        *remove_entries,
        *strict_remove_entries,
        *strict_generalise_entries,
        *strict_topology_entries,
        *profile_configurable_entries,
        *sensitive_entries,
        *text_entries,
        *safe_entries,
    )


PATH_REGISTRY: tuple[PrivacyRegistryEntry, ...] = (
    *_BASE_PATH_REGISTRY,
    *_generated_key_entries(),
)


@dataclass
class ClassificationSummary:
    """Privacy classification counters and coverage errors."""

    tokenised: dict[str, int] = field(default_factory=dict)
    preserved: int = 0
    removed: int = 0
    unclassified: list[str] = field(default_factory=list)
    prohibited_paths: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    cost_values_removed: int = 0
    timestamps_generalised: int = 0
    regions_generalised: int = 0
    topology_values_reduced: int = 0
    tag_values_tokenised: int = 0
    text_values_tokenised: int = 0
    log_values_removed: int = 0
    registry_decisions_used: int = 0
    fallback_decisions_used: int = 0
    prohibited_decisions: int = 0
    unsupported_decisions: int = 0

    def record_token(self, category: str) -> None:
        """Record one tokenised category."""
        self.tokenised[category] = self.tokenised.get(category, 0) + 1

    def record_prohibited_path(self, path: str) -> None:
        """Record one prohibited privacy-registry path without storing values."""
        self.prohibited_decisions += 1
        self.prohibited_paths.append(path)

    def record_resolver_decision(self, decision_source: str) -> None:
        """Record one non-secret aggregate registry decision source."""
        if decision_source == "fallback_allowed":
            self.fallback_decisions_used += 1
        elif decision_source == "unsupported":
            self.unsupported_decisions += 1
        else:
            self.registry_decisions_used += 1

    def convert_to_dict(self) -> dict[str, object]:
        """Return JSON-safe summary."""
        return {
            "tokenised": dict(sorted(self.tokenised.items())),
            "preserved": self.preserved,
            "removed": self.removed,
            "unclassified": list(self.unclassified),
            "prohibited_paths": list(self.prohibited_paths),
            "warnings": list(self.warnings),
            "applied_transformations": self.applied_transformations(),
            "resolver_decisions": self.resolver_decisions(),
        }

    def applied_transformations(self) -> dict[str, int]:
        """Return counters for profile-enforced privacy transformations."""
        return {
            "cost_values_removed": self.cost_values_removed,
            "timestamps_generalised": self.timestamps_generalised,
            "regions_generalised": self.regions_generalised,
            "topology_values_reduced": self.topology_values_reduced,
            "tag_values_tokenised": self.tag_values_tokenised,
            "text_values_tokenised": self.text_values_tokenised,
            "log_values_removed": self.log_values_removed,
        }

    def resolver_decisions(self) -> dict[str, int]:
        """Return aggregate registry resolver counters."""
        return {
            "registry_decisions_used": self.registry_decisions_used,
            "fallback_decisions_used": self.fallback_decisions_used,
            "prohibited_decisions": self.prohibited_decisions,
            "unsupported_decisions": self.unsupported_decisions,
        }


def is_supported_json_path(name: str) -> bool:
    """Return true when the v1 registry intentionally covers a JSON member."""
    return name in SUPPORTED_JSON_FILES or (name.startswith(SUPPORTED_JSON_PREFIXES) and name.endswith(".json") and not name.startswith("privacy/"))


def registry_entries_for_domain(domain: str) -> tuple[PrivacyRegistryEntry, ...]:
    """Return registry entries for one path domain."""
    return tuple(entry for entry in PATH_REGISTRY if entry.domain == domain)


def registry_contract() -> list[dict[str, object]]:
    """Return the machine-readable privacy registry contract."""
    return [entry.convert_to_dict() for entry in PATH_REGISTRY]
