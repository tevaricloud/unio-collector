"""Exact typed protocol fields in the known-original scan view."""

from __future__ import annotations

import math
from uuid import UUID

from unio_collector.collector.protocol import UNIO_PROTOCOL
from unio_collector.privacy.leak.public.lifecycle import ProtocolLifecycleScanContract
from unio_collector.privacy.leak.public.region import public_region
from unio_collector.privacy.leak.public.result import ResultMetadataScanContract
from unio_collector.privacy.leak.public.temporal import TemporalScanPolicy
from unio_collector.privacy.leak.public.transport import TransportErrorScanContract
from unio_collector.privacy.producer_fields import producer_category, unknown_producer_paths
from unio_collector.privacy.region_scope import REGION_SCOPE_MEMBERS, region_scope_category
from unio_collector.privacy.resolver import PrivacyRegistryResolver

_GENERATED_UUID_VERSION = 4
_COLLECTION = frozenset({"complete", "partial", "failed", "cancelled"})
_SCANNER = frozenset({"completed", "completed_with_warnings", "failed", "disabled", "skipped", "unavailable", "cancelled", "timed_out"})
_VALUES = {
    ("account-scope.json", "$.region_scope.discovery_status"): frozenset({"completed"}),
    ("manifest.json", "$.region_scope.discovery_status"): frozenset({"completed"}),
    ("collection-summary.json", "$.region_scope.discovery_status"): frozenset({"completed"}),
    **{(name, "$.collection_status"): _COLLECTION for name in ("collection-summary.json", "manifest.json")},
    ("collection-summary.json", "$.collection_runtime_summary.slowest_tasks[].status"): _SCANNER,
    ("permissions-summary.json", "$.scanner_permissions[].scanner_status"): _SCANNER,
    **{
        (name, prefix + "." + field): values
        for name, prefix in (
            ("analysis-readiness.json", "$.scanner_evidence_coverage"),
            ("collection-summary.json", "$.strict_analysis_readiness.scanner_evidence_coverage"),
            ("scan-result/report-bundle.json", "$.summary.scanner_evidence_coverage"),
        )
        for field, values in (("collection_status", _COLLECTION), ("status", frozenset({"complete", "incomplete"})))
    },
    ("scan-result/report-bundle.json", "$.summary.collection_status"): _COLLECTION,
}
_REFERENCES = {
    ("analysis-readiness.json", "$.pricing_replay.context_file"): "scan-result/pricing-context.json",
    ("analysis-readiness.json", "$.scanner_evidence_payload_file"): "scan-result/scanner-evidence.json",
    ("collection-summary.json", "$.strict_analysis_readiness.pricing_replay.context_file"): "scan-result/pricing-context.json",
    ("collection-summary.json", "$.strict_analysis_readiness.scanner_evidence_payload_file"): "scan-result/scanner-evidence.json",
    ("signature.json", "$.signed_payload"): "checksums.json",
}
_OBSERVED = {
    ("permissions-summary.json", "$.assessment_method"): frozenset(
        f"observed_{namespace}_api_calls" for namespace in (UNIO_PROTOCOL.namespace, *UNIO_PROTOCOL.accepted_import_namespaces)
    ),
    **{
        (member, prefix + ".evidence_interpretation"): frozenset({"observed_absent"})
        for member, prefix in (
            ("manifest.json", "$.permission_limitations[]"),
            ("permissions-summary.json", "$.permission_degradation.degradation_details[]"),
            ("permissions-summary.json", "$.permission_degradation.stable_limitation_details[]"),
            ("permissions/degradation-records.json", "$.records[]"),
        )
    },
}


_OBSERVED.update(
    {
        (member, prefix + "." + field): frozenset({"unknown"}) | _OBSERVED.get((member, prefix + "." + field), frozenset())
        for member, prefix in (
            ("manifest.json", "$.permission_limitations[]"),
            ("permissions-summary.json", "$.permission_degradation.degradation_details[]"),
            ("permissions-summary.json", "$.permission_degradation.stable_limitation_details[]"),
            ("permissions/degradation-records.json", "$.records[]"),
        )
        for field in ("outcome", "evidence_interpretation", "confidence_effect")
    }
)
_OBSERVED[("permissions/degradation-records.json", "$.records[].error_classification")] = frozenset({"unknown"})

_KEYS = {
    **{(member, "$.profile.preserve_unknown_fields"): bool for member in ("privacy/protection-policy.json", "privacy/preview-summary.json")},
    ("analysis-contract.json", "$.contains_completed_report_bundle"): bool,
    ("scan-result/pricing-context.json", "$.stopped_lookup_request_count"): int,
    ("scan-result/pricing-context.json", "$.completed_api_call_count"): int,
    ("scan-result/pricing-context.json", "$.completed_lookup_request_count"): int,
}


class ProtocolScanContract:
    """Mask only declared field names and their separately enumerated literals.

    This never changes archive bytes or admission. Every child value remains
    scanned unless its exact field has a finite public vocabulary. Unknown
    paths, wrong types, dynamic keys and customer text remain visible.
    """

    def __init__(self, generated_tokens: frozenset[str] = frozenset()) -> None:
        """Bind the actual generated token inventory, never token-looking text."""
        self._generated_tokens = generated_tokens

    def mask(self, member: str, value: object, path: str = "$") -> object:
        """Retain customer values while distinguishing exact typed protocol positions."""
        if path == "$" and member in {name for name, _ in _REFERENCES} and not self._reference_root(member, value):
            return value
        policy = TemporalScanPolicy.create(member, value, self._generated_tokens)
        return self._mask(member, value, path, policy)

    @staticmethod
    def _reference_root(member: str, value: object) -> bool:
        """Require declared root fields and existing nested producer guards before reference views."""
        if not isinstance(value, dict):
            return False
        checked = value
        if member == "collection-summary.json" and value.get("privacy_profile_id") == "strict" and value.get("privacy_protection_enabled") is True:
            checked = {
                key: child for key, child in value.items() if not (key in {"billing_region_coverage", "billing_region_scope_derivation"} and child is None)
            }
        if unknown_producer_paths(checked, member):
            return False
        resolver = PrivacyRegistryResolver()
        return all(
            isinstance(key, str)
            and not any(character in key for character in ".[]")
            and (
                resolver.resolve(domain="protected_bundle_input", member_path=member, json_path="$." + key, key=key, profile_id="standard").treatment
                != "unsupported"
                or ProtocolScanContract._generated_reference_metadata(key, value[key])
                or (
                    (member, key) in {("analysis-readiness.json", "scanner_evidence_coverage"), ("collection-summary.json", "strict_analysis_readiness")}
                    and isinstance(value[key], dict)
                )
            )
            for key in value
        )

    @staticmethod
    def _generated_reference_metadata(key: str, value: object) -> bool:
        """Admit only typed metadata appended by protection; every value remains scanned."""
        if key == "privacy_profile_id":
            return isinstance(value, str) and value in {"standard", "strict", "custom"}
        if key == "privacy_protection_enabled":
            return value is True
        if key == "protected_llm_policy":
            return value == "llm_disabled_in_v1"
        if key == "privacy_limitations":
            return isinstance(value, list) and all(
                item
                == {
                    "type": "privacy_policy_cost_precision_reduced",
                    "reason": "Strict privacy profile reduced cost precision; financial conclusions are limited.",
                }
                for item in value
            )
        if key == "protected_bundle_id" and isinstance(value, str):
            try:
                identity = UUID(value)
            except ValueError:
                return False
            return identity.version == _GENERATED_UUID_VERSION and str(identity) == value
        return False

    def _mask(self, member: str, value: object, path: str, policy: TemporalScanPolicy) -> object:
        observed = policy.root_owned and policy.row_owned and isinstance(value, str) and value in _OBSERVED.get((member, path), ())
        reference = isinstance(value, str) and value == _REFERENCES.get((member, path))
        if reference or observed or policy.is_value(path, value):
            return ""
        if member in REGION_SCOPE_MEMBERS and region_scope_category(path) == "region" and public_region(value):
            return ""
        if ProtocolLifecycleScanContract.public_value(member, path, value):
            return ""
        vocabulary = _VALUES.get((member, path))
        if vocabulary is not None and isinstance(value, str) and value in vocabulary:
            return ""
        if member == "scan-result/scanner-results.json" and path == "$.scanner_results[]" and isinstance(value, dict):
            return ResultMetadataScanContract.mask(value)
        if isinstance(value, list):
            return [self._mask(member, child, path + "[]", policy) for child in value]
        if not isinstance(value, dict):
            return value
        if TransportErrorScanContract.reject_root(member, value, path):
            return value
        policy = policy.for_container(path, value)
        value = TransportErrorScanContract.view(member, value, path, self._generated_tokens)
        value = ProtocolLifecycleScanContract.ledger_view(member, path, value, self._generated_tokens)
        pairs = []
        for key, child in value.items():
            child_path = path + "." + key
            declared = not any(c in key for c in ".[]") and self._declared(member, child_path, child)
            pairs.append(["" if declared else key, self._mask(member, child, child_path, policy) if not any(c in key for c in ".[]") else child])
        return pairs

    @staticmethod
    def _declared(member: str, path: str, child: object) -> bool:
        if (member, path) == ("scan-result/pricing-context.json", "$.observed_pages_per_lookup"):
            return child is None or (type(child) is int and child >= 0) or (isinstance(child, float) and math.isfinite(child) and child >= 0)
        if ProtocolLifecycleScanContract.public_key(member, path, child):
            return True
        kind = _KEYS.get((member, path))
        if kind is not None:
            return type(child) is kind and (kind is not int or (isinstance(child, int) and child >= 0))
        if producer_category(member, path) is not None:
            return not unknown_producer_paths(child, member, path)
        return False
