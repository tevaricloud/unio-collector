from __future__ import annotations  # noqa: D100

# ruff: noqa: C901
from typing import TYPE_CHECKING, Any, cast

from unio_collector.environment import EnvironmentClassifier
from unio_collector.privacy.environment.record import (
    apply_environment_context,
    remove_internal_ledger_diagnostics,
)
from unio_collector.privacy.environment.record import display_path as render_display_path
from unio_collector.privacy.generalisation import PrivacyValueGeneraliser
from unio_collector.privacy.patterns import (
    TIMESTAMP_RE,
    is_safe_literal,
)
from unio_collector.privacy.producer_fields import producer_category, unknown_producer_paths
from unio_collector.privacy.region_scope import REGION_SCOPE_MEMBERS, region_scope_category
from unio_collector.privacy.registry import (
    FALLBACK_SAFE_STRING_KEYS,
    FALLBACK_SENSITIVE_KEY_CATEGORIES,
    FALLBACK_TEXT_KEYS,
    ClassificationSummary,
)
from unio_collector.privacy.resolver import PrivacyRegistryResolver
from unio_collector.privacy.rules import (
    is_strict_cost_key,
    is_strict_log_key,
    is_strict_region_key,
    is_strict_timestamp_key,
    is_strict_topology_key,
)
from unio_collector.privacy.selection import select_producer_contract
from unio_collector.privacy.token.transformer import PrivacyValueTokens
from unio_collector.privacy.tokens import is_protected_token

if TYPE_CHECKING:
    from unio_collector.privacy.closed_schema import ClosedProducerContract
    from unio_collector.privacy.profiles import PrivacyProfile
    from unio_collector.privacy.tokens import TokenService
    from unio_collector.privacy.treatment_decision import PrivacyTreatmentDecision


class PrivacyTransformer:
    """Structured JSON privacy transformer for protected evidence bundles."""

    def __init__(
        self,
        *,
        token_service: TokenService,
        profile: PrivacyProfile,
        allow_unknown_fields: bool,
        summary: ClassificationSummary | None = None,
        registry_resolver: PrivacyRegistryResolver | None = None,
        environment_classifier: EnvironmentClassifier | None = None,
        environment_semantics: str = "detailed",
    ) -> None:
        """Create a transformer with one token service and registry policy."""
        self._profile = profile
        self._allow_unknown_fields = allow_unknown_fields
        self.summary = summary or ClassificationSummary()
        self._value_tokens = PrivacyValueTokens(token_service, self.summary)
        self._generaliser = PrivacyValueGeneraliser(self.summary)
        self._registry_resolver = registry_resolver or PrivacyRegistryResolver()
        self._environment_classifier = environment_classifier or EnvironmentClassifier()
        self._environment_semantics = environment_semantics
        self._producer_contract: ClosedProducerContract | None = None

    def transform(self, value: Any, *, file_name: str) -> Any:  # noqa: ANN401
        """Transform one JSON-compatible value."""
        if not self._allow_unknown_fields:
            self.summary.unclassified.extend(unknown_producer_paths(value, file_name))
        return self._transform_value(value, member_path=file_name, json_path="$", key=None, in_tags=False)

    def _transform_value(
        self,
        value: Any,  # noqa: ANN401
        *,
        member_path: str,
        json_path: str,
        key: str | None,
        in_tags: bool,
    ) -> Any:  # noqa: ANN401
        scope_category = region_scope_category(json_path) if member_path in REGION_SCOPE_MEMBERS else None
        if member_path in REGION_SCOPE_MEMBERS and json_path.startswith("$.region_scope") and scope_category is None:
            self._blocked_or_unknown(
                self._resolve_decision(member_path=member_path, json_path=json_path, key=key),
                display_path=render_display_path(member_path, json_path),
                value=value,
            )
            return value
        if producer_category(member_path, json_path) in {"diagnostic_counts", "diagnostic_groups"} and isinstance(value, dict):
            self.summary.removed += len(value)
            return {}
        if scope_category is None and is_strict_cost_key(self._profile, key) and isinstance(value, dict | list):
            self.summary.cost_values_removed += 1
            self.summary.removed += 1
            return None
        if is_strict_topology_key(self._profile, key) and isinstance(value, dict):
            self.summary.topology_values_reduced += len(value)
            self.summary.removed += len(value)
            return {}
        if is_strict_log_key(self._profile, member_path, key) and isinstance(value, dict | list):
            self.summary.log_values_removed += len(value)
            self.summary.removed += len(value)
            return {} if isinstance(value, dict) else []
        if isinstance(value, dict):
            return self._transform_dict(
                value,
                member_path=member_path,
                json_path=json_path,
                in_tags=in_tags,
            )
        if isinstance(value, list):
            if is_strict_topology_key(self._profile, key):
                self.summary.topology_values_reduced += len(value)
                self.summary.removed += len(value)
                return []
            if is_strict_region_key(self._profile, key):
                self.summary.regions_generalised += len(value)
                self.summary.preserved += 1
                return ["aws-region"] if value else []
            return [
                self._transform_value(
                    item,
                    member_path=member_path,
                    json_path=f"{json_path}[]",
                    key=key,
                    in_tags=in_tags,
                )
                for item in value
            ]
        if isinstance(value, str):
            return self._transform_string(
                value,
                member_path=member_path,
                json_path=json_path,
                key=key,
                in_tags=in_tags,
            )
        if not isinstance(value, dict | list):
            decision = self._resolve_decision(
                member_path=member_path,
                json_path=json_path,
                key=key,
            )
            blocked = self._blocked_or_unknown(
                decision,
                display_path=render_display_path(member_path, json_path),
                value=value,
            )
            if blocked is not None:
                return blocked
            if decision.treatment == "remove":
                if decision.category == "cost":
                    self.summary.cost_values_removed += 1
                self.summary.removed += 1
                return None
            if decision.category != "summary_count" and scope_category is None and is_strict_cost_key(self._profile, key) and isinstance(value, int | float):
                self.summary.cost_values_removed += 1
                self.summary.removed += 1
                return None
            if is_strict_topology_key(self._profile, key) and value is not None:
                self.summary.topology_values_reduced += 1
                self.summary.removed += 1
                return None
            if is_strict_timestamp_key(self._profile, key) and value is not None:
                self.summary.unclassified.append(render_display_path(member_path, json_path))
                return value
        self.summary.preserved += 1
        return value

    def _transform_dict(
        self,
        value: dict[str, Any],
        *,
        member_path: str,
        json_path: str,
        in_tags: bool,
    ) -> dict[str, Any]:
        if member_path == "scan-result/scanner-evidence.json" and json_path == "$.scanner_evidence[]" and self._producer_contract is None:
            contract = select_producer_contract(value)
            if contract is not None:
                if not self._allow_unknown_fields:
                    self.summary.unclassified.extend(contract.unknown_record_paths(value, member_path))
                self._producer_contract = contract
                try:
                    return self._transform_dict(value, member_path=member_path, json_path=json_path, in_tags=in_tags)
                finally:
                    self._producer_contract = None
        key_category = self._producer_contract.mapping_key_category(json_path) if self._producer_contract is not None else None
        if key_category is not None:
            return {
                (
                    self._transform_tag_key(str(key)) if key_category == "tag_key" else self._value_tokens.tokenise(key_category, str(key))
                ): self._transform_value(child, member_path=member_path, json_path=f"{json_path}.{key}", key=str(key), in_tags=False)
                for key, child in value.items()
            }
        if json_path.endswith((".tags", ".target_tags", ".current_tags")):
            return {
                self._transform_tag_key(str(key)): self._transform_value(
                    child,
                    member_path=member_path,
                    json_path=f"{json_path}.{key}",
                    key=str(key),
                    in_tags=True,
                )
                for key, child in value.items()
            }
        if self._is_tag_record(json_path, value):
            return {
                key: self._transform_tag_record_value(
                    key,
                    child,
                    member_path=member_path,
                    json_path=f"{json_path}.{key}",
                )
                for key, child in value.items()
            }
        if member_path == "collection-log.jsonl":
            value = remove_internal_ledger_diagnostics(value)
        if member_path == "permissions/degradation-records.json":
            value = dict(value)
            value.pop("technical_detail", None)
        scanner_reference = value.get("source_scanner_id") or value.get("scanner_id")
        transformed = {
            key: (
                self._preserve_string(child)
                if key == "raw_reference_id" and scanner_reference is not None and child == scanner_reference
                else self._transform_value(
                    child,
                    member_path=member_path,
                    json_path=f"{json_path}.{key}",
                    key=str(key),
                    in_tags=in_tags,
                )
            )
            for key, child in value.items()
            if key != "environment_context"
        }
        return apply_environment_context(
            value,
            transformed,
            classifier=self._environment_classifier,
            semantics=self._environment_semantics,
            summary=self.summary,
        )

    def _is_tag_record(self, json_path: str, value: dict[str, Any]) -> bool:
        declared = self._producer_contract is not None and self._producer_contract.is_tag_record(json_path)
        return (declared or json_path.endswith((".tags[]", ".target_tags[]", ".current_tags[]"))) and (
            "Key" in value or "key" in value or "Value" in value or "value" in value
        )

    def _transform_tag_record_value(
        self,
        key: str,
        value: Any,  # noqa: ANN401
        *,
        member_path: str,
        json_path: str,
    ) -> Any:  # noqa: ANN401
        lowered = key.lower()
        if lowered == "key" and isinstance(value, str):
            return self._transform_tag_key(value)
        if lowered == "value" and isinstance(value, str):
            self.summary.tag_values_tokenised += 1
            return self._value_tokens.tokenise("tag_value", value)
        return self._transform_value(
            value,
            member_path=member_path,
            json_path=json_path,
            key=key,
            in_tags=False,
        )

    def _transform_tag_key(self, key: str) -> str:
        lowered = key.lower()
        if self._profile.profile_id == "strict" or any(
            part in lowered
            for part in (
                "owner",
                "email",
                "user",
                "project",
                "customer",
                "client",
                "costcenter",
                "costcentre",
            )
        ):
            self.summary.tag_values_tokenised += 1
            return self._value_tokens.tokenise("tag_key", key)
        self.summary.preserved += 1
        return key

    def _transform_string(
        self,
        value: str,
        *,
        member_path: str,
        json_path: str,
        key: str | None,
        in_tags: bool,
    ) -> str:
        decision = self._resolve_decision(
            member_path=member_path,
            json_path=json_path,
            key=key,
            string_value=value,
        )
        display_path = render_display_path(member_path, json_path)
        key_lower = (key or "").lower()
        blocked = self._blocked_or_unknown(
            decision,
            display_path=display_path,
            value=value,
        )
        if blocked is not None:
            return cast("str", blocked)
        if is_protected_token(value):
            self.summary.preserved += 1
            return value
        if not (member_path in REGION_SCOPE_MEMBERS and region_scope_category(json_path) is not None) and is_strict_cost_key(self._profile, key):
            self.summary.cost_values_removed += 1
            self.summary.removed += 1
            return ""
        if is_strict_timestamp_key(self._profile, key):
            if value == "" and self._producer_contract is not None and decision.category == "timestamp":
                self.summary.preserved += 1
                return ""
            if TIMESTAMP_RE.match(value):
                self.summary.timestamps_generalised += 1
                self.summary.preserved += 1
                return value[:7]
            self.summary.unclassified.append(display_path)
            return value
        if is_strict_region_key(self._profile, key):
            self.summary.regions_generalised += 1
            self.summary.preserved += 1
            return "aws-region"
        if is_strict_topology_key(self._profile, key):
            self.summary.topology_values_reduced += 1
            self.summary.removed += 1
            return ""
        if is_strict_log_key(self._profile, member_path, key):
            self.summary.log_values_removed += 1
            self.summary.removed += 1
            return ""
        if decision.treatment == "remove":
            self.summary.removed += 1
            return ""
        if decision.treatment == "generalise":
            return self._generaliser.generalise(value, decision.category)
        if in_tags:
            self.summary.tag_values_tokenised += 1
            return self._value_tokens.tokenise("tag_value", value)
        if decision.treatment in {"tokenise", "derive_then_tokenise"} and decision.category is not None:
            return self._value_tokens.sensitive_string(value, decision.category)
        if decision.category == "free_text":
            self.summary.text_values_tokenised += 1
            return self._value_tokens.embedded_values(value)
        if decision.treatment == "profile_configurable" and decision.category in {
            "cost",
            "region",
            "safe_metadata",
            "timestamp",
            "topology",
        }:
            self.summary.preserved += 1
            return value
        if decision.treatment == "preserve" or is_safe_literal(value):
            self.summary.preserved += 1
            return value
        if decision.fallback_allowed:
            return self._transform_string_with_fallback(
                value,
                display_path=display_path,
                key_lower=key_lower,
                in_tags=in_tags,
            )
        self.summary.unsupported_decisions += 1
        if self._allow_unknown_fields:
            self.summary.warnings.append(
                f"Preserved unclassified field by custom profile: {display_path}",
            )
            self.summary.preserved += 1
            return value
        self.summary.unclassified.append(display_path)
        return value

    def _transform_string_with_fallback(
        self,
        value: str,
        *,
        display_path: str,
        key_lower: str,
        in_tags: bool,
    ) -> str:
        category = FALLBACK_SENSITIVE_KEY_CATEGORIES.get(key_lower)
        if in_tags:
            self.summary.tag_values_tokenised += 1
            return self._value_tokens.tokenise("tag_value", value)
        if category is not None:
            return self._value_tokens.sensitive_string(value, category)
        if key_lower in FALLBACK_TEXT_KEYS:
            self.summary.text_values_tokenised += 1
            return self._value_tokens.embedded_values(value)
        if key_lower in FALLBACK_SAFE_STRING_KEYS or is_safe_literal(value):
            self.summary.preserved += 1
            return value
        transformed = self._value_tokens.embedded_values(value)
        if transformed != value:
            return transformed
        if self._allow_unknown_fields:
            self.summary.warnings.append(
                f"Preserved unclassified field by custom profile: {display_path}",
            )
            self.summary.preserved += 1
            return value
        self.summary.unclassified.append(display_path)
        return value

    def _resolve_decision(self, *, member_path: str, json_path: str, key: str | None, string_value: str | None = None) -> PrivacyTreatmentDecision:
        scoped = None
        if self._producer_contract is not None:
            scoped = (
                self._producer_contract.resolve_string(json_path, string_value, self._profile.profile_id)
                if string_value is not None
                else self._producer_contract.resolve(json_path, self._profile.profile_id)
            )
        decision = scoped or self._registry_resolver.resolve(
            domain="protected_bundle_input",
            member_path=member_path,
            json_path=json_path,
            key=key,
            profile_id=self._profile.profile_id,
        )
        if decision.decision_source == "unsupported":
            self.summary.unsupported_decisions += 1
        else:
            self.summary.record_resolver_decision(decision.decision_source)
        return decision

    def _blocked_or_unknown(self, decision: PrivacyTreatmentDecision, *, display_path: str, value: object) -> object | None:
        if decision.treatment == "prohibited":
            self.summary.record_prohibited_path(display_path)
            return value
        if decision.treatment != "unsupported":
            return None
        if self._allow_unknown_fields:
            self.summary.warnings.append(
                f"Preserved unclassified field by custom profile: {display_path}; privacy coverage is weakened.",
            )
            self.summary.preserved += 1
            return value
        self.summary.unclassified.append(display_path)
        return value

    def _preserve_string(self, value: Any) -> Any:  # noqa: ANN401
        if isinstance(value, str):
            self.summary.preserved += 1
        return value
