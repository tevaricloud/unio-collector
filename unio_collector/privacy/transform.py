from __future__ import annotations  # noqa: D100

# ruff: noqa: C901
import ipaddress
from typing import TYPE_CHECKING, Any, cast

from unio_collector.privacy.canonicalization import canonicalize_value
from unio_collector.privacy.patterns import (
    ACCOUNT_RE,
    ARN_PART_COUNT,
    ARN_RE,
    CIDR_RE,
    DNS_RE,
    EMAIL_RE,
    IP_RE,
    IPV4_VERSION,
    RESOURCE_RE,
    TIMESTAMP_RE,
)
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
from unio_collector.privacy.tokens import TokenService, is_protected_token

if TYPE_CHECKING:
    from unio_collector.privacy.profiles import PrivacyProfile
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
    ) -> None:
        """Create a transformer with one token service and registry policy."""
        self._token_service = token_service
        self._profile = profile
        self._allow_unknown_fields = allow_unknown_fields
        self.summary = summary or ClassificationSummary()
        self._registry_resolver = registry_resolver or PrivacyRegistryResolver()

    def transform(self, value: Any, *, file_name: str) -> Any:  # noqa: ANN401
        """Transform one JSON-compatible value."""
        return self._transform_value(
            value,
            member_path=file_name,
            json_path="$",
            key=None,
            in_tags=False,
        )

    def _transform_value(
        self,
        value: Any,  # noqa: ANN401
        *,
        member_path: str,
        json_path: str,
        key: str | None,
        in_tags: bool,
    ) -> Any:  # noqa: ANN401
        if is_strict_cost_key(self._profile, key) and isinstance(value, dict | list):
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
                display_path=self._display_path(member_path, json_path),
                value=value,
            )
            if blocked is not None:
                return blocked
            if is_strict_cost_key(self._profile, key) and isinstance(value, int | float):
                self.summary.cost_values_removed += 1
                self.summary.removed += 1
                return None
            if is_strict_timestamp_key(self._profile, key) and value is not None:
                self.summary.unclassified.append(self._display_path(member_path, json_path))
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
            value = self._remove_internal_ledger_diagnostics(value)
        if member_path == "permissions/degradation-records.json":
            value = dict(value)
            value.pop("technical_detail", None)
        scanner_reference = value.get("source_scanner_id") or value.get("scanner_id")
        return {
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
        }

    def _remove_internal_ledger_diagnostics(
        self,
        value: dict[str, Any],
    ) -> dict[str, Any]:
        sanitized = dict(value)
        sanitized.pop("errorMessage", None)
        sanitized.pop("requestParameters", None)
        response = sanitized.get("responseElements")
        if isinstance(response, dict) and "awsRequestId" in response:
            sanitized_response = dict(response)
            sanitized_response.pop("awsRequestId", None)
            sanitized["responseElements"] = sanitized_response
        return sanitized

    def _is_tag_record(self, json_path: str, value: dict[str, Any]) -> bool:
        return json_path.endswith((".tags[]", ".target_tags[]", ".current_tags[]")) and (
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
            return self._tokenise("tag_value", value)
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
            return self._tokenise("tag_key", key)
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
        )
        display_path = self._display_path(member_path, json_path)
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
        if is_strict_cost_key(self._profile, key):
            self.summary.cost_values_removed += 1
            self.summary.removed += 1
            return ""
        if is_strict_timestamp_key(self._profile, key):
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
            return self._generalise(value, decision.category)
        if in_tags:
            self.summary.tag_values_tokenised += 1
            return self._tokenise("tag_value", value)
        if decision.treatment in {"tokenise", "derive_then_tokenise"} and decision.category is not None:
            return self._transform_sensitive_string(value, decision.category)
        if decision.category == "free_text":
            self.summary.text_values_tokenised += 1
            return self._tokenise_embedded_values(value)
        if decision.treatment == "profile_configurable" and decision.category in {
            "cost",
            "region",
            "safe_metadata",
            "timestamp",
            "topology",
        }:
            self.summary.preserved += 1
            return value
        if decision.treatment == "preserve" or self._is_safe_literal(value):
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
            return self._tokenise("tag_value", value)
        if category is not None:
            return self._transform_sensitive_string(value, category)
        if key_lower in FALLBACK_TEXT_KEYS:
            self.summary.text_values_tokenised += 1
            return self._tokenise_embedded_values(value)
        if key_lower in FALLBACK_SAFE_STRING_KEYS or self._is_safe_literal(value):
            self.summary.preserved += 1
            return value
        transformed = self._tokenise_embedded_values(value)
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

    def _resolve_decision(
        self,
        *,
        member_path: str,
        json_path: str,
        key: str | None,
    ) -> PrivacyTreatmentDecision:
        decision = self._registry_resolver.resolve(
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

    def _blocked_or_unknown(
        self,
        decision: PrivacyTreatmentDecision,
        *,
        display_path: str,
        value: object,
    ) -> object | None:
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

    def _display_path(self, member_path: str, json_path: str) -> str:
        if json_path == "$":
            return member_path
        return f"{member_path}{json_path[1:]}"

    def _generalise(self, value: str, category: str | None) -> str:
        if category == "region":
            self.summary.regions_generalised += 1
            self.summary.preserved += 1
            return "aws-region"
        if category == "timestamp":
            if TIMESTAMP_RE.match(value):
                self.summary.timestamps_generalised += 1
                self.summary.preserved += 1
                return value[:7]
            self.summary.unclassified.append("timestamp")
            return value
        self.summary.preserved += 1
        return value

    def _transform_sensitive_string(self, value: str, category: str) -> str:
        if category == "arn":
            return self._tokenise_arn(value)
        if category == "cidr":
            return self._tokenise_cidr(value)
        if category in {"ipv4", "ipv6"}:
            return self._tokenise_ip(value)
        return self._tokenise(category, value)

    def _tokenise_embedded_values(self, value: str) -> str:
        result = CIDR_RE.sub(lambda match: self._tokenise_cidr(match.group(0)), value)
        result = ARN_RE.sub(lambda match: self._tokenise_arn(match.group(0)), result)
        result = EMAIL_RE.sub(lambda match: self._tokenise("email", match.group(0)), result)
        result = ACCOUNT_RE.sub(lambda match: self._tokenise("aws_account_id", match.group(0)), result)
        result = RESOURCE_RE.sub(lambda match: self._tokenise("resource_id", match.group(0)), result)
        result = IP_RE.sub(lambda match: self._tokenise_ip(match.group(0)), result)
        return DNS_RE.sub(lambda match: self._tokenise("dns_name", match.group(0)), result)

    def _tokenise_arn(self, value: str) -> str:
        parts = value.split(":", 5)
        if len(parts) != ARN_PART_COUNT or parts[0].lower() != "arn":
            return self._tokenise("arn", value)
        partition, service, region, account, resource = parts[1:]
        protected_account = self._tokenise("aws_account_id", account) if account else ""
        protected_resource = resource if service == "iam" and resource == "root" else self._tokenise("resource_id", resource) if resource else ""
        return f"arn:{partition}:{service}:{region}:{protected_account}:{protected_resource}"

    def _tokenise_ip(self, value: str) -> str:
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError:
            return self._tokenise("resource_id", value)
        return self._tokenise(
            "ipv4" if parsed.version == IPV4_VERSION else "ipv6",
            str(parsed),
        )

    def _tokenise_cidr(self, value: str) -> str:
        try:
            parsed = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return self._tokenise("resource_id", value)
        return self._tokenise("cidr", str(parsed))

    def _tokenise(self, category: str, value: object) -> str:
        canonical = canonicalize_value(category, value)
        token = self._token_service.token_for(canonical, observed_value=value)
        self.summary.record_token(canonical.category)
        return token

    def _is_safe_literal(self, value: str) -> bool:
        return not value.strip() or value.isdigit() or value in {"true", "false", "none", "null"}

    def _preserve_string(self, value: Any) -> Any:  # noqa: ANN401
        if isinstance(value, str):
            self.summary.preserved += 1
        return value
