from __future__ import annotations  # noqa: D100

# ruff: noqa: C901,PLR1714,PLR2004,TC001
import json
import re
from typing import TYPE_CHECKING, Any

from unio_collector.privacy.audit.selection import select_audit_note
from unio_collector.privacy.billing.contract import BillingPrivacyContract
from unio_collector.privacy.identity.contract import IdentityPrivacyContract
from unio_collector.privacy.patterns import TIMESTAMP_RE
from unio_collector.privacy.selection import select_producer_contract
from unio_collector.privacy.token.codec import TOKEN_PREFIXES

if TYPE_CHECKING:
    from unio_collector.privacy.closed_schema import ClosedProducerContract
from unio_collector.privacy.producer_fields import producer_category
from unio_collector.privacy.profiles import PrivacyProfile
from unio_collector.privacy.region_scope import REGION_SCOPE_MEMBERS, region_scope_category
from unio_collector.privacy.rules import (
    is_strict_cost_key,
    is_strict_log_key,
    is_strict_region_key,
    is_strict_timestamp_key,
    is_strict_topology_key,
)


class StrictTransformationVerifier:
    """Verify strict transformations against staged content, not metadata."""

    def verify(self, files: dict[str, bytes], profile: PrivacyProfile, *, generated_tokens: frozenset[str] = frozenset()) -> None:
        """Fail when strict-sensitive values remain in supported JSON members."""
        if profile.profile_id != "strict":
            return
        failures: list[str] = []
        for name, data in sorted(files.items()):
            if name.startswith("privacy/"):
                continue
            if name.endswith(".json"):
                payload = json.loads(data.decode("utf-8"))
                if name == "scan-result/pricing-context.json" and (payload.get("rates") or payload.get("usage_records")):
                    failures.append(name)
                self._walk(payload, profile, name, None, failures, generated_tokens=generated_tokens)
            elif name.endswith(".jsonl"):
                if name == "collection-log.jsonl" and data.strip():
                    failures.append(name)
                    continue
                for index, line in enumerate(data.decode("utf-8").splitlines()):
                    if line.strip():
                        self._walk(json.loads(line), profile, f"{name}[{index}]", None, failures, generated_tokens=generated_tokens)
        if failures:
            raise ValueError("Strict privacy transformation verification failed: " + "; ".join(failures[:20]))

    def _walk(
        self,
        value: Any,  # noqa: ANN401
        profile: PrivacyProfile,
        path: str,
        key: str | None,
        failures: list[str],
        contract: ClosedProducerContract | None = None,
        suffix: str = "",
        *,
        generated_tokens: frozenset[str] = frozenset(),
    ) -> None:
        member = path.split(".$", maxsplit=1)[0]
        if (
            contract is None
            and isinstance(value, dict)
            and member == "scan-result/scanner-results.json"
            and re.fullmatch(r"scan-result/scanner-results\.json\.\$scanner_results\[\d+\]\.\$coverage_notes\[\d+\]", path)
        ):
            contract = select_audit_note(value)
            suffix = ""
        if isinstance(contract, IdentityPrivacyContract) and suffix == "analyzer_inventory_status":
            if value != {}:
                failures.append(path)
            return
        if contract is not None and isinstance(value, list):
            selected = contract.for_sequence(value, contract.prefix + ("." + suffix if suffix else ""))
            if selected is not None:
                contract = selected
        spec = contract.fields.get(suffix) if contract is not None else None
        if spec is not None and spec[1] == "cost" and value not in (None, ""):
            failures.append(path)
            return
        if spec is not None and spec[0] == "boolean" and spec[1] == "safe_metadata":
            if not (type(value) is bool or (value is None and spec[2])):
                failures.append(path)
            return
        if spec is not None and spec[0] == "count" and spec[1] == "summary_count":
            if value is None and spec[2]:
                return
            if type(value) is not int or value < 0:
                failures.append(path)
            return
        producer_member, _, producer_relative = path.partition(".$")
        category = producer_category(producer_member, "$." + producer_relative.replace(".$", "."))
        if category == "summary_count":
            if type(value) is not int or value < 0:
                failures.append(path)
            return
        if category == "cost" and value not in (None, ""):
            failures.append(path)
            return
        member, _, relative = path.partition(".$region_scope")
        scope_category = region_scope_category("$.region_scope" + relative.replace(".$", ".")) if member in REGION_SCOPE_MEMBERS else None
        if scope_category == "region" and isinstance(value, str) and value != "aws-region":
            failures.append(path)
            return
        if scope_category is None and is_strict_cost_key(profile, key) and value is not None and value != "":
            failures.append(path)
            return
        if is_strict_region_key(profile, key) and value not in ("aws-region", None, ""):
            if value != [] and value != ["aws-region"]:
                failures.append(path)
            return
        if is_strict_topology_key(profile, key) and value is not None and value != "":
            if value != [] and value != {}:
                failures.append(path)
            return
        if is_strict_log_key(profile, path.split("$", 1)[0], key) and value is not None and value != "":
            if value != [] and value != {}:
                failures.append(path)
            return
        if is_strict_timestamp_key(profile, key):
            if value in (None, ""):
                return
            if not isinstance(value, str) or len(value) != 7 or not TIMESTAMP_RE.match(f"{value}-01"):
                failures.append(path)
            return
        if isinstance(value, str) and value.startswith("arn:"):
            parts = value.split(":", 5)
            if len(parts) == 6 and parts[3] not in {"", "aws-region"}:
                failures.append(path)
                return
        if isinstance(value, dict):
            for child_key, child in value.items():
                selected = contract
                relative = suffix + ("." if suffix else "") + child_key
                if contract is None and child_key == "payload" and producer_member == "scan-result/scanner-evidence.json":
                    selected = select_producer_contract(value)
                    relative = ""

                key_category = contract.mapping_key_category(contract.prefix + "." + suffix) if contract is not None else None
                typed_tags = (
                    contract is not None and spec is not None and spec[:2] == ("tag_map", "tag_value") and not contract.unknown_paths(value, member, suffix)
                )
                if typed_tags:
                    key_category = "tag_key"
                expected_prefix = TOKEN_PREFIXES.get(key_category or "")
                registered_key = expected_prefix is not None and child_key.startswith(expected_prefix + "-") and child_key in generated_tokens
                semantic_key = None if registered_key else str(child_key)
                if registered_key and isinstance(contract, BillingPrivacyContract):
                    found = contract.spec(suffix)
                    if found is not None and found[0].get("member") == "Spend":
                        relative = suffix + ".0"
                self._walk(child, profile, f"{path}.${child_key}", semantic_key, failures, selected, relative, generated_tokens=generated_tokens)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                relative = contract.sequence_item_path(suffix, index) if contract is not None else suffix + "[]"
                self._walk(child, profile, f"{path}[{index}]", key, failures, contract, relative, generated_tokens=generated_tokens)
