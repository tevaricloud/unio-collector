# noqa: D100
# pyright: reportAttributeAccessIssue=false
from __future__ import annotations

from typing import Any, TypeVar

AuditRecordT = TypeVar("AuditRecordT")


class AuditMetricHelperMixin:  # noqa: D101
    def _count_cloudtrail_status_errors(
        self,
        statuses: list[dict[str, Any]],
    ) -> int:
        error_keys = (
            "LatestDeliveryError",
            "LatestNotificationError",
            "LatestCloudWatchLogsDeliveryError",
        )
        return sum(1 for status in statuses if any(status.get(key) for key in error_keys))

    def _count_trails_with_management_events(
        self,
        event_selectors: list[dict[str, Any]],
    ) -> int:
        return len(
            self._get_management_event_trail_names(
                event_selectors,
                limit=None,
            ),
        )

    def _count_logging_trails_with_management_events(
        self,
        event_selectors: list[dict[str, Any]],
        statuses: list[dict[str, Any]],
    ) -> int:
        logging_trails = {
            str(
                status.get("__TrailName") or status.get("Name") or status.get("TrailName"),
            )
            for status in statuses
            if status.get("IsLogging") and (status.get("__TrailName") or status.get("Name") or status.get("TrailName"))
        }
        if not logging_trails:
            return 0
        management_trails = set(
            self._get_management_event_trail_names(
                event_selectors,
                limit=None,
            ),
        )
        return len(logging_trails & management_trails)

    def _get_management_event_trail_names(
        self,
        event_selectors: list[dict[str, Any]],
        *,
        limit: int | None = 10,
    ) -> list[str]:
        names: set[str] = set()
        for selectors in event_selectors:
            if self._count_management_event_selectors(selectors) <= 0:
                continue
            trail_name = selectors.get("__TrailName")
            if trail_name:
                names.add(str(trail_name))
        sorted_names = sorted(names)
        return sorted_names if limit is None else sorted_names[:limit]

    def _count_advanced_field_selectors(self, selectors: dict[str, Any]) -> int:
        advanced = selectors.get("AdvancedEventSelectors", [])
        if not isinstance(advanced, list):
            return 0
        count = 0
        for selector in advanced:
            if not isinstance(selector, dict):
                continue
            fields = selector.get("FieldSelectors", [])
            if isinstance(fields, list):
                count += len(fields)
        return count

    def _get_data_resource_types(  # noqa: C901
        self,
        event_selectors: list[dict[str, Any]],
    ) -> list[str]:
        resource_types: set[str] = set()
        for selectors in event_selectors:
            for selector in selectors.get("EventSelectors", []) or []:
                if not isinstance(selector, dict):
                    continue
                for resource in selector.get("DataResources", []) or []:
                    if isinstance(resource, dict) and resource.get("Type"):
                        resource_types.add(str(resource["Type"]))
            for selector in selectors.get("AdvancedEventSelectors", []) or []:
                if not isinstance(selector, dict):
                    continue
                for field_selector in selector.get("FieldSelectors", []) or []:
                    if not isinstance(field_selector, dict):
                        continue
                    if field_selector.get("Field") != "resources.type":
                        continue
                    for value in field_selector.get("Equals", []) or []:
                        resource_types.add(str(value))
        return sorted(resource_types)

    def _get_selector_read_write_types(
        self,
        event_selectors: list[dict[str, Any]],
    ) -> list[str]:
        read_write_types: set[str] = set()
        for selectors in event_selectors:
            for selector in selectors.get("EventSelectors", []) or []:
                if isinstance(selector, dict) and selector.get("ReadWriteType"):
                    read_write_types.add(str(selector["ReadWriteType"]))
        return sorted(read_write_types)

    def _get_advanced_selector_names(
        self,
        event_selectors: list[dict[str, Any]],
    ) -> list[str]:
        names: set[str] = set()
        for selectors in event_selectors:
            for selector in selectors.get("AdvancedEventSelectors", []) or []:
                if isinstance(selector, dict) and selector.get("Name"):
                    names.add(str(selector["Name"]))
        return sorted(names)

    def _get_sample_data_resource_values(
        self,
        event_selectors: list[dict[str, Any]],
        *,
        limit: int = 20,
    ) -> list[str]:
        values: list[str] = []
        for selectors in event_selectors:
            for selector in selectors.get("EventSelectors", []) or []:
                if not isinstance(selector, dict):
                    continue
                for resource in selector.get("DataResources", []) or []:
                    if not isinstance(resource, dict):
                        continue
                    resource_values = resource.get("Values", [])
                    if not isinstance(resource_values, list):
                        continue
                    values.extend(str(value) for value in resource_values[:limit])
        return sorted(dict.fromkeys(values))[:limit]

    def _get_max_event_data_store_retention_days(
        self,
        stores: list[dict[str, Any]],
    ) -> int | None:
        values = [self._get_event_data_store_retention_days(store) for store in stores]
        values = [value for value in values if value > 0]
        return max(values) if values else None

    def _get_event_data_store_retention_days(self, store: dict[str, Any]) -> int:
        value = store.get("RetentionPeriod")
        return value if isinstance(value, int) else 0

    def _count_event_data_store_advanced_selectors(
        self,
        stores: list[dict[str, Any]],
    ) -> int:
        return sum(len(store.get("AdvancedEventSelectors", []) or []) for store in stores if isinstance(store.get("AdvancedEventSelectors", []), list))

    def _get_sample_event_data_store_names(
        self,
        stores: list[dict[str, Any]],
    ) -> list[str]:
        names = [str(store.get("Name") or store.get("EventDataStoreArn")) for store in stores if store.get("Name") or store.get("EventDataStoreArn")]
        return sorted(dict.fromkeys(names))[:10]

    def _get_event_data_store_statuses(
        self,
        stores: list[dict[str, Any]],
    ) -> list[str]:
        statuses = [str(store.get("Status")) for store in stores if store.get("Status")]
        return sorted(dict.fromkeys(statuses))

    def _count_managed_rule_groups(self, rules: list[dict[str, Any]]) -> int:
        return sum(1 for rule in rules if rule.get("Statement", {}).get("ManagedRuleGroupStatement"))

    def _count_rate_based_rules(self, rules: list[dict[str, Any]]) -> int:
        return sum(1 for rule in rules if rule.get("Statement", {}).get("RateBasedStatement"))

    def _count_waf_action_rules(
        self,
        rules: list[dict[str, Any]],
        action_name: str,
    ) -> int:
        return sum(1 for rule in rules if self._get_waf_rule_action_name(rule) == action_name)

    def _get_waf_rule_action_name(self, rule: dict[str, Any]) -> str:
        action = rule.get("Action")
        if isinstance(action, dict) and action:
            return next(iter(action.keys())).upper()
        override_action = rule.get("OverrideAction")
        if isinstance(override_action, dict) and override_action:
            return next(iter(override_action.keys())).upper()
        return ""

    def _count_waf_default_actions(
        self,
        web_acl_details: list[dict[str, Any]],
        action_name: str,
    ) -> int:
        return sum(1 for detail in web_acl_details if self._get_waf_default_action_name(detail) == action_name)

    def _get_waf_default_action_name(self, web_acl: dict[str, Any]) -> str:
        action = web_acl.get("DefaultAction")
        if isinstance(action, dict) and action:
            return next(iter(action.keys())).upper()
        return ""

    def _get_waf_rule_action_types(self, rules: list[dict[str, Any]]) -> list[str]:
        action_types = {action for rule in rules if (action := self._get_waf_rule_action_name(rule))}
        return sorted(action_types)

    def _get_waf_rate_limits(self, rules: list[dict[str, Any]]) -> list[int]:
        limits: list[int] = []
        for rule in rules:
            statement = rule.get("Statement", {})
            if not isinstance(statement, dict):
                continue
            rate_statement = statement.get("RateBasedStatement")
            if not isinstance(rate_statement, dict):
                continue
            limit = self._get_int(rate_statement.get("Limit"))
            if limit > 0:
                limits.append(limit)
        return sorted(limits)[:20]

    def _get_int(self, value: Any) -> int:  # noqa: ANN401
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    def _get_managed_rule_group_names(
        self,
        rules: list[dict[str, Any]],
    ) -> list[str]:
        names: set[str] = set()
        for rule in rules:
            statement = rule.get("Statement", {})
            if not isinstance(statement, dict):
                continue
            managed = statement.get("ManagedRuleGroupStatement")
            if not isinstance(managed, dict):
                continue
            vendor = str(managed.get("VendorName") or "").strip()
            name = str(managed.get("Name") or "").strip()
            if vendor and name:
                names.add(f"{vendor}/{name}")
            elif name:
                names.add(name)
        return sorted(names)[:20]

    def _get_associated_resource_types(
        self,
        resource_arns: list[Any],
    ) -> set[str]:
        resource_types: set[str] = set()
        for value in resource_arns:
            arn = str(value or "")
            parts = arn.split(":")
            if len(parts) >= 3 and parts[2]:  # noqa: PLR2004
                resource_types.add(parts[2])
        return resource_types

    def _get_enabled_guardduty_features(
        self,
        detector_details: list[dict[str, Any]],
    ) -> list[str]:
        return self._get_guardduty_features_by_status(
            detector_details,
            status="ENABLED",
        )

    def _get_disabled_guardduty_features(
        self,
        detector_details: list[dict[str, Any]],
    ) -> list[str]:
        return self._get_guardduty_features_by_status(
            detector_details,
            status="DISABLED",
        )

    def _get_guardduty_features_by_status(
        self,
        detector_details: list[dict[str, Any]],
        *,
        status: str,
    ) -> list[str]:
        feature_names: list[str] = []
        for feature in self._iter_guardduty_features(detector_details):
            if str(feature.get("Status") or "").upper() != status:
                continue
            name = feature.get("Name")
            if name:
                feature_names.append(str(name))
        return sorted(set(feature_names))

    def _get_guardduty_feature_status_counts(
        self,
        detector_details: list[dict[str, Any]],
    ) -> dict[str, int]:
        counts: dict[str, int] = {}
        for feature in self._iter_guardduty_features(detector_details):
            status = str(feature.get("Status") or "UNKNOWN").upper()
            counts[status] = counts.get(status, 0) + 1
        return dict(sorted(counts.items()))

    def _iter_guardduty_features(
        self,
        detector_details: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        features: list[dict[str, Any]] = []
        for detail in detector_details:
            raw_features = detail.get("Features", [])
            if not isinstance(raw_features, list):
                continue
            features.extend(feature for feature in raw_features if isinstance(feature, dict))
        return features

    def _get_guardduty_detector_status_values(
        self,
        detector_details: list[dict[str, Any]],
    ) -> list[str]:
        return sorted(
            {str(detail.get("Status")) for detail in detector_details if detail.get("Status")},
        )

    def _is_enabled_status(self, value: str | None) -> bool:
        return str(value or "").upper() in {"ENABLED", "ENABLING"}

    def _is_recording(self, status: dict[str, Any]) -> bool:
        return bool(status.get("recording"))

    def _is_aws_managed_config_rule(self, rule: dict[str, Any]) -> bool:
        source = rule.get("Source")
        if not isinstance(source, dict):
            return False
        return str(source.get("Owner") or "").upper() == "AWS"

    def _has_periodic_trigger(self, rule: dict[str, Any]) -> bool:
        for detail in self._get_config_source_details(rule):
            message_type = str(detail.get("MessageType") or "")
            if message_type == "ScheduledNotification":
                return True
        return False
