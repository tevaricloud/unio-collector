from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

import yaml

from unio_collector.aws.client.config import AwsRuntimeConfig
from unio_collector.collector.provider import normalize_collector_provider_id
from unio_collector.collector_cli.services.configuration.data import (
    CollectorFileConfig,
)
from unio_collector.config.scan.modes import normalize_scan_mode
from unio_collector.config.scan.profiles import FULL_SCAN_DETAIL_PROFILE
from unio_collector.evidence.tagging.defaults import DEFAULT_COST_GROUP_TAGS
from unio_collector.products.collection import get_collection_product
from unio_collector.scanners.pillars import normalize_scan_pillars

if TYPE_CHECKING:
    from pathlib import Path


class CollectorConfigFileLoader:
    """Load the collector-safe subset of YAML configuration."""

    def __init__(self, path: Path) -> None:
        """Store the YAML config path."""
        self.path = path

    def load(self, *, strict: bool) -> CollectorFileConfig:
        """Parse a YAML config file without report or LLM config imports."""
        raw = yaml.safe_load(self.path.read_text(encoding="utf-8"))
        if raw is None:
            return CollectorFileConfig()
        if not isinstance(raw, dict):
            msg = "Config file root must be a mapping."
            raise ValueError(msg)
        diagnostics = self._collect_diagnostics(raw)
        if strict and diagnostics:
            joined = "\n".join(diagnostics)
            msg = f"Strict collector config validation failed:\n{joined}"
            raise ValueError(msg)
        scan = _mapping(raw, "scan")
        scanner_states, scanner_options = self._parse_scanners(
            _mapping(raw, "scanners"),
        )
        service_usage = _mapping(scan, "service_usage_precheck")
        configured_keys = frozenset(f"scan.{key}" for key in scan if isinstance(key, str))
        return CollectorFileConfig(
            provider_id=normalize_collector_provider_id(
                _optional_text(scan.get("provider")),
            ),
            azure_subscription_id=_optional_text(scan.get("azure_subscription_id")),
            entra_tenant_id=_optional_text(scan.get("entra_tenant_id")),
            gcp_project_id=_optional_text(scan.get("gcp_project_id")),
            preset=_optional_text(scan.get("preset")),
            scan_mode=normalize_scan_mode(_optional_text(scan.get("scan_mode"))),
            product_id=_product_id(scan.get("product")),
            pillars=normalize_scan_pillars(_string_list(scan.get("pillars", []))),
            regions=tuple(_string_list(scan.get("regions", []))),
            regions_from_billing=_bool(
                scan.get("regions_from_billing"),
                default=False,
            ),
            mode=_optional_text(scan.get("mode")),
            detail_profile=(_optional_text(scan.get("detail_profile")) or FULL_SCAN_DETAIL_PROFILE),
            allow_chargeable_scanners=_bool(
                scan.get("allow_chargeable_scanners"),
                default=_bool(scan.get("allow_chargeable_scans"), default=False),
            ),
            service_usage_precheck_enabled=_bool(
                service_usage.get("enabled"),
                default=True,
            ),
            force_service_scanners=_bool(
                service_usage.get("force_run"),
                default=_bool(scan.get("force_service_scanners"), default=False),
            ),
            required_tags=_required_tags(raw, scan),
            scanner_states=scanner_states,
            scanner_options=scanner_options,
            cost_grouping_tags=_cost_grouping_tags(raw),
            cur_paths=tuple(_string_list(_mapping(raw, "cost_data").get("cur_paths"))),
            runtime=self._parse_runtime(_mapping(raw, "runtime")),
            configured_keys=configured_keys,
            diagnostics=tuple(diagnostics),
        )

    def _parse_scanners(
        self,
        value: dict[str, object],
    ) -> tuple[dict[str, bool], dict[str, dict[str, object]]]:
        states: dict[str, bool] = {}
        options: dict[str, dict[str, object]] = {}
        for scanner_id, raw_value in value.items():
            if isinstance(raw_value, bool):
                states[str(scanner_id)] = raw_value
                continue
            if isinstance(raw_value, dict):
                enabled = raw_value.get("enabled")
                if isinstance(enabled, bool):
                    states[str(scanner_id)] = enabled
                options[str(scanner_id)] = {str(key): child for key, child in raw_value.items() if key != "enabled"}
                continue
            msg = f"Config scanner value for {scanner_id!r} must be true/false or a mapping."
            raise ValueError(msg)
        return states, options

    def _parse_runtime(self, value: dict[str, object]) -> AwsRuntimeConfig:
        return AwsRuntimeConfig().with_overrides(
            max_workers=_optional_int(value.get("max_workers")),
            scanner_max_workers=_optional_int(value.get("scanner_max_workers")),
            max_pool_connections=_optional_int(value.get("max_pool_connections")),
            total_max_attempts=_optional_int(value.get("total_max_attempts")),
            connect_timeout_seconds=_optional_int(
                value.get("connect_timeout_seconds"),
            ),
            read_timeout_seconds=_optional_int(value.get("read_timeout_seconds")),
        )

    def _collect_diagnostics(self, raw: dict[str, object]) -> list[str]:
        allowed = {
            "audit",
            "baseline",
            "scan",
            "scanners",
            "tagging",
            "cost_grouping",
            "cost_data",
            "framework_readiness",
            "llm",
            "metadata",
            "pricing",
            "redaction",
            "reporting",
            "runtime",
            "required_tags",
            "severity",
        }
        return [f"Collector config ignores unsupported top-level key: {key}" for key in sorted(raw) if key not in allowed]


def _required_tags(
    raw: dict[str, object],
    scan: dict[str, object],
) -> tuple[str, ...]:
    tags = _string_list(raw.get("required_tags", scan.get("required_tags", [])))
    return tuple(tags)


def _cost_grouping_tags(raw: dict[str, object]) -> tuple[str, ...]:
    cost_grouping = _mapping(raw, "cost_grouping")
    tags = _string_list(cost_grouping.get("group_by_tags", []))
    return tuple(tags or list(DEFAULT_COST_GROUP_TAGS))


def _mapping(value: dict[str, object], key: str) -> dict[str, object]:
    raw = value.get(key, {})
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        msg = f"Config section {key!r} must be a mapping."
        raise ValueError(msg)
    return raw


def _optional_text(value: object) -> str | None:
    if value in (None, ""):
        return None
    text = str(value).strip()
    return text or None


def _product_id(value: object) -> str | None:
    product_id = _optional_text(value)
    if product_id is None:
        return None
    return get_collection_product(product_id.lower()).product_id


def _string_list(value: object) -> list[str]:
    if value in (None, ""):
        return []
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        msg = "Config value must be a string list."
        raise ValueError(msg)
    return [item.strip() for item in value if item.strip()]


def _bool(value: object, *, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    msg = "Config value must be true or false."
    raise ValueError(msg)


def _optional_int(value: object) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(str(value))
    except ValueError as exc:
        msg = f"Config value must be an integer, got {value!r}."
        raise ValueError(msg) from exc


__all__ = ["CollectorConfigFileLoader"]
