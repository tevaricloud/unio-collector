from __future__ import annotations  # noqa: D100

from typing import Any


class ManagedPlatformApiGatewayHelpersMixin:
    """Managed platform inventory collector helpers."""

    @property
    def _collector(self) -> Any:  # noqa: ANN401
        return self

    def _summarize_stage_settings(
        self,
        stages: list[dict[str, Any]],
    ) -> dict[str, Any]:
        return {
            "stage_count": len(stages),
            "cache_enabled_stage_count": sum(1 for stage in stages if self._collector._has_stage_cache(stage)),  # noqa: SLF001
            "access_logging_stage_count": sum(1 for stage in stages if stage.get("accessLogSettings") or stage.get("AccessLogSettings")),
            "execution_logging_stage_count": sum(1 for stage in stages if self._collector._has_execution_logging(stage)),  # noqa: SLF001
            "detailed_metrics_stage_count": sum(1 for stage in stages if self._collector._has_detailed_metrics(stage)),  # noqa: SLF001
            "data_trace_stage_count": sum(1 for stage in stages if self._collector._has_data_trace(stage)),  # noqa: SLF001
            "xray_tracing_stage_count": sum(1 for stage in stages if bool(stage.get("tracingEnabled"))),
        }

    def _get_rest_api_endpoint_types(self, api: dict[str, Any]) -> list[str]:
        endpoint_configuration = api.get("endpointConfiguration")
        if not isinstance(endpoint_configuration, dict):
            return []
        endpoint_types = endpoint_configuration.get("types", [])
        if not isinstance(endpoint_types, list):
            return []
        return [str(endpoint_type).upper() for endpoint_type in endpoint_types if endpoint_type]

    def _has_api_route_authorization(self, route: dict[str, Any]) -> bool:
        authorization_type = str(route.get("AuthorizationType") or "").upper()
        return authorization_type not in {"", "NONE"}

    def _is_default_route(self, route: dict[str, Any]) -> bool:
        return str(route.get("RouteKey") or "").strip() == "$default"

    def _build_route_keys(self, routes: list[dict[str, Any]]) -> list[str]:
        keys: list[str] = []
        for route in routes[:10]:
            api_name = route.get("api_name")
            route_key = route.get("RouteKey")
            if api_name and route_key:
                keys.append(f"{api_name}:{route_key}")
            elif route_key:
                keys.append(str(route_key))
        return keys

    def _count_available_vpc_links(self, links: list[dict[str, Any]]) -> int:
        return sum(1 for link in links if self._collector._is_available_vpc_link(link))  # noqa: SLF001

    def _is_available_vpc_link(self, link: dict[str, Any]) -> bool:
        status = str(
            link.get("status") or link.get("Status") or link.get("VpcLinkStatus") or "",
        ).upper()
        return status in {"AVAILABLE", "ACTIVE"}

    def _build_vpc_link_names(self, links: list[dict[str, Any]]) -> list[str]:
        names = [
            str(value)
            for link in links
            if (value := (link.get("name") or link.get("Name") or link.get("VpcLinkId") or link.get("vpcLinkId") or link.get("VpcLinkArn")))
        ]
        return self._collector._limit_samples(names)  # noqa: SLF001

    def _has_stage_cache(self, stage: dict[str, Any]) -> bool:
        if stage.get("cacheClusterEnabled"):
            return True
        return any(bool(settings.get("cachingEnabled")) for settings in self._collector._iter_route_or_method_settings(stage))  # noqa: SLF001

    def _has_execution_logging(self, stage: dict[str, Any]) -> bool:
        return any(
            str(settings.get("loggingLevel") or settings.get("LoggingLevel") or "OFF") != "OFF"
            for settings in self._collector._iter_route_or_method_settings(stage)  # noqa: SLF001
        )

    def _has_detailed_metrics(self, stage: dict[str, Any]) -> bool:
        return any(
            bool(
                settings.get("metricsEnabled") or settings.get("DetailedMetricsEnabled"),
            )
            for settings in self._collector._iter_route_or_method_settings(stage)  # noqa: SLF001
        )

    def _has_data_trace(self, stage: dict[str, Any]) -> bool:
        return any(
            bool(settings.get("dataTraceEnabled") or settings.get("DataTraceEnabled"))
            for settings in self._collector._iter_route_or_method_settings(stage)  # noqa: SLF001
        )

    def _has_throttling_settings(self, stage: dict[str, Any]) -> bool:
        return any(self._collector._settings_have_throttling(settings) for settings in self._collector._iter_route_or_method_settings(stage))  # noqa: SLF001

    def _settings_have_throttling(self, settings: dict[str, Any]) -> bool:
        return any(
            self._collector._get_int(settings.get(key)) > 0  # noqa: SLF001
            for key in (
                "throttlingBurstLimit",
                "throttlingRateLimit",
                "ThrottlingBurstLimit",
                "ThrottlingRateLimit",
            )
        )

    def _iter_route_or_method_settings(
        self,
        stage: dict[str, Any],
    ) -> list[dict[str, Any]]:
        settings: list[dict[str, Any]] = []
        method_settings = stage.get("methodSettings")
        if isinstance(method_settings, dict):
            settings.extend(value for value in method_settings.values() if isinstance(value, dict))
        route_settings = stage.get("RouteSettings")
        if isinstance(route_settings, dict):
            settings.extend(value for value in route_settings.values() if isinstance(value, dict))
        default_route_settings = stage.get("DefaultRouteSettings")
        if isinstance(default_route_settings, dict):
            settings.append(default_route_settings)
        return settings

    def _build_stage_names(self, stages: list[dict[str, Any]]) -> list[str]:
        names: list[str] = []
        for stage in stages[:10]:
            api_name = stage.get("api_name")
            stage_name = stage.get("stageName") or stage.get("StageName")
            if api_name and stage_name:
                names.append(f"{api_name}/{stage_name}")
            elif stage_name:
                names.append(str(stage_name))
        return names

    def _empty_api_gateway_counts(self) -> dict[str, Any]:
        return {
            "rest_api_count": 0,
            "http_api_count": 0,
            "websocket_api_count": 0,
            "stage_count": 0,
            "private_rest_api_count": 0,
            "regional_rest_api_count": 0,
            "edge_optimized_rest_api_count": 0,
            "auto_deploy_stage_count": 0,
            "cache_enabled_stage_count": 0,
            "access_logging_stage_count": 0,
            "execution_logging_stage_count": 0,
            "detailed_metrics_stage_count": 0,
            "data_trace_stage_count": 0,
            "xray_tracing_stage_count": 0,
            "route_count": 0,
            "authorization_configured_route_count": 0,
            "default_route_count": 0,
            "cors_configured_api_count": 0,
            "throttling_configured_stage_count": 0,
            "vpc_link_count": 0,
            "available_vpc_link_count": 0,
            "vpc_link_detail_collected": (self._collector.api_gateway_vpc_link_detail_mode == "full"),
            "sample_endpoint_types": [],
            "sample_api_names": [],
            "sample_route_keys": [],
            "sample_stage_names": [],
            "sample_vpc_link_names": [],
        }
