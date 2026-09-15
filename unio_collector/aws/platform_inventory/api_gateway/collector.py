from __future__ import annotations  # noqa: D100

from typing import Any

from unio_collector.aws.api_gateway.region_record import ApiGatewayRegionRecord


class ManagedPlatformApiGatewayMixin:
    """Managed platform inventory collector helpers."""

    @property
    def _collector(self) -> Any:  # noqa: ANN401
        return self

    def _collect_api_gateway_record(
        self,
        region: str,
    ) -> list[ApiGatewayRegionRecord]:
        permission_errors: list[str] = []
        rest_record = self._collector._collect_rest_api_gateway_metadata(  # noqa: SLF001
            region,
            permission_errors,
        )
        v2_record = self._collector._collect_v2_api_gateway_metadata(  # noqa: SLF001
            region,
            permission_errors,
        )
        return [
            ApiGatewayRegionRecord(
                account_id=self._collector.account_id,
                region=region,
                rest_api_count=rest_record["rest_api_count"],
                http_api_count=v2_record["http_api_count"],
                websocket_api_count=v2_record["websocket_api_count"],
                private_rest_api_count=rest_record["private_rest_api_count"],
                regional_rest_api_count=rest_record["regional_rest_api_count"],
                edge_optimized_rest_api_count=rest_record["edge_optimized_rest_api_count"],
                stage_count=rest_record["stage_count"] + v2_record["stage_count"],
                auto_deploy_stage_count=(rest_record["auto_deploy_stage_count"] + v2_record["auto_deploy_stage_count"]),
                cache_enabled_stage_count=rest_record["cache_enabled_stage_count"],
                access_logging_stage_count=(rest_record["access_logging_stage_count"] + v2_record["access_logging_stage_count"]),
                execution_logging_stage_count=(rest_record["execution_logging_stage_count"] + v2_record["execution_logging_stage_count"]),
                detailed_metrics_stage_count=(rest_record["detailed_metrics_stage_count"] + v2_record["detailed_metrics_stage_count"]),
                data_trace_stage_count=(rest_record["data_trace_stage_count"] + v2_record["data_trace_stage_count"]),
                xray_tracing_stage_count=rest_record["xray_tracing_stage_count"],
                route_count=v2_record["route_count"],
                authorization_configured_route_count=v2_record["authorization_configured_route_count"],
                default_route_count=v2_record["default_route_count"],
                cors_configured_api_count=(rest_record["cors_configured_api_count"] + v2_record["cors_configured_api_count"]),
                throttling_configured_stage_count=(rest_record["throttling_configured_stage_count"] + v2_record["throttling_configured_stage_count"]),
                vpc_link_count=(rest_record["vpc_link_count"] + v2_record["vpc_link_count"]),
                available_vpc_link_count=(rest_record["available_vpc_link_count"] + v2_record["available_vpc_link_count"]),
                vpc_link_detail_collected=(rest_record["vpc_link_detail_collected"] and v2_record["vpc_link_detail_collected"]),
                sample_endpoint_types=self._collector._limit_samples(  # noqa: SLF001
                    rest_record["sample_endpoint_types"],
                ),
                sample_api_names=self._collector._limit_samples(  # noqa: SLF001
                    rest_record["sample_api_names"] + v2_record["sample_api_names"],
                ),
                sample_route_keys=self._collector._limit_samples(  # noqa: SLF001
                    v2_record["sample_route_keys"],
                ),
                sample_stage_names=self._collector._limit_samples(  # noqa: SLF001
                    rest_record["sample_stage_names"] + v2_record["sample_stage_names"],
                ),
                sample_vpc_link_names=self._collector._limit_samples(  # noqa: SLF001
                    rest_record["sample_vpc_link_names"] + v2_record["sample_vpc_link_names"],
                ),
                permission_errors=permission_errors,
            ),
        ]

    def _collect_rest_api_gateway_metadata(
        self,
        region: str,
        permission_errors: list[str],
    ) -> dict[str, Any]:
        client = self._collector._safe_client("apigateway", region, permission_errors)  # noqa: SLF001
        if client is None:
            return self._collector._empty_api_gateway_counts()  # noqa: SLF001
        apis = self._collector._collect_rest_apis(client, permission_errors)  # noqa: SLF001
        stages = [
            stage
            for api in apis
            for stage in self._collector._collect_rest_api_stages(  # noqa: SLF001
                client,
                api,
                permission_errors,
            )
        ]
        vpc_links = self._collector._collect_api_gateway_vpc_links_if_enabled(  # noqa: SLF001
            client,
            permission_errors,
            result_key="items",
        )
        endpoint_types = [endpoint_type for api in apis for endpoint_type in self._collector._get_rest_api_endpoint_types(api)]  # noqa: SLF001
        return {
            **self._collector._summarize_stage_settings(stages),  # noqa: SLF001
            "rest_api_count": len(apis),
            "http_api_count": 0,
            "websocket_api_count": 0,
            "private_rest_api_count": endpoint_types.count("PRIVATE"),
            "regional_rest_api_count": endpoint_types.count("REGIONAL"),
            "edge_optimized_rest_api_count": endpoint_types.count("EDGE"),
            "auto_deploy_stage_count": 0,
            "route_count": 0,
            "authorization_configured_route_count": 0,
            "default_route_count": 0,
            "cors_configured_api_count": 0,
            "throttling_configured_stage_count": sum(1 for stage in stages if self._collector._has_throttling_settings(stage)),  # noqa: SLF001
            "vpc_link_count": len(vpc_links),
            "available_vpc_link_count": self._collector._count_available_vpc_links(  # noqa: SLF001
                vpc_links,
            ),
            "vpc_link_detail_collected": (self._collector.api_gateway_vpc_link_detail_mode == "full"),
            "sample_endpoint_types": self._collector._limit_samples(endpoint_types),  # noqa: SLF001
            "sample_api_names": [str(api.get("name")) for api in apis[:10] if api.get("name")],
            "sample_route_keys": [],
            "sample_stage_names": self._collector._build_stage_names(stages),  # noqa: SLF001
            "sample_vpc_link_names": self._collector._build_vpc_link_names(vpc_links),  # noqa: SLF001
        }

    def _collect_v2_api_gateway_metadata(
        self,
        region: str,
        permission_errors: list[str],
    ) -> dict[str, Any]:
        client = self._collector._safe_client("apigatewayv2", region, permission_errors)  # noqa: SLF001
        if client is None:
            return self._collector._empty_api_gateway_counts()  # noqa: SLF001
        apis = self._collector._collect_v2_apis(client, permission_errors)  # noqa: SLF001
        stages = [
            stage
            for api in apis
            for stage in self._collector._collect_v2_api_stages(  # noqa: SLF001
                client,
                api,
                permission_errors,
            )
        ]
        routes = [
            route
            for api in apis
            for route in self._collector._collect_v2_api_routes(  # noqa: SLF001
                client,
                api,
                permission_errors,
            )
        ]
        vpc_links = self._collector._collect_api_gateway_vpc_links_if_enabled(  # noqa: SLF001
            client,
            permission_errors,
            result_key="Items",
        )
        return {
            **self._collector._summarize_stage_settings(stages),  # noqa: SLF001
            "rest_api_count": 0,
            "private_rest_api_count": 0,
            "regional_rest_api_count": 0,
            "edge_optimized_rest_api_count": 0,
            "http_api_count": sum(1 for api in apis if api.get("ProtocolType") == "HTTP"),
            "websocket_api_count": sum(1 for api in apis if api.get("ProtocolType") == "WEBSOCKET"),
            "auto_deploy_stage_count": sum(1 for stage in stages if bool(stage.get("AutoDeploy"))),
            "route_count": len(routes),
            "authorization_configured_route_count": sum(1 for route in routes if self._collector._has_api_route_authorization(route)),  # noqa: SLF001
            "default_route_count": sum(1 for route in routes if self._collector._is_default_route(route)),  # noqa: SLF001
            "cors_configured_api_count": sum(1 for api in apis if isinstance(api.get("CorsConfiguration"), dict)),
            "throttling_configured_stage_count": sum(1 for stage in stages if self._collector._has_throttling_settings(stage)),  # noqa: SLF001
            "vpc_link_count": len(vpc_links),
            "available_vpc_link_count": self._collector._count_available_vpc_links(  # noqa: SLF001
                vpc_links,
            ),
            "vpc_link_detail_collected": (self._collector.api_gateway_vpc_link_detail_mode == "full"),
            "sample_endpoint_types": [],
            "sample_api_names": [str(api.get("Name")) for api in apis[:10] if api.get("Name")],
            "sample_route_keys": self._collector._build_route_keys(routes),  # noqa: SLF001
            "sample_stage_names": self._collector._build_stage_names(stages),  # noqa: SLF001
            "sample_vpc_link_names": self._collector._build_vpc_link_names(vpc_links),  # noqa: SLF001
        }

    def _collect_rest_apis(
        self,
        client: Any,  # noqa: ANN401
        permission_errors: list[str],
    ) -> list[dict[str, Any]]:
        try:
            result = self._collector._pagination.collect_pages(  # noqa: SLF001
                client,
                "get_rest_apis",
                result_key="items",
            )
        except Exception as exc:  # noqa: BLE001
            self._collector._record_collection_error(  # noqa: SLF001
                permission_errors,
                method_name="get_rest_apis",
                exc=exc,
            )
            return []
        return self._collector._collect_items(result.pages, "items")  # noqa: SLF001

    def _collect_rest_api_stages(
        self,
        client: Any,  # noqa: ANN401
        api: dict[str, Any],
        permission_errors: list[str],
    ) -> list[dict[str, Any]]:
        api_id = str(api.get("id") or "")
        if not api_id:
            return []
        try:
            response = client.get_stages(restApiId=api_id)
        except Exception as exc:  # noqa: BLE001
            self._collector._record_collection_error(  # noqa: SLF001
                permission_errors,
                method_name="get_stages",
                exc=exc,
            )
            return []
        stages = response.get("item", []) if isinstance(response, dict) else []
        if not isinstance(stages, list):
            return []
        return [
            {
                **stage,
                "api_name": api.get("name"),
                "api_id": api_id,
                "api_kind": "REST",
            }
            for stage in stages
            if isinstance(stage, dict)
        ]

    def _collect_v2_apis(
        self,
        client: Any,  # noqa: ANN401
        permission_errors: list[str],
    ) -> list[dict[str, Any]]:
        try:
            result = self._collector._pagination.collect_pages(  # noqa: SLF001
                client,
                "get_apis",
                result_key="Items",
            )
        except Exception as exc:  # noqa: BLE001
            self._collector._record_collection_error(  # noqa: SLF001
                permission_errors,
                method_name="get_apis",
                exc=exc,
            )
            return []
        return self._collector._collect_items(result.pages, "Items")  # noqa: SLF001

    def _collect_v2_api_stages(
        self,
        client: Any,  # noqa: ANN401
        api: dict[str, Any],
        permission_errors: list[str],
    ) -> list[dict[str, Any]]:
        api_id = str(api.get("ApiId") or "")
        if not api_id:
            return []
        try:
            result = self._collector._pagination.collect_pages(  # noqa: SLF001
                client,
                "get_stages",
                result_key="Items",
                request_parameters={"ApiId": api_id},
            )
        except Exception as exc:  # noqa: BLE001
            self._collector._record_collection_error(  # noqa: SLF001
                permission_errors,
                method_name="get_stages",
                exc=exc,
            )
            return []
        stages = self._collector._collect_items(result.pages, "Items")  # noqa: SLF001
        return [
            {
                **stage,
                "api_name": api.get("Name"),
                "api_id": api_id,
                "api_kind": api.get("ProtocolType") or "API_GATEWAY_V2",
            }
            for stage in stages
        ]

    def _collect_v2_api_routes(
        self,
        client: Any,  # noqa: ANN401
        api: dict[str, Any],
        permission_errors: list[str],
    ) -> list[dict[str, Any]]:
        api_id = str(api.get("ApiId") or "")
        if not api_id:
            return []
        try:
            result = self._collector._pagination.collect_pages(  # noqa: SLF001
                client,
                "get_routes",
                result_key="Items",
                request_parameters={"ApiId": api_id},
            )
        except Exception as exc:  # noqa: BLE001
            self._collector._record_collection_error(  # noqa: SLF001
                permission_errors,
                method_name="get_routes",
                exc=exc,
            )
            return []
        routes = self._collector._collect_items(result.pages, "Items")  # noqa: SLF001
        return [
            {
                **route,
                "api_name": api.get("Name"),
                "api_id": api_id,
                "api_kind": api.get("ProtocolType") or "API_GATEWAY_V2",
            }
            for route in routes
        ]

    def _collect_api_gateway_vpc_links(
        self,
        client: Any,  # noqa: ANN401
        permission_errors: list[str],
        *,
        result_key: str,
    ) -> list[dict[str, Any]]:
        try:
            result = self._collector._pagination.collect_pages(  # noqa: SLF001
                client,
                "get_vpc_links",
                result_key=result_key,
            )
        except Exception as exc:  # noqa: BLE001
            self._collector._record_collection_error(  # noqa: SLF001
                permission_errors,
                method_name="get_vpc_links",
                exc=exc,
            )
            return []
        return self._collector._collect_items(result.pages, result_key)  # noqa: SLF001

    def _collect_api_gateway_vpc_links_if_enabled(
        self,
        client: Any,  # noqa: ANN401
        permission_errors: list[str],
        *,
        result_key: str,
    ) -> list[dict[str, Any]]:
        if self._collector.api_gateway_vpc_link_detail_mode == "summary":
            return []
        return self._collector._collect_api_gateway_vpc_links(  # noqa: SLF001
            client,
            permission_errors,
            result_key=result_key,
        )
