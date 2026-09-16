from __future__ import annotations  # noqa: D100

from typing import Any

from unio_collector.aws import errors as aws_errors


class ManagedPlatformInventoryCommonMixin:
    """Managed platform inventory collector helpers."""

    @property
    def _collector(self) -> Any:  # noqa: ANN401
        return self

    def _collect_elasticache_clusters(
        self,
        client: Any,  # noqa: ANN401
        permission_errors: list[str],
    ) -> list[dict[str, Any]]:
        try:
            result = self._collector._pagination.collect_pages(  # noqa: SLF001
                client,
                "describe_cache_clusters",
                result_key="CacheClusters",
                request_parameters={"ShowCacheNodeInfo": True},
            )
        except Exception as exc:  # noqa: BLE001
            self._collector._record_collection_error(  # noqa: SLF001
                permission_errors,
                method_name="describe_cache_clusters",
                exc=exc,
            )
            return []
        return self._collector._collect_items(result.pages, "CacheClusters")  # noqa: SLF001

    def _has_elasticache_cluster_mode(self, group: dict[str, Any]) -> bool:
        if bool(group.get("ClusterEnabled")):
            return True
        groups = group.get("NodeGroups")
        return isinstance(groups, list) and len(groups) > 1

    def _get_int(self, value: Any) -> int:  # noqa: ANN401
        return self._collector._values.get_int(value)  # noqa: SLF001

    def _safe_client(
        self,
        service_name: str,
        region: str,
        permission_errors: list[str],
    ) -> Any | None:  # noqa: ANN401
        try:
            return self._collector.session.create_client(
                service_name,
                region_name=region,
                audit_context=self._collector.audit_context,
            )
        except Exception as exc:  # noqa: BLE001
            self._collector._record_collection_error(  # noqa: SLF001
                permission_errors,
                method_name=f"{service_name}:CreateClient",
                exc=exc,
            )
            return None

    def _record_collection_error(
        self,
        errors: list[str],
        *,
        method_name: str,
        exc: Exception,
    ) -> None:
        if aws_errors.is_expected_absence_error(exc):
            return
        code = aws_errors.get_aws_error_code(exc) or exc.__class__.__name__
        errors.append(f"{method_name}:{code}")

    def _extend_unique(self, target: list[str], values: list[str]) -> None:
        self._collector._values.extend_unique(target, values)  # noqa: SLF001

    def _get_max_workers(self) -> int:
        runtime_config = getattr(self._collector.session, "runtime_config", None)
        configured = getattr(runtime_config, "max_workers", 4)
        if not isinstance(configured, int) or configured <= 0:
            return 4
        return min(16, configured)

    def _collect_items(
        self,
        pages: list[dict[str, Any]],
        key: str,
    ) -> list[dict[str, Any]]:
        return self._collector._values.collect_dict_items(pages, key)  # noqa: SLF001

    def _collect_response_items(
        self,
        response: dict[str, Any],
        key: str,
    ) -> list[dict[str, Any]]:
        return self._collector._values.collect_response_items(response, key)  # noqa: SLF001

    def _limit_samples(self, values: list[str]) -> list[str]:
        return self._collector._values.limit_samples(values)  # noqa: SLF001

    def _chunk_values(
        self,
        values: list[str],
        chunk_size: int,
    ) -> list[list[str]]:
        return self._collector._values.chunk_values(values, chunk_size)  # noqa: SLF001

    def _truncate_sample_text(self, value: str, max_length: int = 160) -> str:
        return self._collector._values.truncate_sample_text(  # noqa: SLF001
            value,
            max_length=max_length,
        )

    def get_available_regions(self) -> list[str]:  # noqa: D102
        if self._collector._available_regions_cache is not None:  # noqa: SLF001
            return self._collector._available_regions_cache  # noqa: SLF001
        if self._collector.selected_regions:
            self._collector._available_regions_cache = sorted(  # noqa: SLF001
                self._collector.selected_regions,
            )
            return self._collector._available_regions_cache  # noqa: SLF001
        client = self._collector.session.create_client(
            "ec2",
            region_name=self._collector.session.get_region_name() or "us-east-1",
            audit_context=self._collector.audit_context,
        )
        response = client.describe_regions(AllRegions=False)
        self._collector._available_regions_cache = sorted(region["RegionName"] for region in response.get("Regions", []))  # noqa: SLF001
        return self._collector._available_regions_cache  # noqa: SLF001
