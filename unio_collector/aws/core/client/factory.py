from __future__ import annotations  # noqa: D100

import threading
from typing import TYPE_CHECKING, Any

from unio_collector.aws.core.client.cache_key import AwsClientCacheKey

if TYPE_CHECKING:
    from unio_collector.aws.client.config import AwsRuntimeConfig


class AwsClientFactory:  # noqa: D101
    def __init__(self, boto_session: Any, runtime_config: AwsRuntimeConfig) -> None:  # noqa: ANN401, D107
        self._boto_session = boto_session
        self._runtime_config = runtime_config
        self._clients: dict[AwsClientCacheKey, Any] = {}
        self._lock = threading.Lock()

    def create_client(  # noqa: D102
        self,
        service_name: str,
        *,
        region_name: str | None,
        client_config: Any | None = None,  # noqa: ANN401
    ) -> Any:  # noqa: ANN401
        if client_config is not None:
            return self._boto_session.client(
                service_name,
                region_name=region_name,
                config=client_config,
            )
        key = AwsClientCacheKey(
            service_name=service_name,
            region_name=region_name or "aws-global",
            runtime_signature=self._build_runtime_signature(),
        )
        with self._lock:
            client = self._clients.get(key)
            if client is None:
                client = self._boto_session.client(
                    service_name,
                    region_name=region_name,
                    config=self._runtime_config.build_botocore_config(),
                )
                self._clients[key] = client
            return client

    def _build_runtime_signature(self) -> tuple[object, ...]:
        return (
            self._runtime_config.max_pool_connections,
            self._runtime_config.retry_mode,
            self._runtime_config.total_max_attempts,
            self._runtime_config.connect_timeout_seconds,
            self._runtime_config.read_timeout_seconds,
        )
