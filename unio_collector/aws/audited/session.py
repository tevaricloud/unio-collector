from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

from unio_collector.aws.audited.client import AuditedAwsClient
from unio_collector.aws.cassette import (
    AwsCassetteRecorder,
    AwsCassetteReplayer,
    AwsCassetteStore,
)
from unio_collector.aws.client.config import AwsRuntimeConfig
from unio_collector.aws.client.factory import AwsClientFactory
from unio_collector.aws.rate.limiter import AwsRateLimiter
from unio_collector.aws.telemetry import AwsApiTelemetryRecorder

if TYPE_CHECKING:
    from unio_collector.aws.api.call_ledger import ApiCallLedger
    from unio_collector.aws.audit.context import AwsAuditContext


class AuditedAwsSession:  # noqa: D101
    def __init__(  # noqa: D107
        self,
        boto_session: Any,  # noqa: ANN401
        ledger: ApiCallLedger,
        *,
        runtime_config: AwsRuntimeConfig | None = None,
        client_factory: AwsClientFactory | None = None,
        rate_limiter: AwsRateLimiter | None = None,
        telemetry: AwsApiTelemetryRecorder | None = None,
    ) -> None:
        self._boto_session = boto_session
        self.ledger = ledger
        self.runtime_config = runtime_config or AwsRuntimeConfig()
        self.runtime_config.validate()
        self.client_factory = client_factory or AwsClientFactory(
            boto_session,
            self.runtime_config,
        )
        self.rate_limiter = rate_limiter or AwsRateLimiter(self.runtime_config)
        self.telemetry = telemetry or AwsApiTelemetryRecorder(
            enabled=self.runtime_config.telemetry_enabled,
        )
        cassette_store: AwsCassetteStore | None = None
        if self.runtime_config.record_aws_cassette:
            cassette_store = AwsCassetteStore(self.runtime_config.record_aws_cassette)
        if self.runtime_config.replay_aws_cassette:
            cassette_store = AwsCassetteStore(self.runtime_config.replay_aws_cassette)
        self.cassette_recorder = AwsCassetteRecorder(cassette_store) if cassette_store and self.runtime_config.record_aws_cassette else None
        self.cassette_replayer = AwsCassetteReplayer(cassette_store) if cassette_store and self.runtime_config.replay_aws_cassette else None
        self.region_scope: Any | None = None

    def get_region_name(self) -> str | None:  # noqa: D102
        return self._boto_session.region_name

    def get_available_regions(self, service_name: str) -> list[str]:  # noqa: D102
        if self.region_scope is not None:
            return self.region_scope.get_service_regions(service_name)
        return self.get_sdk_available_regions(service_name)

    def get_sdk_available_regions(self, service_name: str) -> list[str]:  # noqa: D102
        return self._boto_session.get_available_regions(service_name)

    def create_client(  # noqa: D102
        self,
        service_name: str,
        *,
        region_name: str | None = None,
        audit_context: AwsAuditContext,
        client_config: Any | None = None,  # noqa: ANN401
    ) -> AuditedAwsClient:
        raw_client = self.client_factory.create_client(
            service_name,
            region_name=region_name,
            client_config=client_config,
        )
        return AuditedAwsClient(
            raw_client=raw_client,
            service_name=service_name,
            region_name=region_name,
            ledger=self.ledger,
            audit_context=audit_context,
            rate_limiter=self.rate_limiter,
            telemetry=self.telemetry,
            cassette_recorder=self.cassette_recorder,
            cassette_replayer=self.cassette_replayer,
            attempt=audit_context.attempt,
        )
