from __future__ import annotations  # noqa: D100

from importlib import import_module
from typing import TYPE_CHECKING

from unio_collector.collector.transformation.identity import (
    IdentityEvidenceTransformationPolicy,
)

if TYPE_CHECKING:
    from unio_collector.collector.execution.result import CollectorExecutionResult
    from unio_collector.collector.transformation.policy import (
        EvidenceTransformationPolicy,
    )


class CollectorExecutionService:
    """Dispatch collection through the provider-owned collection boundary."""

    def execute(
        self,
        config: object,
        selection: object,
        progress: object | None = None,
        *,
        minimisation: object | None = None,
    ) -> CollectorExecutionResult:
        """Run collection without selecting a full scan executor."""
        provider_id = str(getattr(config, "provider_id", "aws"))
        if provider_id != "aws":
            msg = "The standalone collector distribution currently supports AWS only."
            raise ValueError(msg)
        executor_type = import_module(
            "unio_collector.providers.aws.collection.executor",
        ).AwsProviderCollectionExecutor
        executor = executor_type()
        result = executor.execute_collection(
            config,
            selection,
            progress,
            minimisation=minimisation,
        )
        return self._transformation_policy.transform(result)

    def execute_with_context(
        self,
        config: object,
        selection: object,
        *,
        session: object,
        ledger: object,
        account_context: dict[str, object],
        progress: object | None = None,
        minimisation: object | None = None,
    ) -> CollectorExecutionResult:
        """Collect with an isolated organization account execution context."""
        provider_id = str(getattr(config, "provider_id", "aws"))
        if provider_id != "aws":
            message = "Organization collection supports AWS only."
            raise ValueError(message)
        executor_type = import_module(
            "unio_collector.providers.aws.collection.executor",
        ).AwsProviderCollectionExecutor
        result = executor_type().execute_with_context(
            config,
            selection,
            session=session,
            ledger=ledger,
            account_context=account_context,
            progress=progress,
            minimisation=minimisation,
        )
        return self._transformation_policy.transform(result)

    def __init__(
        self,
        transformation_policy: EvidenceTransformationPolicy | None = None,
    ) -> None:
        """Store the collector-safe pre-serialization transformation policy."""
        self._transformation_policy = transformation_policy or IdentityEvidenceTransformationPolicy()
