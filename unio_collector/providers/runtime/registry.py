from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from importlib import import_module
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from collections.abc import Callable

    from unio_collector.collector.execution.contract import (
        ProviderCollectionExecutorProtocol,
    )
    from unio_collector.providers.runtime.contract import ProviderRuntimeProtocol
    from unio_collector.providers.runtime.descriptor import ProviderRuntimeDescriptor
    from unio_collector.scan_workflow.provider_execution.executor import ProviderScanExecutorProtocol


@dataclass(frozen=True)
class ProviderRuntimeRegistry:
    """Deterministic in-process registry for provider runtime availability."""

    descriptors: tuple[ProviderRuntimeDescriptor, ...] = ()

    def get_descriptor(self, provider_id: str) -> ProviderRuntimeDescriptor | None:
        """Return the descriptor for one provider ID, when known."""
        normalized = provider_id.strip().lower()
        for descriptor in self.descriptors:
            if descriptor.provider_id == normalized:
                return descriptor
        return None

    def list_descriptors(self) -> tuple[ProviderRuntimeDescriptor, ...]:
        """Return all known runtime descriptors in stable order."""
        return tuple(sorted(self.descriptors, key=lambda descriptor: descriptor.provider_id))

    def live_provider_ids(self) -> tuple[str, ...]:
        """Return provider IDs enabled for live scan runtime selection."""
        return tuple(descriptor.provider_id for descriptor in self.list_descriptors() if descriptor.live_selectable)

    def require_live_descriptor(self, provider_id: str) -> ProviderRuntimeDescriptor:
        """Return one live descriptor or raise a clear validation error."""
        descriptor = self.get_descriptor(provider_id)
        if descriptor is not None and descriptor.live_selectable:
            return descriptor
        allowed = ", ".join(self.live_provider_ids())
        msg = f"Provider must be one of: {allowed}."
        raise ValueError(msg)

    def create_runtime(self, provider_id: str) -> ProviderRuntimeProtocol:
        """Instantiate the registered runtime for one live provider."""
        descriptor = self.require_live_descriptor(provider_id)
        runtime_factory_path = descriptor.runtime_factory_path
        if runtime_factory_path is None:
            msg = f"Live provider {provider_id!r} has no runtime factory path."
            raise RuntimeError(msg)
        factory = self._load_factory(
            runtime_factory_path,
            provider_id=descriptor.provider_id,
            factory_role="runtime",
        )
        return cast("ProviderRuntimeProtocol", factory())

    def create_scan_executor(self, provider_id: str) -> ProviderScanExecutorProtocol[object]:
        """Instantiate the registered scan executor for one live provider."""
        descriptor = self.require_live_descriptor(provider_id)
        executor_factory_path = descriptor.scan_executor_factory_path
        if executor_factory_path is None:
            msg = f"Live provider {provider_id!r} has no scan executor factory path."
            raise RuntimeError(msg)
        factory = self._load_factory(
            executor_factory_path,
            provider_id=descriptor.provider_id,
            factory_role="scan executor",
        )
        return cast("ProviderScanExecutorProtocol[object]", factory())

    def create_collection_executor(
        self,
        provider_id: str,
    ) -> ProviderCollectionExecutorProtocol:
        """Instantiate the collection-only executor for one live provider."""
        descriptor = self.require_live_descriptor(provider_id)
        factory_path = descriptor.collection_executor_factory_path
        if factory_path is None:
            msg = f"Live provider {provider_id!r} has no collection executor factory path."
            raise RuntimeError(msg)
        factory = self._load_factory(
            factory_path,
            provider_id=descriptor.provider_id,
            factory_role="collection executor",
        )
        return cast("ProviderCollectionExecutorProtocol", factory())

    def _load_factory(
        self,
        factory_path: str,
        *,
        provider_id: str,
        factory_role: str,
    ) -> Callable[[], Any]:
        if factory_path.count(":") != 1:
            msg = self._format_factory_error(
                provider_id,
                factory_role,
                factory_path,
                "must use exact module:attribute shape",
            )
            raise RuntimeError(msg)
        module_name, attribute_name = factory_path.split(":", maxsplit=1)
        if not module_name or not attribute_name:
            msg = self._format_factory_error(
                provider_id,
                factory_role,
                factory_path,
                "must include non-empty module and attribute segments",
            )
            raise RuntimeError(msg)
        try:
            module = import_module(module_name)
        except ImportError as exc:
            msg = self._format_factory_error(
                provider_id,
                factory_role,
                factory_path,
                f"could not import module {module_name!r}",
            )
            raise RuntimeError(msg) from exc
        try:
            factory = getattr(module, attribute_name)
        except AttributeError as exc:
            msg = self._format_factory_error(
                provider_id,
                factory_role,
                factory_path,
                f"could not find attribute {attribute_name!r}",
            )
            raise RuntimeError(msg) from exc
        if not callable(factory):
            msg = self._format_factory_error(
                provider_id,
                factory_role,
                factory_path,
                f"attribute {attribute_name!r} is not callable",
            )
            raise RuntimeError(msg)
        return cast("Callable[[], Any]", factory)

    def _format_factory_error(
        self,
        provider_id: str,
        factory_role: str,
        factory_path: str,
        reason: str,
    ) -> str:
        return f"Provider {provider_id!r} {factory_role} factory path {factory_path!r} is invalid: {reason}."
