from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class ProviderRuntimeDescriptor:
    """Registry descriptor for live and future provider runtime support."""

    provider_id: str
    display_name: str
    maturity: str
    package_status: str
    source_contract: str
    live_selectable: bool = False
    runtime_factory_path: str | None = None
    scan_executor_factory_path: str | None = None
    collection_executor_factory_path: str | None = None

    def __post_init__(self) -> None:
        """Reject descriptors that imply live support without factory paths."""
        if self.live_selectable and not self.runtime_factory_path:
            msg = f"Live provider {self.provider_id!r} requires a runtime factory path."
            raise ValueError(msg)
        if self.live_selectable and not self.scan_executor_factory_path:
            msg = f"Live provider {self.provider_id!r} requires a scan executor factory path."
            raise ValueError(msg)
