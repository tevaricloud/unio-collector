from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

    from unio_collector.scanners.registry.source import ScannerDefinitionSource
    from unio_collector.scanners.scanner.definition import ScannerDefinition

BUILT_IN_PERMISSION_METADATA_SOURCE_IDS = {
    "analytics_ai",
    "audit_cost",
    "aws_native_recommendations",
    "cost",
    "dynamodb",
    "ec2",
    "network",
    "observability",
    "platform",
    "security_governance",
    "service_coverage",
    "service_quotas",
    "serverless",
    "storage",
    "tagging",
    "utilization",
}


class ScannerDiscoveryRegistry:
    """Discover scanner definitions from deterministic built-in sources."""

    def __init__(self, sources: Iterable[ScannerDefinitionSource]) -> None:  # noqa: D107
        self._sources = tuple(sources)

    def discover_definitions(self) -> dict[str, ScannerDefinition]:  # noqa: D102
        discovered: dict[str, ScannerDefinition] = {}
        source_by_scanner_id: dict[str, str] = {}

        for source in self._sources:
            for scanner_id, definition in source.definitions.items():
                self._validate_definition_key(source, scanner_id, definition)
                if scanner_id in discovered:
                    first_source = source_by_scanner_id[scanner_id]
                    msg = f"Duplicate scanner ID discovered: {scanner_id} from {first_source} and {source.source_id}."
                    raise ValueError(
                        msg,
                    )
                discovered[scanner_id] = definition
                source_by_scanner_id[scanner_id] = source.source_id

        if self._uses_builtin_permission_metadata_sources():
            from unio_collector.scanners.registry.iam_requirements import (  # noqa: PLC0415
                attach_explicit_scanner_iam_requirements,
            )

            return attach_explicit_scanner_iam_requirements(discovered)
        return discovered

    def _validate_definition_key(
        self,
        source: ScannerDefinitionSource,
        scanner_id: str,
        definition: ScannerDefinition,
    ) -> None:
        if scanner_id == definition.scanner_id:
            return
        msg = f"Scanner definition key mismatch in {source.source_id}: {scanner_id} maps to {definition.scanner_id}."
        raise ValueError(
            msg,
        )

    def _uses_builtin_permission_metadata_sources(self) -> bool:
        return bool(self._sources) and all(source.source_id in BUILT_IN_PERMISSION_METADATA_SOURCE_IDS for source in self._sources)
