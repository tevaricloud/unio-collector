from __future__ import annotations  # noqa: D100

from datetime import UTC, date, datetime
from typing import TYPE_CHECKING, Any

from unio_collector.collector.parity.result import AwsCollectionParityResult

if TYPE_CHECKING:
    from unio_collector.collector.parity.exception import AwsCollectionParityException
    from unio_collector.collector.parity.model import AwsCollectionCapabilityModel


class AwsCollectionParityValidator:
    """Compare path-neutral semantics and enforce narrow exception lifecycle."""

    def compare(
        self,
        core: AwsCollectionCapabilityModel,
        collector: AwsCollectionCapabilityModel,
        *,
        exceptions: tuple[AwsCollectionParityException, ...] = (),
        as_of: date | None = None,
    ) -> AwsCollectionParityResult:
        """Return deterministic differences after applying exact exceptions."""
        effective_date = as_of or datetime.now(UTC).date()
        differences = self._differences(core, collector)
        exception_errors = [error for item in exceptions for error in item.validation_errors(as_of=effective_date)]
        applied = []
        uncovered = []
        difference_keys = {(str(item["capability_id"]), str(item["dimension"])) for item in differences}
        for item in exceptions:
            key = (item.capability_id, item.dimension)
            if key not in difference_keys:
                exception_errors.append(
                    f"Stale parity exception does not match a current difference: {item.capability_id}/{item.dimension}.",
                )
        for difference in differences:
            matching = [
                item
                for item in exceptions
                if item.capability_id == difference["capability_id"]
                and item.dimension == difference["dimension"]
                and not item.validation_errors(as_of=effective_date)
            ]
            if matching:
                applied.append(matching[0])
            else:
                uncovered.append(difference)
        passed = not uncovered and not exception_errors
        return AwsCollectionParityResult(
            status="passed" if passed else "failed",
            differences=tuple(uncovered),
            applied_exceptions=tuple(
                sorted(
                    set(applied),
                    key=lambda item: (item.capability_id, item.dimension),
                ),
            ),
            exception_errors=tuple(sorted(exception_errors)),
            core_semantic_sha256=core.semantic_sha256(),
            collector_semantic_sha256=collector.semantic_sha256(),
        )

    def _differences(
        self,
        core: AwsCollectionCapabilityModel,
        collector: AwsCollectionCapabilityModel,
    ) -> list[dict[str, Any]]:
        differences: list[dict[str, Any]] = []
        self._append_difference(
            differences,
            capability_id="aws-runtime",
            dimension="configuration",
            core_value=core.configuration_fields,
            collector_value=collector.configuration_fields,
        )
        for dimension in sorted(
            set(core.execution_contract) | set(collector.execution_contract),
        ):
            self._append_difference(
                differences,
                capability_id="aws-runtime",
                dimension=dimension,
                core_value=core.execution_contract.get(dimension),
                collector_value=collector.execution_contract.get(dimension),
            )
        core_scanners = {item.scanner_id: item for item in core.scanners}
        collector_scanners = {item.scanner_id: item for item in collector.scanners}
        self._append_difference(
            differences,
            capability_id="aws-scanner-registry",
            dimension="scanner_ids",
            core_value=tuple(sorted(core_scanners)),
            collector_value=tuple(sorted(collector_scanners)),
        )
        dimensions = (
            "definition_source_id",
            "implementation_identity",
            "collection_callable",
            "evidence_return_annotation",
            "default_enabled",
            "supports_regions",
            "execution_phase",
            "dependencies",
            "operations",
            "permissions",
            "may_incur_charges",
            "chargeable_reason",
            "output_finding_types",
        )
        for scanner_id in sorted(set(core_scanners) & set(collector_scanners)):
            core_scanner = core_scanners[scanner_id]
            collector_scanner = collector_scanners[scanner_id]
            for dimension in dimensions:
                self._append_difference(
                    differences,
                    capability_id=scanner_id,
                    dimension=dimension,
                    core_value=getattr(core_scanner, dimension),
                    collector_value=getattr(collector_scanner, dimension),
                )
        return differences

    def _append_difference(
        self,
        differences: list[dict[str, Any]],
        *,
        capability_id: str,
        dimension: str,
        core_value: object,
        collector_value: object,
    ) -> None:
        if core_value == collector_value:
            return
        differences.append(
            {
                "capability_id": capability_id,
                "dimension": dimension,
                "core": self._json_value(core_value),
                "collector": self._json_value(collector_value),
            },
        )

    def _json_value(self, value: object) -> object:
        if isinstance(value, tuple):
            return [self._json_value(item) for item in value]
        if hasattr(value, "convert_to_dict"):
            return value.convert_to_dict()  # type: ignore[union-attr]
        return value


__all__ = ["AwsCollectionParityValidator"]
