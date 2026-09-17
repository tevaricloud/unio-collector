from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.scanners.scanner.evidence_serializer import (
    build_scanner_evidence_payload,
    require_serialized_scanner_evidence,
)
from unio_collector.scanners.scanner.implementation import ScannerImplementation

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext
    from unio_collector.scanners.scanner.definition import ScannerDefinition
    from unio_collector.scanners.scanner.hooks import ScannerAnalysisContract


class BaseUnioScanner:  # noqa: D101
    def __init__(self, metadata: ScannerDefinition) -> None:  # noqa: D107
        self.metadata = metadata

    def prepare(self, context: ScannerContext) -> None:  # noqa: D102
        del context

    def collect(self, context: ScannerContext) -> object:  # noqa: D102
        del context
        return None

    def analyze(self, evidence: object, context: ScannerContext) -> object:  # noqa: D102
        raise NotImplementedError

    def run[ResultT](self: ScannerAnalysisContract[ResultT], context: ScannerContext) -> ResultT:  # noqa: D102
        context.raise_if_cancelled()
        self.prepare(context)
        context.raise_if_cancelled()
        evidence = self.collect(context)
        context.raise_if_cancelled()
        payload = build_scanner_evidence_payload(scanner_id=self.metadata.scanner_id, evidence=evidence)
        require_serialized_scanner_evidence(payload)
        context.record_scanner_evidence_payload(self.metadata.scanner_id, payload)
        context.raise_if_cancelled()
        return self.analyze(evidence, context)

    def describe_implementation(self) -> ScannerImplementation:  # noqa: D102
        return ScannerImplementation(
            implementation_type="native",
            implementation_class=self.__class__.__name__,
            implementation_module=self.__class__.__module__,
        )
