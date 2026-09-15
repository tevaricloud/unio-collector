from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from unio_collector.scan_workflow.scanner.runtime.cancellation import (
    ScannerCancellationToken,
)
from unio_collector.scanners.scanner.gateway.analysis import ScannerAnalysisGateway
from unio_collector.scanners.scanner.gateway.cloudwatch import ScannerCloudWatchGateway
from unio_collector.scanners.scanner.gateway.cost import ScannerCostGateway
from unio_collector.scanners.scanner.gateway.data import ScannerDataGateway
from unio_collector.scanners.scanner.gateway.ec2 import ScannerEc2Gateway
from unio_collector.scanners.scanner.gateway.finding import ScannerFindingGateway
from unio_collector.scanners.scanner.gateway.lambda_ import ScannerLambdaGateway
from unio_collector.scanners.scanner.gateway.network import ScannerNetworkGateway
from unio_collector.scanners.scanner.gateway.options import ScannerOptionsGateway
from unio_collector.scanners.scanner.gateway.s3 import ScannerS3Gateway
from unio_collector.scanners.scanner.gateway.security import ScannerSecurityGateway
from unio_collector.scanners.scanner.gateway.tagging import ScannerTaggingGateway
from unio_collector.scanners.scanner.gateway.warning import ScannerWarningGateway

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.definition import ScannerDefinition
    from unio_collector.scanners.scanner.runtime_protocol import ScannerRuntimeProtocol


@dataclass(frozen=True, init=False)
class ScannerContext:  # noqa: D101
    runtime: ScannerRuntimeProtocol
    definition: ScannerDefinition
    costs: ScannerCostGateway
    ec2: ScannerEc2Gateway
    network: ScannerNetworkGateway
    s3: ScannerS3Gateway
    cloudwatch: ScannerCloudWatchGateway
    tagging: ScannerTaggingGateway
    lambda_: ScannerLambdaGateway
    security: ScannerSecurityGateway
    warnings: ScannerWarningGateway
    options: ScannerOptionsGateway
    data: ScannerDataGateway
    findings: ScannerFindingGateway
    analysis: ScannerAnalysisGateway

    def __init__(  # noqa: D107
        self,
        *,
        runtime: ScannerRuntimeProtocol | None = None,
        definition: ScannerDefinition,
        runner: ScannerRuntimeProtocol | None = None,
    ) -> None:
        resolved_runtime = runtime or runner
        if resolved_runtime is None:
            msg = "ScannerContext requires a runtime."
            raise ValueError(msg)
        object.__setattr__(self, "runtime", resolved_runtime)
        object.__setattr__(self, "definition", definition)
        object.__setattr__(
            self,
            "costs",
            ScannerCostGateway(resolved_runtime, definition),
        )
        object.__setattr__(
            self,
            "ec2",
            ScannerEc2Gateway(resolved_runtime, definition),
        )
        object.__setattr__(
            self,
            "network",
            ScannerNetworkGateway(resolved_runtime, definition),
        )
        object.__setattr__(
            self,
            "s3",
            ScannerS3Gateway(resolved_runtime, definition),
        )
        object.__setattr__(
            self,
            "cloudwatch",
            ScannerCloudWatchGateway(resolved_runtime, definition),
        )
        object.__setattr__(
            self,
            "tagging",
            ScannerTaggingGateway(resolved_runtime, definition),
        )
        object.__setattr__(
            self,
            "lambda_",
            ScannerLambdaGateway(resolved_runtime, definition),
        )
        object.__setattr__(
            self,
            "security",
            ScannerSecurityGateway(resolved_runtime, definition),
        )
        object.__setattr__(
            self,
            "warnings",
            ScannerWarningGateway(resolved_runtime, definition),
        )
        object.__setattr__(
            self,
            "options",
            ScannerOptionsGateway(resolved_runtime, definition),
        )
        object.__setattr__(
            self,
            "data",
            ScannerDataGateway(resolved_runtime, definition),
        )
        object.__setattr__(
            self,
            "findings",
            ScannerFindingGateway(resolved_runtime, definition),
        )
        object.__setattr__(
            self,
            "analysis",
            ScannerAnalysisGateway(resolved_runtime, definition),
        )

    @property
    def runner(self) -> ScannerRuntimeProtocol:
        """Compatibility alias; new scanner code should use runtime or gateways."""
        return self.runtime

    @property
    def cancellation_token(self) -> ScannerCancellationToken:
        """Return cooperative scanner cancellation and deadline state."""
        token = getattr(self.runtime, "cancellation_token", None)
        if isinstance(token, ScannerCancellationToken):
            return token
        return ScannerCancellationToken()

    def is_cancelled(self) -> bool:
        """Return whether the scanner has been cancelled."""
        checker = getattr(self.runtime, "is_cancelled", None)
        if callable(checker):
            return bool(checker())
        return False

    def raise_if_cancelled(self) -> None:
        """Raise when scanner work should stop."""
        checker = getattr(self.runtime, "raise_if_cancelled", None)
        if callable(checker):
            checker()

    def time_remaining_seconds(self) -> float | None:
        """Return remaining scanner deadline budget, if configured."""
        reader = getattr(self.runtime, "time_remaining_seconds", None)
        if callable(reader):
            value = reader()
            if isinstance(value, int | float):
                return float(value)
        return None

    def record_scanner_evidence_payload(  # noqa: D102
        self,
        scanner_id: str,
        payload: dict[str, Any],
    ) -> None:
        recorder = getattr(self.runtime, "record_scanner_evidence_payload", None)
        if callable(recorder):
            recorder(scanner_id, payload)
