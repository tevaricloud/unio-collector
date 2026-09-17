from __future__ import annotations  # noqa: D100

from collections.abc import Callable

from unio_collector.scanners.scanner.types import ScannerExecutionPhase

ScannerPhaseResolver = Callable[[str], ScannerExecutionPhase | str]
ScannerDependencyResolver = Callable[[str], tuple[str, ...]]

VALID_EXECUTION_PHASES: tuple[ScannerExecutionPhase, ...] = (
    "baseline",
    "independent",
    "dependent",
)

PHASE_STAGE_NAMES: dict[ScannerExecutionPhase, str] = {
    "baseline": "cost-baseline",
    "independent": "independent-scanners",
    "dependent": "dependent-scanners",
}
