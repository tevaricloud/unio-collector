from __future__ import annotations  # noqa: D100

from typing import Protocol

from unio_collector.scan_workflow.runner.merge_contract import (
    ScannerChildMergeRuntimeContract,
)
from unio_collector.scan_workflow.scanner.runner_parent_contract import (
    ScannerChildRunnerParentContract,
)


class ScannerScheduleHelperRuntimeContract(
    ScannerChildRunnerParentContract,
    ScannerChildMergeRuntimeContract,
    Protocol,
):
    """Runner fields required for scheduler helper child creation and merge."""
