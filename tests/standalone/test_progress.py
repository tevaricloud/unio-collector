"""Offline progress and authoritative protection gates in every public target."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, call

import pytest

from tools.build_native_collector import _add_synthetic_region_scope
from unio_collector.collector_cli.app import main
from unio_collector.collector_launcher.controller import LauncherController
from unio_collector.collector_launcher.feedback import ProtectionFeedback
from unio_collector.collector_launcher.protection import ProtectionOperation
from unio_collector.collector_launcher.stage import ProtectionStage

pytestmark = pytest.mark.offline
FIXTURES = Path(__file__).parent / "fixtures"


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_real_producer_protection_requires_independent_validation_and_receipt(tmp_path: Path, profile: str) -> None:
    """Run the exported CLI through the same coordinator used by the GUI."""
    source = tmp_path / "source.zip"
    assert main(["collect", "--fixture", str(FIXTURES / "cost.json"), "--output", str(source), "--quiet"]) == 0
    _add_synthetic_region_scope(source, FIXTURES / "region-scope.json")
    controller = LauncherController((sys.executable, "-B", "-m", main.__module__))
    output = tmp_path / "protected.zip"
    argv = controller.protect_argv(bundle=source, output=output, vault=tmp_path / "private/vault.json", profile=profile)
    stages: list[ProtectionStage] = []
    result = ProtectionOperation(controller, argv, "synthetic-test-only-input\n", stages.append)()
    assert result.exit_code == 0, result.output
    assert stages == list(ProtectionStage)
    assert output.with_suffix(".zip.receipt.json").exists()


@pytest.mark.parametrize("exit_code", [0, 1, 130])
def test_long_progress_never_floods_transcript_or_guesses_percent(exit_code: int) -> None:
    """The public native validation checks exact progress contracts on every OS."""
    root, status, bar, output = (MagicMock() for _ in range(4))
    busy = [True]
    feedback = ProtectionFeedback(root, status, bar, output, lambda: busy[0])
    generation = object()
    feedback.start(generation)
    for _ in range(600):
        feedback.tick(generation)
    output.assert_called_once_with("Protection started.")
    assert feedback.progress.percentage is None
    bar.configure.assert_called_once_with(mode="indeterminate", value=0)
    feedback.finish(exit_code, generation)
    assert feedback.progress.state == {0: "completed", 1: "failed", 130: "cancelled"}[exit_code]
    assert bar.configure.call_args.kwargs["value"] == (100 if exit_code == 0 else 0)
    count = status.set.call_count
    feedback.tick(generation)
    assert status.set.call_count == count


def test_cancellation_request_remains_distinct_and_is_not_repeated() -> None:
    """A stage update cannot erase a pending request or claim completion."""
    root, status, bar, output = (MagicMock() for _ in range(4))
    feedback = ProtectionFeedback(root, status, bar, output, lambda: True)
    feedback.start(object())
    operation = MagicMock()
    assert feedback.cancel(operation)
    assert feedback.cancel(operation)
    operation.cancel.assert_called_once_with()
    assert feedback.progress.state == "cancellation requested"
    feedback.progress.advance(ProtectionStage.RECEIPT)
    assert feedback.progress.state == "cancellation requested"
    assert feedback.progress.percentage is None
    assert output.call_args_list == [call("Protection started."), call("Protection cancellation requested.")]
