"""Bounded stage interruption preserves diagnostics without success claims."""

from __future__ import annotations

import json
import signal
import subprocess
import sys
import time
from typing import TYPE_CHECKING

import pytest

from tools.collector_repository.process import STAGE_TIMEOUT_SECONDS, VALIDATION_DRIVER_TIMEOUT_SECONDS, RepositoryProcess

if TYPE_CHECKING:
    from pathlib import Path


def test_timeout_terminates_child_and_retains_log(tmp_path: Path) -> None:
    """An over-budget synthetic Python stage fails with final retained metadata."""
    timeout = 0.5
    process = RepositoryProcess(tmp_path, tmp_path)
    command = [sys.executable, "-u", "-c", "import time; print('synthetic stage started'); time.sleep(30)"]
    with pytest.raises(RuntimeError, match="timed-out"):
        process.run("native-build", command, cwd=tmp_path, timeout_seconds=timeout)
    row = process.steps[-1]
    assert row["status"] == "timed-out"
    assert row["exit_code"] != 0
    assert row["timeout_seconds"] == timeout
    assert "synthetic stage started" in (tmp_path / "native-build.log").read_text()
    assert json.loads((tmp_path / "process-progress.json").read_text())["steps"] == process.steps


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, InterruptedError])
def test_cancellation_stops_child_and_restores_handlers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, interruption: type[BaseException]) -> None:
    """Runner interruption cannot turn into success or leave a sleeping task child."""
    original = subprocess.Popen.wait
    handler = signal.getsignal(signal.SIGTERM)
    interrupted = False

    def wait(child: subprocess.Popen[bytes], timeout: float | None = None) -> int:
        nonlocal interrupted
        if not interrupted:
            interrupted = True
            raise interruption()
        return original(child, timeout=timeout)

    monkeypatch.setattr(subprocess.Popen, "wait", wait)
    process = RepositoryProcess(tmp_path, tmp_path)
    with pytest.raises(RuntimeError, match="cancelled"):
        process.run("native-build", [sys.executable, "-c", "import time; time.sleep(30)"], cwd=tmp_path)
    assert process.steps[-1]["status"] == "cancelled"
    assert process.steps[-1]["exit_code"] is not None
    assert signal.getsignal(signal.SIGTERM) == handler


def test_stage_budgets_preserve_diagnostic_margin() -> None:
    """Long source tests and native phases have separate bounded budgets."""
    assert STAGE_TIMEOUT_SECONDS["tests"] == 345 * 60
    assert sum(STAGE_TIMEOUT_SECONDS[name] for name in ("native-build", "native-installer", "native-malware")) < 105 * 60


def test_timeout_stops_descendant_tree(tmp_path: Path) -> None:
    """A stage timeout stops nested Python work, not only its direct parent."""
    marker = tmp_path / "descendant-completed"
    descendant = f"import time; print('descendant ready', flush=True); time.sleep(1.5); open({str(marker)!r}, 'w').write('unexpected')"
    parent = f"import subprocess,sys,time; subprocess.Popen([sys.executable,'-u','-c',{descendant!r}]); time.sleep(30)"
    process = RepositoryProcess(tmp_path, tmp_path)
    with pytest.raises(RuntimeError, match="timed-out"):
        process.run("native-build", [sys.executable, "-u", "-c", parent], cwd=tmp_path, timeout_seconds=0.7)
    assert "descendant ready" in (tmp_path / "native-build.log").read_text()
    time.sleep(2)
    assert not marker.exists()


def test_job_deadline_stops_before_launch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Setup time cannot consume the reserved post-validation diagnostic window."""
    monkeypatch.setenv("UNIO_VALIDATION_DEADLINE_EPOCH", "1")
    process = RepositoryProcess(tmp_path, tmp_path)
    with pytest.raises(RuntimeError, match="budget expired"):
        process.run("tests", [str(tmp_path / "must-not-launch")], cwd=tmp_path)
    assert process.steps[-1]["status"] == "timed-out"
    assert process.steps[-1]["exit_code"] is None
    assert not (tmp_path / "tests.log").exists()


def test_export_driver_has_source_budget(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The outer source-validation driver must not get a ten-minute child-stage cap."""
    monkeypatch.delenv("UNIO_VALIDATION_DEADLINE_EPOCH", raising=False)
    process = RepositoryProcess(tmp_path, tmp_path)
    process.run("synthetic-driver", [sys.executable, "-c", "pass"], cwd=tmp_path)
    assert process.steps[-1]["timeout_seconds"] == VALIDATION_DRIVER_TIMEOUT_SECONDS
