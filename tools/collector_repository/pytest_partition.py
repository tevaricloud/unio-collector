"""Pytest collection hook retaining complete, deterministic shard witnesses."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from tools.collector_repository.identity import canonical_json, read_json
from tools.collector_repository.partition import TestPartition
from tools.collector_repository.paths import require


@pytest.hookimpl(trylast=True)
def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Record the complete collection before selecting the configured shard."""
    index = int(os.environ["UNIO_TEST_SHARD_INDEX"])
    count = int(os.environ["UNIO_TEST_SHARD_COUNT"])
    report = TestPartition.select([item.nodeid for item in items], index, count)
    worker = getattr(config, "workerinput", {}).get("workerid", "controller")
    directory = Path(os.environ["UNIO_TEST_SHARD_OUTPUT"])
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{worker}.json").write_bytes(canonical_json(report))
    selected = set(report["selected"])
    deselected = [item for item in items if item.nodeid not in selected]
    items[:] = [item for item in items if item.nodeid in selected]
    config.hook.pytest_deselected(items=deselected)


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Only successful controller completion may seal worker collection evidence."""
    if hasattr(session.config, "workerinput") or exitstatus != 0:
        return
    directory = Path(os.environ["UNIO_TEST_SHARD_OUTPUT"])
    reports = [read_json(path) for path in sorted(directory.glob("*.json")) if path.name != "partition.json"]
    require(bool(reports) and all(report == reports[0] for report in reports), "Worker test collections disagree or are missing.")
    TestPartition.validate(reports[0])
    (directory / "partition.json").write_bytes(canonical_json(reports[0]))
