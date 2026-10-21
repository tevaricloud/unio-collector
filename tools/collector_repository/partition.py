"""Deterministic, exhaustive test partitions for independently budgeted jobs."""

from __future__ import annotations

import hashlib
from typing import Any

from tools.collector_repository.paths import require

MAX_TEST_SHARDS = 8


class TestPartition:
    """Bind each shard to the complete collected node inventory and its selection."""

    @staticmethod
    def select(nodes: list[str], index: int, count: int) -> dict[str, Any]:
        """Partition individual parametrized cases without changing their behaviour."""
        require(type(count) is int and 1 <= count <= MAX_TEST_SHARDS, "Invalid test shard count.")
        require(type(index) is int and 0 <= index < count, "Invalid test shard index.")
        require(bool(nodes) and all(isinstance(node, str) and node for node in nodes), "Empty or malformed test collection.")
        require(len(set(nodes)) == len(nodes), "Duplicate collected test identity.")
        ordered = sorted(nodes)
        selected = [node for node in ordered if int(hashlib.sha256(node.encode()).hexdigest(), 16) % count == index]
        require(bool(selected), "Empty test shard.")
        return {"index": index, "count": count, "collected": ordered, "selected": selected}

    @classmethod
    def validate(cls, report: dict[str, Any]) -> None:
        """Reject fabricated selections, malformed metadata and changed collections."""
        require(isinstance(report, dict) and set(report) == {"index", "count", "collected", "selected"}, "Malformed test partition.")
        require(isinstance(report["collected"], list), "Malformed test collection.")
        require(cls.select(report["collected"], report["index"], report["count"]) == report, "Test partition selection mismatch.")

    @classmethod
    def complete(cls, reports: list[dict[str, Any]], count: int) -> None:
        """Require every shard exactly once, common collection and exhaustive union."""
        require(type(count) is int and 1 <= count <= MAX_TEST_SHARDS and len(reports) == count, "Missing test shards.")
        for report in reports:
            cls.validate(report)
        require(sorted(report["index"] for report in reports) == list(range(count)), "Duplicate or missing test shard.")
        require(all(report["count"] == count and report["collected"] == reports[0]["collected"] for report in reports), "Test shard collection mismatch.")
        selected = [node for report in reports for node in report["selected"]]
        require(len(selected) == len(set(selected)) and sorted(selected) == reports[0]["collected"], "Incomplete or overlapping test coverage.")
