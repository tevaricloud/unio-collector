"""Bounded public diagnostics extracted from pytest's existing duration table."""

from __future__ import annotations

import os
import platform
import re
import sys
from typing import TYPE_CHECKING

from tools.collector_repository.identity import canonical_json

if TYPE_CHECKING:
    from pathlib import Path

MAX_LOG_BYTES = 8 * 1024 * 1024
MAX_OUTPUT_BYTES = 32 * 1024
MAX_ROWS = 20
MAX_LINE_LENGTH = 4096
MAX_IDENTITY_LENGTH = 512
ASCII_SPACE = 32
ASCII_TILDE = 126
HEADER = re.compile(r"=+ slowest 20 durations =+")
ROW = re.compile(r"([0-9]{1,6}\.[0-9]{1,6})s (setup|call|teardown) +(.+)")
IDENTITY = re.compile(r"tests/standalone/(?:[A-Za-z0-9_]+/)*test_[A-Za-z0-9_]+\.py::[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*")
END = re.compile(r"(?:=+ )?(?:[0-9]+ (?:passed|failed|skipped|deselected|xfailed|xpassed|errors?|warnings?)(?:, )?)+ in [0-9.]+s(?: \([0-9:]+\))?(?: =+)?")
HIDDEN = re.compile(r"\([0-9]+ durations? < [0-9.]+s hidden\.  Use -vv to show these durations\.\)")


class PytestDurationDiagnostics:
    """Retain observations without making timing collection an acceptance gate."""

    def extract(self, content: bytes) -> dict[str, object]:
        """Reject untrusted rows; never retain raw output or parameter values."""
        rows: list[dict[str, object]] = []
        result: dict[str, object] = {
            "schema_version": 1,
            "scope": "top-20 observations; not complete suite accounting",
            "parameter_values": "omitted; rows may share a test identity",
            "worker_attribution": None,
            "status": "absent",
            "observations": rows,
        }
        if len(content) > MAX_LOG_BYTES:
            result["status"] = "incomplete"
            return result
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            result["status"] = "incomplete"
            return result
        result["status"] = self._table(text, rows)
        return result

    def _table(self, text: str, rows: list[dict[str, object]]) -> str:
        found = False
        invalid = False
        ended = False
        hidden = False
        for raw in text.split("\n"):
            line = raw.removesuffix("\r")
            if HEADER.fullmatch(line):
                if found:
                    invalid = True
                found = True
                continue
            if not found:
                continue
            if END.fullmatch(line):
                ended = True
                break
            if not line or HIDDEN.fullmatch(line):
                hidden = hidden or bool(HIDDEN.fullmatch(line))
                continue
            row = self._row(line)
            if row is None or len(rows) >= MAX_ROWS:
                invalid = True
            else:
                rows.append(row)
        if not found:
            return "absent"
        return "extracted" if ended and not invalid and (rows or hidden) else "incomplete"

    @staticmethod
    def _row(line: str) -> dict[str, object] | None:
        if len(line) > MAX_LINE_LENGTH or any(ord(char) < ASCII_SPACE or ord(char) > ASCII_TILDE for char in line):
            return None
        match = ROW.fullmatch(line)
        if match is None:
            return None
        seconds, phase, node = match.groups()
        identity, separator, parameters = node.partition("[")
        if separator and not parameters.endswith("]"):
            return None
        if len(identity) > MAX_IDENTITY_LENGTH or IDENTITY.fullmatch(identity) is None:
            return None
        return {"seconds": float(seconds), "phase": phase, "test": identity}

    def retain(
        self,
        output: Path,
        *,
        source_sha: str | None,
        export: dict[str, object] | None,
        workers: int,
        shard: int,
        shards: int,
        enabled: bool = True,
    ) -> None:
        """Write a filtered sidecar; callers isolate all diagnostic failures."""
        if not enabled:
            return
        log = output / "tests.log"
        if log.is_symlink():
            result = self.extract(b"\xff")
        else:
            try:
                with log.open("rb") as stream:
                    result = self.extract(stream.read(MAX_LOG_BYTES + 1))
            except FileNotFoundError:
                result = self.extract(b"")
        provenance = export or {}
        result["provenance"] = {
            "validation_source_sha": self._hex(source_sha, 40),
            "github_checkout_sha": self._hex(os.environ.get("GITHUB_SHA"), 40),
            "verified_export_at_start_source_sha": self._hex(provenance.get("source_sha"), 40),
            "verified_export_at_start_tree_digest": self._hex(provenance.get("tree_digest"), 64),
            "validator_python": platform.python_version(),
            "platform": sys.platform if sys.platform in {"win32", "linux", "darwin"} else None,
            "machine": platform.machine().lower() if platform.machine().lower() in {"amd64", "x86_64", "arm64", "aarch64"} else None,
            "configured_workers": workers,
            "shard_index": shard,
            "shard_count": shards,
            "github_run_id": self._digits(os.environ.get("GITHUB_RUN_ID")),
            "github_run_attempt": self._digits(os.environ.get("GITHUB_RUN_ATTEMPT")),
        }
        content = canonical_json(result)
        if len(content) <= MAX_OUTPUT_BYTES:
            (output / "pytest-durations.json").write_bytes(content)

    @staticmethod
    def _hex(value: object, length: int) -> str | None:
        return value if isinstance(value, str) and re.fullmatch(rf"[0-9a-f]{{{length}}}", value) else None

    @staticmethod
    def _digits(value: str | None) -> str | None:
        return value if value is not None and re.fullmatch(r"[0-9]{1,20}", value) else None
