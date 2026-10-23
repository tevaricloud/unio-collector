"""Authenticated, read-only GitHub transport with bounded responses."""

from __future__ import annotations

import base64
import json
import re
import subprocess
from typing import TYPE_CHECKING, Any, cast

from tools.collector_repository.paths import require
from tools.test_packages.executables import host_executable

if TYPE_CHECKING:
    from pathlib import Path

PAGE_SIZE = 100

MAX_DOWNLOAD = 2 * 1024**3


class GitHubReadClient:
    """Use existing gh authentication; never send a GitHub mutation."""

    def __init__(self, repository: str) -> None:
        """Bind the authenticated transport and explicit source context."""
        require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is not None, "Invalid repository.")
        self.repository = repository
        self.prefix = f"repos/{repository}/"

    def _read(self, route: str) -> object:
        """Read authenticated JSON without accepting arbitrary URLs."""
        require(route == "user" or route.startswith(self.prefix), "Foreign API route.")
        result = subprocess.run([str(host_executable("gh")), "api", "--method", "GET", route], capture_output=True, check=True, timeout=120)  # noqa: S603
        require(len(result.stdout) <= 16 * 1024**2, "Oversized API response.")
        return json.loads(result.stdout)

    def get(self, route: str) -> dict[str, Any]:
        """Read an authenticated JSON object, rejecting unexpected response shapes."""
        result = self._read(route)
        require(isinstance(result, dict), "Expected API object.")
        return cast("dict[str, Any]", result)

    def reviews(self, run_id: int) -> list[dict[str, Any]]:
        """Read protected-environment review history as authenticated records."""
        result = self._read(self.prefix + f"actions/runs/{run_id}/approvals")
        require(isinstance(result, list) and all(isinstance(row, dict) for row in result), "Expected review records.")
        return cast("list[dict[str, Any]]", result)

    def rows(self, suffix: str, key: str) -> list[dict[str, Any]]:
        """Read every page; refuse incomplete or excessive result sets."""
        rows: list[dict[str, Any]] = []
        for page in range(1, 21):
            result = self.get(self.prefix + suffix + f"?per_page=100&page={page}")
            batch = result[key]
            require(isinstance(batch, list), "Malformed API page.")
            rows.extend(batch)
            if len(batch) < PAGE_SIZE:
                require(len(rows) == result["total_count"], "Incomplete API pagination.")
                return rows
        message = "API pagination limit exceeded."
        raise ValueError(message)

    def file(self, name: str, commit: str) -> bytes:
        """Read a regular Git blob through the authenticated contents endpoint."""
        from urllib.parse import quote  # noqa: PLC0415

        row = self.get(self.prefix + f"contents/{quote(name, safe='/')}?ref={quote(commit, safe='')}")
        require(row.get("type") == "file" and row.get("encoding") == "base64" and row.get("size", MAX_DOWNLOAD) < 1024**2, "Unsupported source blob.")
        return base64.b64decode(row["content"])

    def download(self, artifact: dict[str, Any], destination: Path) -> None:
        """Download an explicit artifact ID with a timeout and authenticated size limit."""
        require(type(artifact.get("id")) is int and 0 < artifact["size_in_bytes"] <= MAX_DOWNLOAD, "Invalid artifact size/identity.")
        with destination.open("xb") as output:
            result = subprocess.run(  # noqa: S603
                [str(host_executable("gh")), "api", "--method", "GET", self.prefix + f"actions/artifacts/{artifact['id']}/zip"],
                stdout=output,
                stderr=subprocess.PIPE,
                check=True,
                timeout=180,
            )
        require(result.returncode == 0 and destination.stat().st_size <= MAX_DOWNLOAD, "Artifact download exceeded limit.")
