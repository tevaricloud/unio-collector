"""Bind retained artifact IDs, digests and expiry to one authenticated attempt."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from tools.collector_repository.paths import require
from tools.test_packages.archive import SafeArtifactArchive

if TYPE_CHECKING:
    from pathlib import Path

    from tools.test_packages.api import GitHubReadClient


class ArtifactTransport:
    """Download only explicit run-bound artifacts using existing authentication."""

    def __init__(self, api: GitHubReadClient, run: dict[str, Any]) -> None:
        """Bind the authenticated transport and explicit source context."""
        self.api = api
        self.run = run
        self.artifacts = api.rows(f"actions/runs/{run['id']}/artifacts", "artifacts")

    def fetch(self, name: str, destination: Path) -> tuple[Path, dict[str, str], dict[str, Any]]:
        """Verify server metadata and ZIP digest before inspecting any members."""
        matches = [a for a in self.artifacts if a["name"] == name]
        require(len(matches) == 1, "Missing or ambiguous retained artifact.")
        artifact = matches[0]
        parse = datetime.fromisoformat
        require(artifact.get("expired") is False and parse(artifact["expires_at"]) > datetime.now(UTC), "Artifact expired.")
        require(
            parse(artifact["created_at"]) >= parse(self.run["run_started_at"])
            and parse(artifact["expires_at"]) - parse(artifact["created_at"]) >= timedelta(days=7, seconds=-60),
            "Artifact is not retained for this attempt's full period.",
        )
        require(
            artifact["workflow_run"]["id"] == self.run["id"] and artifact["workflow_run"]["head_sha"] == self.run["head_sha"], "Artifact run/head mismatch."
        )
        archive = destination / f"artifact-{artifact['id']}.zip"
        self.api.download(artifact, archive)
        with archive.open("rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        require(artifact.get("digest") == "sha256:" + actual, "Authenticated artifact digest mismatch.")
        return archive, SafeArtifactArchive().inspect(archive), artifact
