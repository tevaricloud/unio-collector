"""Explicit local trust anchor, separate from every downloaded artifact."""

from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING

from tools.collector_repository.paths import require
from tools.test_packages.context import sha
from tools.test_packages.executables import host_executable

if TYPE_CHECKING:
    from pathlib import Path


class TrustedCheckout:
    """Require an explicitly reviewed clean source commit before API or artifact access."""

    def verify(self, root: Path, commit: str) -> None:
        """Never accept a trust SHA or executable module supplied by the packet."""
        sha(commit)
        actual = subprocess.check_output([str(host_executable("git")), "rev-parse", "HEAD"], cwd=root, text=True).strip()  # noqa: S603
        status = subprocess.check_output([str(host_executable("git")), "status", "--porcelain", "--untracked-files=all"], cwd=root, text=True).strip()  # noqa: S603
        ignored = subprocess.check_output(  # noqa: S603
            [str(host_executable("git")), "ls-files", "--others", "--ignored", "--exclude-standard"], cwd=root, text=True
        ).splitlines()
        require(not any(name.casefold().endswith((".py", ".pyc", ".pyd", ".dll", ".exe")) for name in ignored), "Ignored executable code in trusted source.")
        require(actual == commit and not status, "Selector requires the explicitly reviewed clean local source.")
