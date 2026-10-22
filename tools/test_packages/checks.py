"""Authenticated complete workflow results and reviewed workflow/code bindings."""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Any

from tools.collector_repository.paths import require
from tools.test_packages.context import TARGETS, WORKFLOW
from tools.test_packages.workflow import workflow_bytes

if TYPE_CHECKING:
    from pathlib import Path

    from tools.test_packages.api import GitHubReadClient


class MatrixAcceptance:
    """Check server-side results independently of every retained packet."""

    def __init__(self, api: GitHubReadClient, trusted: Path) -> None:
        """Bind the authenticated transport and explicit source context."""
        self.api = api
        self.trusted = trusted

    def native(self, run: dict[str, Any], context: dict[str, Any]) -> dict[str, int]:
        """Require every source shard and native target from this exact attempt."""
        require(run["status"] == "completed" and run["conclusion"] == "success", "Native workflow did not pass.")
        jobs = self.api.rows(f"actions/runs/{context['run_id']}/attempts/{context['attempt']}/jobs", "jobs")
        expected = {f"native ({runner}, {target})" for target, (runner, _) in TARGETS.items()}
        expected |= {f"native source ({runner}, {target}, shard {number})" for target, (runner, _) in TARGETS.items() for number in range(2)}
        expected |= {"retention-request", "retention-approval"}
        require(
            len(jobs) == len(expected)
            and len({j["id"] for j in jobs}) == len(jobs)
            and {j["name"] for j in jobs} == expected
            and all(
                j["status"] == "completed" and j["conclusion"] == "success" and j["run_id"] == context["run_id"] and j["run_attempt"] == context["attempt"]
                for j in jobs
            ),
            "Missing/failed/ambiguous matrix job.",
        )
        return {target: next(j["id"] for j in jobs if j["name"] == f"native ({runner}, {target})") for target, (runner, _) in TARGETS.items()}

    def controls(self, context: dict[str, Any]) -> None:
        """Verify exact workflow and executable controller bytes against trusted local source."""
        expected = workflow_bytes(self.trusted)
        require(hashlib.sha256(expected).hexdigest() == context["workflow_hash"], "Unreviewed candidate workflow.")
        for commit in (context["workflow_sha"], context["checkout"], context["control_sha"]):
            require(self.api.file(WORKFLOW, commit).replace(b"\r\n", b"\n") == expected, "Workflow execution/control revision mismatch.")
        for file in sorted((self.trusted / "tools/test_packages").glob("*.py")):
            name = file.relative_to(self.trusted).as_posix()
            for commit in (context["control_sha"], context["checkout"]):
                require(
                    self.api.file(name, commit).replace(b"\r\n", b"\n") == file.read_bytes().replace(b"\r\n", b"\n"), "Unreviewed approval controller code."
                )

    def complementary(self, context: dict[str, Any], selected: dict[str, int]) -> dict[str, Any]:
        """Require explicitly selected Python/security runs for the same PR head and base."""
        result = {}
        require(set(selected) == {"python", "security"}, "Python/security run IDs required.")
        for name, run_id in selected.items():
            run = self.api.get(self.api.prefix + f"actions/runs/{run_id}")
            require(
                run["repository"]["full_name"] == self.api.repository
                and run["event"] == "pull_request"
                and run["path"] == f".github/workflows/{name}.yml"
                and run["head_sha"] == context["head"]
                and run["status"] == "completed"
                and run["conclusion"] == "success",
                "Complementary workflow mismatch.",
            )
            prs = run["pull_requests"]
            require(
                len(prs) == 1 and prs[0]["number"] == context["pr"] and prs[0]["head"]["sha"] == context["head"] and prs[0]["base"]["sha"] == context["base"],
                "Complementary PR context mismatch.",
            )
            jobs = self.api.rows(f"actions/runs/{run_id}/attempts/{run['run_attempt']}/jobs", "jobs")
            require(
                len(jobs) == 1
                and jobs[0]["name"] == name
                and jobs[0]["status"] == "completed"
                and jobs[0]["conclusion"] == "success"
                and jobs[0]["run_id"] == run_id
                and jobs[0]["run_attempt"] == run["run_attempt"],
                "Complementary job did not pass.",
            )
            local = self.trusted / (run["path"] if (self.trusted / "export-manifest.json").is_file() else f"tools/collector_export/assets/{name}.yml")
            require(
                self.api.file(run["path"], context["head"]).replace(b"\r\n", b"\n") == local.read_bytes().replace(b"\r\n", b"\n")
                and self.api.file(run["path"], context["workflow_sha"]).replace(b"\r\n", b"\n") == local.read_bytes().replace(b"\r\n", b"\n"),
                "Complementary workflow is not reviewed.",
            )
            result[name] = {"run_id": run_id, "attempt": run["run_attempt"], "job_id": jobs[0]["id"]}
        return result
