"""Exact candidate identity from authenticated GitHub metadata."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import tomllib
from typing import TYPE_CHECKING, Any

from tools.collector_repository.identity import canonical_json
from tools.collector_repository.paths import require

if TYPE_CHECKING:
    from tools.test_packages.api import GitHubReadClient

MERGE_PARENTS = 2

ENVIRONMENT = "unsigned-pr-test-packages"
LABEL = "retain-unsigned-test"
WORKFLOW = ".github/workflows/native.yml"
TARGETS = {"windows-x86_64": ("windows-2022", 2), "linux-x86_64": ("ubuntu-22.04", 2), "macos-x86_64": ("macos-15-intel", 4), "macos-arm64": ("macos-15", 2)}


def digest(value: object) -> str:
    """Hash canonical structured context."""
    return hashlib.sha256(canonical_json(value)).hexdigest()


def sha(value: object) -> str:
    """Require a full lowercase Git identity."""
    require(isinstance(value, str) and re.fullmatch(r"[a-f0-9]{40}", value) is not None, "Invalid commit identity.")
    return str(value)


class CandidateContext:
    """Construct and recheck a PR snapshot without treating packet claims as API facts."""

    def __init__(self, api: GitHubReadClient) -> None:
        """Bind the authenticated transport and explicit source context."""
        self.api = api

    def capture(self, run_id: int, attempt: int, event: dict[str, Any], checkout: str, workflow: str, control: str) -> dict[str, Any]:
        """Create a fresh approval challenge for exactly this attempt."""
        pr = event["pull_request"]
        context = {
            "schema_version": 1,
            "repository": self.api.repository,
            "run_id": run_id,
            "attempt": attempt,
            "pr": pr["number"],
            "head": sha(pr["head"]["sha"]),
            "base": sha(pr["base"]["sha"]),
            "checkout": sha(checkout),
            "workflow_sha": sha(workflow),
            "control_sha": sha(control),
            "nonce": secrets.token_hex(32),
        }
        self.verify(context)
        commit = self.api.get(self.api.prefix + f"git/commits/{checkout}")
        context["tree"] = sha(commit["tree"]["sha"])
        provenance = json.loads(self.api.file("export-provenance.json", checkout))
        context["private_source"] = sha(provenance["source_sha"])
        context["projection"] = provenance["tree_digest"]
        context["workflow_hash"] = hashlib.sha256(self.api.file(WORKFLOW, workflow)).hexdigest()
        context["version"] = tomllib.loads(self.api.file("pyproject.toml", checkout).decode())["project"]["version"]
        return context

    def verify(self, context: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        """Reject changed candidates, forks, bots, drafts and incorrect attempts."""
        initial = {"schema_version", "repository", "run_id", "attempt", "pr", "head", "base", "checkout", "workflow_sha", "control_sha", "nonce"}
        complete = initial | {"tree", "private_source", "projection", "workflow_hash", "version"}
        require(
            set(context) in (initial, complete) and context["schema_version"] == 1 and type(context["pr"]) is int and context["pr"] > 0,
            "Invalid candidate schema.",
        )
        for name in ("head", "base", "checkout", "workflow_sha", "control_sha"):
            sha(context[name])
        if set(context) == complete:
            sha(context["tree"])
            sha(context["private_source"])
            require(
                re.fullmatch(r"[a-f0-9]{64}", context["projection"]) is not None
                and re.fullmatch(r"[a-f0-9]{64}", context["workflow_hash"]) is not None
                and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", context["version"]) is not None,
                "Invalid candidate projection/configuration.",
            )
        require(context["repository"] == self.api.repository, "Repository mismatch.")
        require(type(context["run_id"]) is int and type(context["attempt"]) is int and context["attempt"] > 0, "Invalid run/attempt.")
        require(re.fullmatch(r"[a-f0-9]{64}", context["nonce"]) is not None, "Invalid approval nonce.")
        run = self.api.get(self.api.prefix + f"actions/runs/{context['run_id']}/attempts/{context['attempt']}")
        pr = self.api.get(self.api.prefix + f"pulls/{context['pr']}")
        latest = self.api.get(self.api.prefix + f"actions/runs/{context['run_id']}")
        require(
            latest["run_attempt"] == context["attempt"] and run["run_attempt"] == context["attempt"] and run["id"] == context["run_id"], "Stale run attempt."
        )
        snapshots = run["pull_requests"]
        require(
            len(snapshots) == 1
            and snapshots[0]["number"] == context["pr"]
            and snapshots[0]["head"]["sha"] == context["head"]
            and snapshots[0]["base"]["sha"] == context["base"],
            "Run PR snapshot mismatch.",
        )
        require(run["actor"]["type"] == run["triggering_actor"]["type"] == "User", "Automated approval context excluded.")
        require(
            run["repository"]["full_name"] == self.api.repository and run["event"] == "pull_request" and run["path"] == WORKFLOW, "Unapproved workflow context."
        )
        require(
            pr["head"]["repo"]["full_name"] == pr["base"]["repo"]["full_name"] == self.api.repository and not pr["draft"] and pr["user"]["type"] == "User",
            "Ineligible PR context.",
        )
        require(LABEL in {row["name"] for row in pr["labels"]}, "Retention was not requested.")
        require(pr["head"]["sha"] == run["head_sha"] == context["head"] and pr["base"]["sha"] == context["base"], "PR head/base changed.")
        require(pr["merge_commit_sha"] == context["checkout"], "Checkout differs from authenticated PR merge.")
        commit = self.api.get(self.api.prefix + f"git/commits/{sha(context['checkout'])}")
        require(
            {p["sha"] for p in commit["parents"]} == {context["head"], context["base"]} and len(commit["parents"]) == MERGE_PARENTS,
            "Checkout is not the exact reviewed PR merge.",
        )
        if "tree" in context:
            require(commit["tree"]["sha"] == context["tree"], "Checkout tree changed.")
        return run, pr
