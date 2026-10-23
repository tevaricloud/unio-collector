"""Request and verify approval without occupying a packaging runner."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

from tools.collector_repository.identity import canonical_json, read_json
from tools.collector_repository.paths import require
from tools.test_packages.approval import RetentionApproval
from tools.test_packages.context import WORKFLOW, CandidateContext, digest
from tools.test_packages.trust import TrustedCheckout

if TYPE_CHECKING:
    from tools.test_packages.api import GitHubReadClient


def workflow_bytes(root: Path) -> bytes:
    """Find the reviewed public workflow in a private or exported control checkout."""
    file = root / (WORKFLOW if (root / "export-manifest.json").is_file() else "tools/collector_export/assets/native.yml")
    return file.read_bytes().replace(b"\r\n", b"\n")


class RetentionWorkflow:
    """Keep labels, protected reviews and candidate identity as distinct controls."""

    def __init__(self, api: GitHubReadClient, root: Path) -> None:
        """Bind the authenticated transport and explicit source context."""
        self.api = api
        self.root = root

    def request(self, event: Path, output: Path, control: str) -> dict[str, Any]:
        """Fail closed before creating the protected job when configuration is inadequate."""
        TrustedCheckout().verify(self.root, control)
        context = CandidateContext(self.api).capture(
            int(os.environ["GITHUB_RUN_ID"]),
            int(os.environ["GITHUB_RUN_ATTEMPT"]),
            read_json(event),
            os.environ["GITHUB_SHA"],
            os.environ["GITHUB_WORKFLOW_SHA"],
            control,
        )
        require(context["workflow_hash"] == hashlib.sha256(workflow_bytes(self.root)).hexdigest(), "Workflow differs from reviewed control.")
        require(
            self.api.file(WORKFLOW, context["checkout"]) == self.api.file(WORKFLOW, context["workflow_sha"]),
            "Workflow execution revision differs from candidate.",
        )
        environment = RetentionApproval(self.api).configuration()
        request = {"context": context, "environment": environment}
        output.mkdir(parents=True, exist_ok=False)
        (output / "request.json").write_bytes(canonical_json(request))
        challenge = "UNIO-TEST-APPROVE " + digest(request)
        with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a", encoding="utf-8") as summary:
            summary.write("Unsigned test retention approval: `" + challenge + "`\n\n" + canonical_json(context).decode())
        return request

    def approve(self, request: dict[str, Any]) -> dict[str, Any]:
        """Verify GitHub review history again after the server-side environment gate."""
        TrustedCheckout().verify(self.root, request["context"]["control_sha"])
        require(
            request["context"]["run_id"] == int(os.environ["GITHUB_RUN_ID"]) and request["context"]["attempt"] == int(os.environ["GITHUB_RUN_ATTEMPT"]),
            "Request belongs to another attempt.",
        )
        approval = RetentionApproval(self.api).verify(request["context"], request["environment"])
        with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
            output.write("approved=true\n")
        return approval
