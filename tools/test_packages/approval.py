"""Protected-environment approval bound to a fresh candidate challenge."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from tools.collector_repository.paths import require
from tools.test_packages.context import ENVIRONMENT, CandidateContext, digest

if TYPE_CHECKING:
    from tools.test_packages.api import GitHubReadClient


class RetentionApproval:
    """Verify protection configuration and real review history, not an approval flag."""

    def __init__(self, api: GitHubReadClient) -> None:
        """Bind the authenticated transport and explicit source context."""
        self.api = api

    def configuration(self) -> dict[str, Any]:
        """Require eligible reviewers, explicit self-review policy and disabled admin bypass."""
        environment = self.api.get(self.api.prefix + f"environments/{ENVIRONMENT}")
        require(environment["name"] == ENVIRONMENT and type(environment["id"]) is int, "Environment identity mismatch.")
        rules = [r for r in environment["protection_rules"] if r["type"] == "required_reviewers"]
        require(
            environment.get("can_admins_bypass") is False and len(rules) == 1 and type(rules[0].get("prevent_self_review")) is bool,
            "Inadequate approval protection.",
        )
        reviewers = rules[0]["reviewers"]
        require(
            bool(reviewers) and all(r["type"] == "User" and r["reviewer"]["type"] == "User" for r in reviewers), "Configure explicit individual maintainers."
        )
        for row in reviewers:
            permission = self.api.get(self.api.prefix + f"collaborators/{row['reviewer']['login']}/permission")
            require(permission.get("permission") in {"admin", "maintain"}, "Reviewer is not a maintainer.")
        return {
            "id": environment["id"],
            "name": environment["name"],
            "reviewers": sorted(r["reviewer"]["id"] for r in reviewers),
            "prevent_self_review": rules[0]["prevent_self_review"],
            "can_admins_bypass": False,
        }

    def verify(self, context: dict[str, Any], configuration: dict[str, Any]) -> dict[str, Any]:
        """Require authenticated maintainer authorisation quoting the fresh challenge."""
        CandidateContext(self.api).verify(context)
        require(self.configuration() == configuration, "Approval configuration changed.")
        reviews = self.api.reviews(context["run_id"])
        comment = "UNIO-TEST-APPROVE " + digest({"context": context, "environment": configuration})
        matching = [r for r in reviews if r.get("comment") == comment and any(e.get("id") == configuration["id"] for e in r.get("environments", []))]
        require(len(matching) == 1 and matching[0].get("state") == "approved", "Missing, rejected or ambiguous current approval.")
        user = matching[0]["user"]
        require(user["type"] == "User" and user["id"] in configuration["reviewers"], "Approver is not an eligible configured maintainer.")
        return {"reviewer_id": user["id"], "reviewer": user["login"], "challenge": comment, "environment_id": configuration["id"]}
