from __future__ import annotations  # noqa: D100

from typing import TypedDict


class ResolvedAuthorizationScope(TypedDict):
    """Resolved result for one bound AWS authorization-scope variant."""

    resource_arn_templates: tuple[str, ...]
    resolved_resources: tuple[str, ...]
    iam_conditions: tuple[dict[str, object], ...]
    unresolved_variables: tuple[str, ...]
    authorization_references: tuple[str, ...]
    wildcard_justification: str
    scope_status: str


__all__ = ["ResolvedAuthorizationScope"]
