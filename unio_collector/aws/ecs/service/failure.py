"""Finite diagnostics for individual read-only ECS describe response failures."""

from __future__ import annotations


def describe_failure_codes(response: object, *, operation: str) -> list[str]:
    """Preserve partial-collection limitations without propagating raw SDK details."""
    if not isinstance(response, dict):
        return [operation + ":UnavailableEvidence"]
    failures = response.get("failures", [])
    if not isinstance(failures, list):
        return [operation + ":MalformedEvidence"]
    codes = []
    for failure in failures:
        if not isinstance(failure, dict) or not isinstance(failure.get("reason"), str):
            code = "MalformedEvidence"
        elif failure["reason"] == "ACCESS_DENIED":
            code = "AccessDeniedException"
        elif failure["reason"] == "MISSING":
            code = "UnavailableEvidence"
        else:
            code = "PartialEvidence"
        codes.append(operation + ":" + code)
    return list(dict.fromkeys(codes))
