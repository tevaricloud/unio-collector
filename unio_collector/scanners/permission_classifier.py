from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable


READ_ONLY_ACTION_PREFIXES = (
    "batchget",
    "describe",
    "get",
    "list",
    "lookup",
    "search",
    "select",
)

READ_ONLY_ACTION_EXCEPTIONS: dict[str, str] = {
    "logs:startquery": (
        "CloudWatch Logs Insights StartQuery starts a read-only query over log events. It does not mutate resources, but AWS can charge for scanned log data."
    ),
}


def is_read_only_iam_action(action: str) -> bool:
    """Return whether an IAM action is approved for read-only scanner metadata."""
    normalized = action.strip().casefold()
    if normalized in READ_ONLY_ACTION_EXCEPTIONS:
        return True
    operation = _get_operation_name(normalized)
    return any(operation.startswith(prefix) for prefix in READ_ONLY_ACTION_PREFIXES)


def classify_iam_actions(actions: Iterable[str]) -> dict[str, list[str]]:
    """Classify IAM actions into read-only and rejected action names."""
    read_only: list[str] = []
    rejected: list[str] = []
    for action in sorted({action for action in actions if action.strip()}):
        if is_read_only_iam_action(action):
            read_only.append(action)
        else:
            rejected.append(action)
    return {
        "read_only": read_only,
        "rejected": rejected,
    }


def _get_operation_name(action: str) -> str:
    if ":" not in action:
        return action
    return action.split(":", 1)[1]
