"""Shared strict synthetic provider state without constructing AWS clients."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from botocore.exceptions import ClientError

if TYPE_CHECKING:
    from tools.collector_serverless.session import SyntheticServerlessSession


def synthetic_arn(service: str, resource: str) -> str:
    """Use only the documented sample account and fixed synthetic resources."""
    return f"arn:aws:{service}:eu-west-2:123456789012:{resource}"


class SyntheticServerlessClient:
    """Retain exact requested operations and reject only declared failure branches."""

    def __init__(self, session: SyntheticServerlessSession, service: str) -> None:
        """Share deterministic provider observations within one synthetic collection."""
        self.session, self.service = session, service

    def can_paginate(self, _operation: str) -> bool:
        """Use the actual supported one-page SDK fallback."""
        return False

    def _fail(self, operation: str) -> None:
        self.session.calls.append(self.service + ":" + operation)
        variant = self.session.variant
        root = operation in {"list_functions", "list_event_source_mappings", "describe_db_instances"}
        partial = variant == "partial" and operation in {"get_function_configuration", "describe_db_instances", "get_metric_data"}
        tags = variant == "tag_denied" and operation in {"list_tags", "list_tags_for_resource"}
        images = variant == "image_unavailable" and operation == "describe_images"
        invoke = variant == "invoke_unavailable" and operation == "get_function_event_invoke_config"
        if (root and variant in {"denied", "unsupported", "failure"}) or partial or tags or images or invoke:
            code = {"denied": "AccessDeniedException", "unsupported": "UnknownOperationException", "failure": "InternalFailure"}.get(
                variant, "AccessDeniedException"
            )
            raise ClientError({"Error": {"Code": code, "Message": "synthetic provider limitation"}}, operation)

    def _response(self, operation: str, key: str, rows: list[Any]) -> dict[str, Any]:
        self._fail(operation)
        return {key: [] if self.session.variant == "empty" else rows}
