from __future__ import annotations  # noqa: D100

from typing import Any

from unio_collector.aws.core.page_result import AwsPageCollectionResult
from unio_collector.aws.response_admission import ProviderResponseError, require_response_mapping, response_cursor


class AwsPaginationHelper:  # noqa: D101
    def collect_pages(  # noqa: D102
        self,
        client: Any,  # noqa: ANN401
        operation_name: str,
        *,
        result_key: str | None = None,
        request_parameters: dict[str, Any] | None = None,
    ) -> AwsPageCollectionResult:
        request_parameters = request_parameters or {}
        if self._can_paginate(client, operation_name):
            paginator = client.get_paginator(operation_name)
            pages = [require_response_mapping(page) for page in paginator.paginate(**request_parameters)]
        else:
            operation = getattr(client, operation_name)
            response = operation(**request_parameters)
            pages = [require_response_mapping(response)]
        return AwsPageCollectionResult(
            pages=pages,
            page_count=len(pages),
            resources_returned=self._count_resources(pages, result_key),
        )

    def collect_token_pages(  # noqa: D102
        self,
        client: Any,  # noqa: ANN401
        operation_name: str,
        *,
        result_key: str | None = None,
        request_parameters: dict[str, Any] | None = None,
        request_cursor_key: str = "NextToken",
        response_cursor_keys: tuple[str, ...] = ("NextToken",),
    ) -> AwsPageCollectionResult:
        if self._can_paginate(client, operation_name):
            return self.collect_pages(
                client,
                operation_name,
                result_key=result_key,
                request_parameters=request_parameters,
            )
        request_parameters = dict(request_parameters or {})
        pages: list[dict[str, Any]] = []
        next_token: str | None = None
        seen_tokens: set[str] = set()
        operation = getattr(client, operation_name)
        while True:
            request = dict(request_parameters)
            if next_token:
                request[request_cursor_key] = next_token
            response = operation(**request)
            pages.append(require_response_mapping(response))
            next_token = self._get_next_token(response, response_cursor_keys)
            if not next_token:
                break
            if next_token in seen_tokens:
                reason = "RepeatedCursor"
                raise ProviderResponseError(reason)
            seen_tokens.add(next_token)
        return AwsPageCollectionResult(
            pages=pages,
            page_count=len(pages),
            resources_returned=self._count_resources(pages, result_key),
        )

    def _can_paginate(self, client: Any, operation_name: str) -> bool:  # noqa: ANN401
        can_paginate = getattr(client, "can_paginate", None)
        if not callable(can_paginate):
            return False
        try:
            return bool(can_paginate(operation_name))
        except Exception:  # noqa: BLE001
            return False

    def _count_resources(
        self,
        pages: list[dict[str, Any]],
        result_key: str | None,
    ) -> int:
        if not result_key:
            return 0
        total = 0
        for page in pages:
            value = page.get(result_key)
            if isinstance(value, list):
                total += len(value)
        return total

    def _get_next_token(
        self,
        page: dict[str, Any],
        response_cursor_keys: tuple[str, ...],
    ) -> str | None:
        return response_cursor(page, response_cursor_keys)
