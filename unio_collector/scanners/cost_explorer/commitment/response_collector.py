"""Bounded provider pagination for observed commitment collection."""

from __future__ import annotations

from typing import Any

from unio_collector.aws.response_admission import (
    ProviderResponseError,
    require_complete_response,
    require_response_mapping,
    require_response_rows,
    response_cursor,
)


class CommitmentResponseCollector:
    """Read provider pages and reject incomplete or repeated cursors."""

    def collect_response_pages(
        self,
        client: Any,  # noqa: ANN401
        method: str,
        kwargs: dict[str, object],
        *,
        request_page_key: str,
        response_page_key: str,
        paginated: bool,
    ) -> list[dict[str, Any]]:
        """Collect admitted pages with the existing opaque cursor protocol."""
        pages: list[dict[str, Any]] = []
        request = dict(kwargs)
        seen_tokens: set[str] = set()
        while True:
            response = require_response_mapping(getattr(client, method)(**request))
            pages.append(response)
            token = response_cursor(response, (response_page_key,)) if paginated else None
            if token is None:
                require_complete_response(response, cursor_keys=("NextPageToken", "NextToken", "nextToken"))
                return pages
            if token in seen_tokens:
                reason = "RepeatedCursor"
                raise ProviderResponseError(reason)
            seen_tokens.add(token)
            request[request_page_key] = token

    def collect_pages(
        self,
        client: Any,  # noqa: ANN401
        method: str,
        result_key: str,
        *,
        request_page_key: str,
        response_page_key: str,
    ) -> list[dict[str, object]]:
        """Collect admitted inventory rows without changing request scope."""
        pages = self.collect_response_pages(
            client,
            method,
            {},
            request_page_key=request_page_key,
            response_page_key=response_page_key,
            paginated=True,
        )
        return [item for page in pages for item in require_response_rows(page, result_key)]
