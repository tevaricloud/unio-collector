"""Read configured S3 billing objects through the scoped collection gateway."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext

S3ObjectFetcher = Callable[[str, str], bytes]


def build_cur_s3_object_fetcher(context: ScannerContext) -> S3ObjectFetcher:  # noqa: D103
    def fetch_object(bucket: str, key: str) -> bytes:
        client = context.security.create_client(
            "s3",
            region_name=context.security.session.get_region_name() or "us-east-1",
            collector_name="CurDataExportReader",
        )
        response = client.get_object(Bucket=bucket, Key=key)
        body = response.get("Body")
        if body is None or not hasattr(body, "read"):
            msg = f"S3 object body was not readable: s3://{bucket}/{key}."
            raise ValueError(msg)
        data = body.read()
        if not isinstance(data, bytes):
            msg = f"S3 object body did not return bytes: s3://{bucket}/{key}."
            raise ValueError(
                msg,
            )
        return data

    return fetch_object
