"""Read configured billing sources without loading application interpretation."""

from __future__ import annotations

import csv
import gzip
import io
from typing import IO, TYPE_CHECKING

from unio_collector.aws.cur.collection.accumulator import CurBillingAccumulator
from unio_collector.aws.cur.path.resolver import CurDataExportPathResolver

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

    from unio_collector.aws.cur.collection.result import CurBillingResult
    from unio_collector.aws.cur.data.source import CurDataSource, CurS3ObjectFetcher
    from unio_collector.core.scan.period import ScanPeriod


class CurBillingReader:
    """Reads AWS CUR/Data Export files from local paths or supplied S3 objects."""

    def __init__(  # noqa: D107
        self,
        paths: Iterable[str | Path],
        *,
        s3_object_fetcher: CurS3ObjectFetcher | None = None,
    ) -> None:
        self.paths = tuple(str(path) for path in paths)
        self.s3_object_fetcher = s3_object_fetcher

    def read_observations(  # noqa: D102
        self,
        scan_period: ScanPeriod,
        *,
        group_by_tags: tuple[str, ...],
    ) -> CurBillingResult:
        path_resolution = CurDataExportPathResolver(
            self.paths,
            s3_object_fetcher=self.s3_object_fetcher,
        ).resolve_paths()
        accumulator = CurBillingAccumulator(group_by_tags=group_by_tags)
        for source in path_resolution.data_sources:
            for row in self._read_rows(source):
                accumulator.record_row(row, scan_period)
        return accumulator.build_observations(path_resolution)

    def _read_rows(self, source: CurDataSource) -> Iterable[dict[str, str]]:
        with self.open_source_text(source) as handle:
            yield from csv.DictReader(handle)

    def open_source_text(self, source: CurDataSource) -> IO[str]:  # noqa: D102
        if source.local_path is not None:
            return open_cur_text(source.local_path)
        if source.bucket and source.key and self.s3_object_fetcher is not None:
            data = self.s3_object_fetcher(source.bucket, source.key)
            return open_cur_bytes(source.display_name, data)
        msg = f"CUR/Data Export source could not be opened: {source.display_name}."
        raise ValueError(
            msg,
        )


def open_cur_text(path: Path) -> IO[str]:  # noqa: D103
    if path.suffix.lower() == ".gz":
        return gzip.open(path, mode="rt", encoding="utf-8", newline="")
    return path.open("r", encoding="utf-8", newline="")


def open_cur_bytes(name: str, data: bytes) -> IO[str]:  # noqa: D103
    raw = io.BytesIO(data)
    if name.casefold().endswith(".gz"):
        return gzip.open(raw, mode="rt", encoding="utf-8", newline="")
    return io.TextIOWrapper(raw, encoding="utf-8", newline="")
