from __future__ import annotations  # noqa: D100

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from unio_collector.aws.cur.data.source import CurDataSource
from unio_collector.aws.cur.line.factory import normalize_column_name
from unio_collector.aws.cur.path.result import CurPathResolutionResult
from unio_collector.core.count_formatting import format_count

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from unio_collector.aws.cur.data.source import CurS3ObjectFetcher

SUPPORTED_DATA_FILE_SUFFIXES = (".csv", ".csv.gz")
UNSUPPORTED_DATA_FILE_SUFFIXES = (".parquet", ".snappy.parquet")


class CurDataExportPathResolver:  # noqa: D101
    def __init__(  # noqa: D107
        self,
        paths: Iterable[str | Path],
        *,
        s3_object_fetcher: CurS3ObjectFetcher | None = None,
    ) -> None:
        self.paths = tuple(str(path) for path in paths)
        self.s3_object_fetcher = s3_object_fetcher
        self.reason_codes: list[str] = []

    def resolve_paths(self) -> CurPathResolutionResult:  # noqa: D102
        self.reason_codes = []
        data_sources: list[CurDataSource] = []
        limitations: list[str] = []
        for path in self.paths:
            self.collect_path(path, data_sources, limitations)
        unique_sources = tuple(dedupe_sources(data_sources))
        if not unique_sources:
            self.reason_codes.append("source_resolution_incomplete")
            limitations.append(
                "No readable CSV or CSV.GZ CUR/Data Export files were found.",
            )
        return CurPathResolutionResult(
            data_sources=unique_sources,
            limitations=tuple(dict.fromkeys(limitations)),
            reason_codes=tuple(dict.fromkeys(self.reason_codes)),
        )

    def collect_path(  # noqa: D102
        self,
        path_value: str | Path,
        data_sources: list[CurDataSource],
        limitations: list[str],
    ) -> None:
        raw_path = str(path_value)
        if is_s3_uri(raw_path):
            self.collect_s3_uri(raw_path, data_sources, limitations)
            return
        path = Path(raw_path)
        if not path.exists():
            self.reason_codes.append("source_resolution_incomplete")
            limitations.append(f"CUR/Data Export path was not found: {path}.")
            return
        if path.is_dir():
            self.collect_directory(path, data_sources, limitations)
            return
        if is_supported_data_file(path):
            data_sources.append(local_data_source(path))
            return
        if is_manifest_file(path):
            self.collect_manifest(path, data_sources, limitations)
            return
        if is_unsupported_data_file(path):
            self.reason_codes.append("source_resolution_incomplete")
            limitations.append(
                f"CUR/Data Export file format is not supported yet: {path.name}.",
            )
            return
        self.reason_codes.append("source_resolution_incomplete")
        limitations.append(
            f"CUR/Data Export path was ignored because the file type is unsupported: {path}.",
        )

    def collect_directory(  # noqa: D102
        self,
        path: Path,
        data_sources: list[CurDataSource],
        limitations: list[str],
    ) -> None:
        initial_count = len(data_sources)
        for child in sorted(path.rglob("*")):
            if child.is_file() and is_supported_data_file(child):
                data_sources.append(local_data_source(child))
            elif child.is_file() and is_unsupported_data_file(child):
                self.reason_codes.append("source_resolution_incomplete")
                limitations.append(
                    f"CUR/Data Export file format is not supported yet: {child.name}.",
                )
        if len(data_sources) == initial_count:
            self.reason_codes.append("source_resolution_incomplete")
            limitations.append(f"CUR/Data Export directory contained no readable data files: {path}.")

    def collect_manifest(  # noqa: D102
        self,
        path: Path,
        data_sources: list[CurDataSource],
        limitations: list[str],
    ) -> None:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            self.reason_codes.append("source_resolution_incomplete")
            limitations.append(
                f"CUR/Data Export manifest could not be read: {path} ({type(exc).__name__}).",
            )
            return

        references = tuple(extract_manifest_file_references(payload))
        if not references:
            self.reason_codes.append("source_resolution_incomplete")
            limitations.append(
                f"CUR/Data Export manifest did not contain local data file references: {path}.",
            )
            return

        matched = 0
        for reference in references:
            resolved = resolve_manifest_reference(
                path.parent,
                reference,
                s3_object_fetcher=self.s3_object_fetcher,
            )
            if resolved is None:
                self.reason_codes.append("source_resolution_incomplete")
                limitations.append(
                    f"CUR/Data Export manifest reference could not be resolved locally: {reference}.",
                )
                continue
            if isinstance(resolved, CurDataSource):
                matched += 1
                data_sources.append(resolved)
            elif is_supported_data_file(resolved):
                matched += 1
                data_sources.append(local_data_source(resolved))
            elif is_unsupported_data_file(resolved):
                self.reason_codes.append("source_resolution_incomplete")
                limitations.append(
                    f"CUR/Data Export manifest referenced unsupported file format: {resolved.name}.",
                )
        if matched:
            limitations.append(
                f"Expanded local CUR/Data Export manifest {path.name} to {format_count(matched, 'data file')}.",
            )

    def collect_s3_uri(  # noqa: D102
        self,
        uri: str,
        data_sources: list[CurDataSource],
        limitations: list[str],
    ) -> None:
        parsed = parse_s3_uri(uri)
        if parsed is None:
            self.reason_codes.append("source_resolution_incomplete")
            limitations.append(f"CUR/Data Export S3 URI could not be parsed: {uri}.")
            return
        bucket, key = parsed
        if is_supported_data_reference(uri):
            if self.s3_object_fetcher is None:
                self.reason_codes.append("source_resolution_incomplete")
                limitations.append(
                    f"S3 CUR/Data Export object requires a live AWS scan with s3:GetObject: {uri}.",
                )
                return
            data_sources.append(s3_data_source(bucket, key))
            return
        if is_manifest_reference(uri):
            self.collect_s3_manifest(bucket, key, data_sources, limitations)
            return
        if is_unsupported_data_reference(uri):
            self.reason_codes.append("source_resolution_incomplete")
            limitations.append(
                f"CUR/Data Export S3 object format is not supported in this phase: {uri}.",
            )
            return
        self.reason_codes.append("source_resolution_incomplete")
        limitations.append(
            f"CUR/Data Export S3 URI was ignored because the file type is unsupported: {uri}.",
        )

    def collect_s3_manifest(  # noqa: D102
        self,
        bucket: str,
        key: str,
        data_sources: list[CurDataSource],
        limitations: list[str],
    ) -> None:
        if self.s3_object_fetcher is None:
            self.reason_codes.append("source_resolution_incomplete")
            limitations.append(
                f"S3 CUR/Data Export manifest requires a live AWS scan with s3:GetObject: s3://{bucket}/{key}.",
            )
            return
        try:
            payload = json.loads(self.s3_object_fetcher(bucket, key).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, OSError, ValueError) as exc:
            self.reason_codes.append("source_resolution_incomplete")
            limitations.append(
                f"CUR/Data Export S3 manifest could not be read: s3://{bucket}/{key} ({type(exc).__name__}).",
            )
            return
        references = tuple(extract_manifest_file_references(payload))
        if not references:
            self.reason_codes.append("source_resolution_incomplete")
            limitations.append(f"CUR/Data Export S3 manifest contained no data file references: s3://{bucket}/{key}.")
        matched = 0
        for reference in references:
            resolved = resolve_s3_manifest_reference(bucket, key, reference)
            if resolved is None:
                self.reason_codes.append("source_resolution_incomplete")
                limitations.append(
                    f"CUR/Data Export S3 manifest reference could not be resolved: {reference}.",
                )
                continue
            if is_supported_data_reference(resolved.display_name):
                matched += 1
                data_sources.append(resolved)
            elif is_unsupported_data_reference(resolved.display_name):
                self.reason_codes.append("source_resolution_incomplete")
                limitations.append(
                    f"CUR/Data Export S3 manifest referenced unsupported file format: {resolved.display_name}.",
                )
        if matched:
            limitations.append(
                f"Expanded S3 CUR/Data Export manifest s3://{bucket}/{key} to {format_count(matched, 'data file')}.",
            )


def local_data_source(path: Path) -> CurDataSource:  # noqa: D103
    return CurDataSource(
        source_type="local",
        display_name=str(path),
        local_path=path,
    )


def s3_data_source(bucket: str, key: str) -> CurDataSource:  # noqa: D103
    return CurDataSource(
        source_type="s3",
        display_name=f"s3://{bucket}/{key}",
        bucket=bucket,
        key=key,
    )


def dedupe_sources(sources: list[CurDataSource]) -> list[CurDataSource]:  # noqa: D103
    unique: dict[str, CurDataSource] = {}
    for source in sources:
        unique.setdefault(source.name, source)
    return list(unique.values())


def is_supported_data_file(path: Path) -> bool:  # noqa: D103
    name = path.name.casefold()
    return any(name.endswith(suffix) for suffix in SUPPORTED_DATA_FILE_SUFFIXES)


def is_unsupported_data_file(path: Path) -> bool:  # noqa: D103
    name = path.name.casefold()
    return any(name.endswith(suffix) for suffix in UNSUPPORTED_DATA_FILE_SUFFIXES)


def is_manifest_file(path: Path) -> bool:  # noqa: D103
    name = path.name.casefold()
    return path.suffix.casefold() == ".json" and "manifest" in name


def is_s3_uri(value: str) -> bool:  # noqa: D103
    return value.casefold().startswith("s3://")


def parse_s3_uri(value: str) -> tuple[str, str] | None:  # noqa: D103
    if not is_s3_uri(value):
        return None
    remainder = value[5:]
    if "/" not in remainder:
        return None
    bucket, key = remainder.split("/", 1)
    if not bucket or not key:
        return None
    return bucket, key


def is_supported_data_reference(value: str) -> bool:  # noqa: D103
    normalized = value.casefold()
    return any(normalized.endswith(suffix) for suffix in SUPPORTED_DATA_FILE_SUFFIXES)


def is_unsupported_data_reference(value: str) -> bool:  # noqa: D103
    normalized = value.casefold()
    return any(normalized.endswith(suffix) for suffix in UNSUPPORTED_DATA_FILE_SUFFIXES)


def is_manifest_reference(value: str) -> bool:  # noqa: D103
    normalized = value.casefold()
    return normalized.endswith(".json") and "manifest" in normalized


def extract_manifest_file_references(payload: Any) -> Iterator[str]:  # noqa: ANN401, D103
    if isinstance(payload, dict):
        for key, value in payload.items():
            normalized_key = normalize_column_name(str(key))
            if normalized_key in {
                "reportkeys",
                "report_keys",
                "data_file_locations",
                "file_locations",
                "files",
                "datafiles",
                "data_files",
                "parts",
            }:
                yield from extract_manifest_file_references(value)
                continue
            if normalized_key in {"key", "path", "file", "filename", "uri", "url"}:
                if isinstance(value, str) and looks_like_data_reference(value):
                    yield value
                continue
            yield from extract_manifest_file_references(value)
    elif isinstance(payload, list):
        for value in payload:
            yield from extract_manifest_file_references(value)
    elif isinstance(payload, str) and looks_like_data_reference(payload):
        yield payload


def looks_like_data_reference(value: str) -> bool:  # noqa: D103
    normalized = value.casefold()
    return any(normalized.endswith(suffix) for suffix in (*SUPPORTED_DATA_FILE_SUFFIXES, *UNSUPPORTED_DATA_FILE_SUFFIXES))


def resolve_manifest_reference(  # noqa: D103
    base_path: Path,
    reference: str,
    *,
    s3_object_fetcher: CurS3ObjectFetcher | None = None,
) -> Path | CurDataSource | None:
    if reference.casefold().startswith("s3://"):
        parsed = parse_s3_uri(reference)
        if parsed and s3_object_fetcher is not None:
            return s3_data_source(*parsed)
        return resolve_s3_like_reference(base_path, reference)
    candidate = Path(reference)
    if candidate.is_absolute() and candidate.exists():
        return candidate
    joined = base_path / candidate
    if joined.exists():
        return joined
    sibling = base_path / candidate.name
    if sibling.exists():
        return sibling
    return None


def resolve_s3_like_reference(base_path: Path, reference: str) -> Path | None:  # noqa: D103
    key_name = reference.rstrip("/").rsplit("/", 1)[-1]
    sibling = base_path / key_name
    if sibling.exists():
        return sibling
    matches = sorted(base_path.rglob(key_name))
    if len(matches) == 1:
        return matches[0]
    return None


def resolve_s3_manifest_reference(  # noqa: D103
    manifest_bucket: str,
    manifest_key: str,
    reference: str,
) -> CurDataSource | None:
    if is_s3_uri(reference):
        parsed = parse_s3_uri(reference)
        return s3_data_source(*parsed) if parsed else None
    base_prefix = manifest_key.rsplit("/", 1)[0] if "/" in manifest_key else ""
    key = reference.lstrip("/")
    if base_prefix and not key.startswith(base_prefix):
        key = f"{base_prefix}/{key}"
    return s3_data_source(manifest_bucket, key)
