from __future__ import annotations  # noqa: D104

from unio_collector.aws.cassette.constants import CASSETTE_FILENAME, CASSETTE_VERSION
from unio_collector.aws.cassette.entry import AwsCassetteEntry
from unio_collector.aws.cassette.errors import (
    MissingAwsCassetteEntryError,
    build_client_error,
)
from unio_collector.aws.cassette.recorder import (
    AwsCassetteRecorder,
    convert_error_to_payload,
)
from unio_collector.aws.cassette.replayer import AwsCassetteReplayer
from unio_collector.aws.cassette.sanitizer import AwsCassetteSanitizer
from unio_collector.aws.cassette.store import AwsCassetteStore

__all__ = [
    "CASSETTE_FILENAME",
    "CASSETTE_VERSION",
    "AwsCassetteEntry",
    "AwsCassetteRecorder",
    "AwsCassetteReplayer",
    "AwsCassetteSanitizer",
    "AwsCassetteStore",
    "MissingAwsCassetteEntryError",
    "build_client_error",
    "convert_error_to_payload",
]
