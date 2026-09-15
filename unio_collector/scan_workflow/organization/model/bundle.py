from __future__ import annotations  # noqa: D100

from pydantic import Field

from unio_collector.core.base_model import UnioBaseModel


class PerAccountBundleResult(UnioBaseModel):
    """Reference one independently valid account bundle and report."""

    account_reference: str
    bundle_path: str
    bundle_sha256: str
    bundle_schema_version: str
    bundle_purpose: str
    protection_status: str
    report_path: str | None = None
    finding_counts: dict[str, int] = Field(default_factory=dict)
    limitations: tuple[str, ...] = ()
