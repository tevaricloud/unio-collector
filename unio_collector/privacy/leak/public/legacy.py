"""Existing legacy log-group inventory region semantics in the scan view."""

from __future__ import annotations

from typing import Any

from unio_collector.collector.protocol import UNIO_PROTOCOL
from unio_collector.privacy.leak.public.region import public_region
from unio_collector.scanners.scanner.schema import admit_evidence_schema


class LegacyRegionScanContract:
    """Match one exact legacy identity; leave every other field/value untouched."""

    @staticmethod
    def mask(row: dict[str, Any]) -> None:
        """Recognize only the admitted log-retention envelope and declared regions."""
        if (
            row.get("scanner_id") != "cloudwatch-log-groups-without-retention"
            or row.get("provider_id", "aws") != "aws"
            or row.get("evidence_type") != "CloudWatchLogRetentionEvidence"
            or row.get("evidence_module")
            not in {f"{namespace}.scanners.cloudwatch.log_retention.evidence" for namespace in UNIO_PROTOCOL.accepted_import_namespaces}
        ):
            return
        schema = admit_evidence_schema(row)
        if schema is not None and (schema.schema_id, schema.version) != ("aws.cloudwatch.log-retention", 1):
            return
        payload = row.get("payload")
        if not isinstance(payload, dict):
            return
        regions = payload.get("regions")
        if isinstance(regions, list) and all(public_region(region) for region in regions):
            payload["regions"] = ["" for _ in regions]
        records = payload.get("records")
        if isinstance(records, list):
            for record in records:
                if isinstance(record, dict) and public_region(record.get("region")):
                    record["region"] = ""
