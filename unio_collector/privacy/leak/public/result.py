"""Typed scanner execution metadata; never a scanner-ID literal exemption."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from unio_collector.privacy.leak.public.metadata import PUBLIC_SCANNER_IDS
from unio_collector.privacy.leak.public.region import public_region
from unio_collector.privacy.leak.public.serverless import ServerlessScanContract
from unio_collector.scanners.registry.catalog import get_scanner

MONTH_PRECISION_LENGTH = 7

_STATUSES = frozenset({"completed", "completed_with_warnings", "failed", "disabled", "skipped", "unavailable", "cancelled", "timed_out"})


class ResultMetadataScanContract:
    """Keep customer data visible while distinguishing execution metadata.

    A registry lookup validates only the reference owner; it does not exempt the
    ID itself and does not import/construct decoders, collectors or AWS clients.
    Only validated execution timestamp roles, finite execution statuses and actual
    SDK region values at regions_scanned receive a structural metadata view.
    """

    @staticmethod
    def mask(value: dict[str, Any]) -> object:
        """Apply finite execution metadata treatment only to an admitted reference."""
        scanner = value.get("scanner_id")
        if (
            not isinstance(scanner, str)
            or value.get("provider_id", "aws") != "aws"
            or value.get("evidence_type") not in (None, "")
            or any(key in value for key in ("evidence_module", "evidence_schema_id", "evidence_schema_version"))
        ):
            return value
        try:
            definition = get_scanner(scanner)
        except ValueError:
            return value
        implementation_owned = ServerlessScanContract.implementation(value)
        pairs = []
        for key, child in value.items():
            masked_key = key
            masked_child = child
            if (
                (implementation_owned and key in {"implementation_type", "implementation_class", "implementation_module"})
                or (key == "scanner_id" and child in PUBLIC_SCANNER_IDS)
                or (key == "display_name" and scanner in PUBLIC_SCANNER_IDS and child == definition.display_name)
            ):
                masked_child = ""
            elif key in {"started_at", "completed_at"} and ResultMetadataScanContract._timestamp(child):
                masked_key = ""
                masked_child = ""
            elif key == "status" and isinstance(child, str) and child in _STATUSES:
                masked_child = ""
            elif key == "regions_scanned" and isinstance(child, list) and all(public_region(region) for region in child):
                masked_child = ["" for _ in child]
            pairs.append([masked_key, masked_child])
        return pairs

    @staticmethod
    def _timestamp(value: object) -> bool:
        if value is None:
            return True
        if not isinstance(value, str):
            return False
        if value == "":
            return True
        try:
            datetime.fromisoformat(value + "-01" if len(value) == MONTH_PRECISION_LENGTH else value)
        except ValueError:
            return False
        return True
