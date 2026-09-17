from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

from unio_collector.aws.response_admission import (
    require_complete_response,
    require_response_bool,
    require_response_mapping,
    require_response_rows,
    require_response_string,
)
from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.kms.key_posture.evidence import KmsKeyPostureEvidence
from unio_collector.scanners.kms.key_posture.record import KmsKeyPostureRecord
from unio_collector.scanners.kms.key_posture.rotation import kms_rotation_status_is_applicable
from unio_collector.scanners.security_governance.collection.regions import get_selected_or_available_regions
from unio_collector.scanners.security_governance.collection.warnings import append_warning

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


from unio_collector.scanners.scanner.implementation import ScannerImplementation


class KmsKeyPostureReviewCollector(BaseUnioScanner):
    """Collect provider evidence for kms-key-posture-review."""

    def collect(self, context: ScannerContext) -> KmsKeyPostureEvidence:  # noqa: D102
        regions = get_selected_or_available_regions(context, "kms")
        warnings: list[str] = []
        keys: list[KmsKeyPostureRecord] = []
        for region in regions:
            client = context.security.create_client(
                "kms",
                region_name=region,
                collector_name="KmsKeyPostureReviewScanner",
            )
            keys.extend(self._collect_region_keys(client, region, warnings))
        for warning in warnings:
            context.warnings.add(warning)
        return KmsKeyPostureEvidence(
            keys=tuple(keys),
            regions=tuple(regions),
            warnings=tuple(warnings),
        )

    def _collect_region_keys(
        self,
        client: Any,  # noqa: ANN401
        region: str,
        warnings: list[str],
    ) -> list[KmsKeyPostureRecord]:
        records: list[KmsKeyPostureRecord] = []
        for key_ref in self._list_key_refs(client, region, warnings):
            key_id = str(key_ref.get("KeyId") or "")
            if not key_id:
                continue
            metadata = self._describe_key(client, key_id, region, warnings)
            if not metadata:
                continue
            rotation_enabled = self._get_rotation_status(
                client,
                key_id,
                metadata,
                region,
                warnings,
            )
            records.append(
                KmsKeyPostureRecord(
                    key_id=str(metadata.get("KeyId") or key_id),
                    arn=metadata.get("Arn"),
                    region=region,
                    key_manager=metadata.get("KeyManager"),
                    key_state=metadata.get("KeyState"),
                    key_usage=metadata.get("KeyUsage"),
                    key_spec=metadata.get("KeySpec"),
                    rotation_enabled=rotation_enabled,
                    origin=metadata.get("Origin"),
                    multi_region=(metadata["MultiRegion"] if isinstance(metadata.get("MultiRegion"), bool) else None),
                ),
            )
        return records

    def _list_key_refs(
        self,
        client: Any,  # noqa: ANN401
        region: str,
        warnings: list[str],
    ) -> list[dict[str, Any]]:
        try:
            paginator = client.get_paginator("list_keys")
            pages = paginator.paginate()
        except Exception:  # noqa: BLE001
            try:
                pages = [client.list_keys()]
            except Exception as exc:  # noqa: BLE001
                append_warning(warnings, f"KMS key list in {region}", exc)
                return []
        records: list[dict[str, Any]] = []
        last_page: object = None
        try:
            for page in pages:
                for item in require_response_rows(page, "Keys"):
                    require_response_string(item.get("KeyId"))
                    records.append(item)
                last_page = page
            require_complete_response(last_page, truncated_keys=("Truncated",))
        except Exception as exc:  # noqa: BLE001
            append_warning(warnings, f"KMS key list in {region}", exc)
        return records

    def _describe_key(
        self,
        client: Any,  # noqa: ANN401
        key_id: str,
        region: str,
        warnings: list[str],
    ) -> dict[str, Any] | None:
        try:
            response = require_response_mapping(client.describe_key(KeyId=key_id))
            metadata = require_response_mapping(response.get("KeyMetadata"))
            require_response_string(metadata.get("KeyId"))
            for field in ("KeyId", "Arn", "KeyManager", "KeyState", "KeyUsage", "KeySpec", "Origin"):
                if field in metadata:
                    require_response_string(metadata[field])
            if "MultiRegion" in metadata:
                require_response_bool(metadata["MultiRegion"])
        except Exception as exc:  # noqa: BLE001
            append_warning(warnings, f"KMS key {key_id} in {region}", exc)
            return None
        return metadata

    def _get_rotation_status(
        self,
        client: Any,  # noqa: ANN401
        key_id: str,
        metadata: dict[str, Any],
        region: str,
        warnings: list[str],
    ) -> bool | None:
        if not kms_rotation_status_is_applicable(metadata):
            return None
        try:
            response = require_response_mapping(client.get_key_rotation_status(KeyId=key_id))
            enabled = require_response_bool(response.get("KeyRotationEnabled"))
        except Exception as exc:  # noqa: BLE001
            append_warning(warnings, f"KMS key rotation {key_id} in {region}", exc)
            return None
        return enabled

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the application identity in collection metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="KmsKeyPostureReviewScanner",
            implementation_module="unio_collector.scanners.kms.key_posture.scanner",
        )
