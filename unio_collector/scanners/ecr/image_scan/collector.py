from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

from unio_collector.aws.response_admission import (
    ProviderResponseError,
    iter_response_rows,
    require_response_bool,
    require_response_mapping,
    require_response_rows,
    require_response_string,
)
from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.ecr.image_scan.evidence import (
    EcrImageScanPostureEvidence,
)
from unio_collector.scanners.ecr.image_scan.registry_record import EcrRegistryScanRecord
from unio_collector.scanners.ecr.image_scan.repository_record import EcrRepositoryScanRecord
from unio_collector.scanners.security_governance.collection.regions import get_selected_or_available_regions
from unio_collector.scanners.security_governance.collection.warnings import build_context_warning

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


from unio_collector.scanners.scanner.implementation import ScannerImplementation


class EcrImageScanPostureReviewCollector(BaseUnioScanner):
    """Collect provider evidence for ecr-image-scan-posture-review."""

    def collect(self, context: ScannerContext) -> EcrImageScanPostureEvidence:  # noqa: D102
        regions = get_selected_or_available_regions(context, "ecr")
        warnings: list[str] = []
        repositories: list[EcrRepositoryScanRecord] = []
        registries: list[EcrRegistryScanRecord] = []
        for region in regions:
            client = context.security.create_client(
                "ecr",
                region_name=region,
                collector_name="EcrImageScanPostureReviewScanner",
            )
            repositories.extend(
                self._collect_repositories(client, region=region, warnings=warnings),
            )
            registry = self._get_registry_scan_configuration(
                client,
                region=region,
                warnings=warnings,
            )
            if registry is not None:
                registries.append(registry)
        for warning in warnings:
            context.warnings.add(warning)
        self._record_ecr_scan_coverage(context, repositories, registries, warnings)
        return EcrImageScanPostureEvidence(
            repositories=tuple(repositories),
            registries=tuple(registries),
            regions=tuple(regions),
            warnings=tuple(warnings),
            account_id=context.security.account_id,
        )

    def _collect_repositories(
        self,
        client: Any,  # noqa: ANN401
        *,
        region: str,
        warnings: list[str],
    ) -> list[EcrRepositoryScanRecord]:
        try:
            pages = client.get_paginator("describe_repositories").paginate()
        except Exception as exc:  # noqa: BLE001
            warnings.append(build_context_warning(region, "ECR repositories", exc))
            return []
        records: list[EcrRepositoryScanRecord] = []
        try:
            for item in iter_response_rows(pages, "repositories"):
                scan_config = require_response_mapping(item.get("imageScanningConfiguration", {}))
                encryption_config = require_response_mapping(item.get("encryptionConfiguration", {}))
                scan_on_push = None
                if "scanOnPush" in scan_config:
                    scan_on_push = require_response_bool(scan_config["scanOnPush"])
                records.append(
                    EcrRepositoryScanRecord(
                        repository_name=require_response_string(item.get("repositoryName")),
                        repository_arn=str(item.get("repositoryArn")) if item.get("repositoryArn") else None,
                        region=region,
                        scan_on_push=scan_on_push,
                        image_tag_mutability=str(item.get("imageTagMutability")) if item.get("imageTagMutability") else None,
                        encryption_type=str(encryption_config.get("encryptionType"))
                        if isinstance(encryption_config, dict) and encryption_config.get("encryptionType")
                        else None,
                        kms_key=str(encryption_config.get("kmsKey")) if isinstance(encryption_config, dict) and encryption_config.get("kmsKey") else None,
                    ),
                )
        except Exception as exc:  # noqa: BLE001
            warnings.append(build_context_warning(region, "ECR repositories", exc))
        return records

    def _get_registry_scan_configuration(
        self,
        client: Any,  # noqa: ANN401
        *,
        region: str,
        warnings: list[str],
    ) -> EcrRegistryScanRecord | None:
        operation = getattr(client, "get_registry_scanning_configuration", None)
        if not callable(operation):
            warnings.append(build_context_warning(region, "ECR registry scanning configuration", ProviderResponseError()))
            return None
        try:
            response = require_response_mapping(operation())
            config = require_response_mapping(response.get("registryScanningConfiguration"))
            scan_type = require_response_string(config.get("scanType"))
            rules = require_response_rows(config, "rules")
        except Exception as exc:  # noqa: BLE001
            warnings.append(
                build_context_warning(
                    region,
                    "ECR registry scanning configuration",
                    exc,
                ),
            )
            return None
        return EcrRegistryScanRecord(
            region=region,
            scan_type=scan_type,
            rule_count=len(rules),
        )

    def _record_ecr_scan_coverage(
        self,
        context: ScannerContext,
        repositories: list[EcrRepositoryScanRecord],
        registries: list[EcrRegistryScanRecord],
        warnings: list[str],
    ) -> None:
        context.warnings.add_coverage_note(
            {
                "note_type": "execution_detail",
                "scope_area": "ecr_image_scanning",
                "repository_count": len(repositories),
                "registry_configuration_count": len(registries),
                "warning_count": len(warnings),
                "regions": sorted({record.region for record in repositories}) or sorted({record.region for record in registries}),
                "result_scope": "current_scan",
                "summary": (f"ECR repository image scanning posture was collected for {len(repositories)} repositories."),
                "impact": (
                    "This evidence checks scan-on-push and registry scan "
                    "configuration metadata. It does not pull images, inspect "
                    "image contents, or prove vulnerabilities are absent."
                ),
            },
        )

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the application identity in collection metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="EcrImageScanPostureReviewScanner",
            implementation_module="unio_collector.scanners.ecr.image_scan.scanner",
        )
