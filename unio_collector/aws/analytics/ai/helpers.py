# noqa: D100
# pyright: reportAttributeAccessIssue=false
from __future__ import annotations

from typing import Any

from unio_collector.aws import errors as aws_errors
from unio_collector.aws.bedrock.operation_limitation import BedrockOperationLimitation


class AnalyticsAiHelperMixin:  # noqa: D101
    def _collect_bedrock_token_items(
        self,
        client: Any,  # noqa: ANN401
        method_name: str,
        api_operation_name: str,
        result_key: str,
        permission_errors: list[str],
        operation_limitations: list[BedrockOperationLimitation],
    ) -> list[dict[str, Any]]:
        if not self._client_supports_operation(
            client,
            method_name=method_name,
            api_operation_name=api_operation_name,
        ):
            operation_limitations.append(
                BedrockOperationLimitation(
                    api_action=f"bedrock:{api_operation_name}",
                    status="skipped_client_model",
                    error_classification="unsupported_operation",
                    error_code="UnsupportedClientModelOperation",
                ),
            )
            return []
        try:
            result = self._pagination.collect_token_pages(
                client,
                method_name,
                result_key=result_key,
                response_cursor_keys=("NextToken", "nextToken"),
                request_cursor_key="NextToken",
            )
        except Exception as exc:  # noqa: BLE001
            if aws_errors.is_unsupported_operation_error(
                exc,
                service_name="bedrock",
                operation_name=api_operation_name,
            ):
                error_code = aws_errors.get_aws_error_code(exc)
                operation_limitations.append(
                    BedrockOperationLimitation(
                        api_action=f"bedrock:{api_operation_name}",
                        status="unsupported_endpoint_operation",
                        error_classification="unsupported_operation",
                        error_code=(error_code if error_code in {"UnknownOperationException", "ValidationException"} else None),
                    ),
                )
                return []
            self._record_collection_error(
                permission_errors,
                method_name=method_name,
                exc=exc,
            )
            return []
        return self._collect_items(result.pages, result_key)

    def _client_supports_operation(
        self,
        client: Any,  # noqa: ANN401
        *,
        method_name: str,
        api_operation_name: str,
    ) -> bool:
        meta = getattr(client, "meta", None)
        service_model = getattr(meta, "service_model", None)
        operation_names = getattr(service_model, "operation_names", None)
        if operation_names is not None:
            return api_operation_name in set(operation_names)
        method_mapping = getattr(meta, "method_to_api_mapping", None)
        if isinstance(method_mapping, dict) and method_name in method_mapping:
            return method_mapping[method_name] == api_operation_name
        return hasattr(client, method_name)

    def _collect_token_items(
        self,
        client: Any,  # noqa: ANN401
        method_name: str,
        result_key: str,
        permission_errors: list[str],
    ) -> list[dict[str, Any]]:
        if not hasattr(client, method_name):
            permission_errors.append(f"{method_name}:UnsupportedClientMethod")
            return []
        try:
            result = self._pagination.collect_token_pages(
                client,
                method_name,
                result_key=result_key,
                response_cursor_keys=("NextToken", "nextToken"),
                request_cursor_key="NextToken",
            )
        except Exception as exc:  # noqa: BLE001
            self._record_collection_error(
                permission_errors,
                method_name=method_name,
                exc=exc,
            )
            return []
        return self._collect_items(result.pages, result_key)

    def _collect_sagemaker_endpoint_configs(
        self,
        client: Any,  # noqa: ANN401
        endpoints: list[dict[str, Any]],
        permission_errors: list[str],
    ) -> list[dict[str, Any]]:
        configs: list[dict[str, Any]] = []
        seen: set[str] = set()
        for endpoint in endpoints:
            endpoint_name = str(endpoint.get("EndpointName") or "")
            if not endpoint_name:
                continue
            endpoint_config_name = self._get_sagemaker_endpoint_config_name(
                client,
                endpoint_name,
                permission_errors,
            )
            if not endpoint_config_name or endpoint_config_name in seen:
                continue
            seen.add(endpoint_config_name)
            config = self._get_sagemaker_endpoint_config(
                client,
                endpoint_config_name,
                permission_errors,
            )
            if config:
                configs.append(config)
        return configs

    def _get_sagemaker_endpoint_config_name(
        self,
        client: Any,  # noqa: ANN401
        endpoint_name: str,
        permission_errors: list[str],
    ) -> str:
        try:
            response = client.describe_endpoint(EndpointName=endpoint_name)
        except Exception as exc:  # noqa: BLE001
            self._record_collection_error(
                permission_errors,
                method_name="describe_endpoint",
                exc=exc,
            )
            return ""
        return str(response.get("EndpointConfigName") or "")

    def _get_sagemaker_endpoint_config(
        self,
        client: Any,  # noqa: ANN401
        endpoint_config_name: str,
        permission_errors: list[str],
    ) -> dict[str, Any] | None:
        try:
            response = client.describe_endpoint_config(
                EndpointConfigName=endpoint_config_name,
            )
        except Exception as exc:  # noqa: BLE001
            self._record_collection_error(
                permission_errors,
                method_name="describe_endpoint_config",
                exc=exc,
            )
            return None
        return response if isinstance(response, dict) else None

    def _is_workgroup_unbounded(self, workgroup: dict[str, Any]) -> bool:
        configuration = self._get_workgroup_configuration(workgroup)
        cutoff = configuration.get("BytesScannedCutoffPerQuery")
        return self._get_int(cutoff) <= 0

    def _is_workgroup_enforced(self, workgroup: dict[str, Any]) -> bool:
        return bool(
            self._get_workgroup_configuration(workgroup).get(
                "EnforceWorkGroupConfiguration",
            ),
        )

    def _is_workgroup_metric_publishing_enabled(
        self,
        workgroup: dict[str, Any],
    ) -> bool:
        return bool(
            self._get_workgroup_configuration(workgroup).get(
                "PublishCloudWatchMetricsEnabled",
            ),
        )

    def _is_workgroup_requester_pays_enabled(
        self,
        workgroup: dict[str, Any],
    ) -> bool:
        return bool(
            self._get_workgroup_configuration(workgroup).get("RequesterPaysEnabled"),
        )

    def _get_workgroup_configuration(
        self,
        workgroup: dict[str, Any],
    ) -> dict[str, Any]:
        configuration = workgroup.get("Configuration")
        return configuration if isinstance(configuration, dict) else {}

    def _is_failed_athena_query(self, execution: dict[str, Any]) -> bool:
        return str(
            self._get_athena_query_status(execution).get("State") or "",
        ).upper() in {"FAILED", "CANCELLED"}

    def _get_athena_query_duration_ms(self, execution: dict[str, Any]) -> int:
        statistics = self._get_athena_query_statistics(execution)
        return max(
            self._get_int(statistics.get("TotalExecutionTimeInMillis")),
            self._get_int(statistics.get("EngineExecutionTimeInMillis")),
        )

    def _get_athena_query_bytes_scanned(self, execution: dict[str, Any]) -> int:
        return self._get_int(
            self._get_athena_query_statistics(execution).get("DataScannedInBytes"),
        )

    def _get_athena_query_status(
        self,
        execution: dict[str, Any],
    ) -> dict[str, Any]:
        status = execution.get("Status")
        return status if isinstance(status, dict) else {}

    def _get_athena_query_statistics(
        self,
        execution: dict[str, Any],
    ) -> dict[str, Any]:
        statistics = execution.get("Statistics")
        return statistics if isinstance(statistics, dict) else {}

    def _has_schedule(self, item: dict[str, Any]) -> bool:
        return bool(item.get("Schedule"))

    def _get_glue_configured_worker_count(self, job: dict[str, Any]) -> int:
        worker_count = self._get_int(job.get("NumberOfWorkers"))
        if worker_count > 0:
            return worker_count
        return self._get_int(job.get("MaxCapacity"))

    def _is_failed_glue_run(self, run: dict[str, Any]) -> bool:
        return str(run.get("JobRunState") or "").upper() in {
            "FAILED",
            "ERROR",
            "STOPPED",
            "TIMEOUT",
            "EXPIRED",
        }

    def _get_glue_run_seconds(self, run: dict[str, Any]) -> int:
        return max(
            self._get_int(run.get("ExecutionTime")),
            self._get_int(run.get("JobRunQueuingDuration")),
        )

    def _is_sagemaker_notebook_running(self, notebook: dict[str, Any]) -> bool:
        return str(notebook.get("NotebookInstanceStatus") or "").lower() == "inservice"

    def _is_sagemaker_endpoint_in_service(self, endpoint: dict[str, Any]) -> bool:
        return str(endpoint.get("EndpointStatus") or "").lower() == "inservice"

    def _is_sagemaker_training_job_active(self, job: dict[str, Any]) -> bool:
        return str(job.get("TrainingJobStatus") or "").lower() in {
            "inprogress",
            "stopping",
        }

    def _is_sagemaker_processing_job_active(self, job: dict[str, Any]) -> bool:
        return str(job.get("ProcessingJobStatus") or "").lower() in {
            "inprogress",
            "stopping",
        }

    def _is_sagemaker_transform_job_active(self, job: dict[str, Any]) -> bool:
        return str(job.get("TransformJobStatus") or "").lower() in {
            "inprogress",
            "stopping",
        }

    def _get_sagemaker_endpoint_variants(
        self,
        config: dict[str, Any],
    ) -> list[dict[str, Any]]:
        variants = config.get("ProductionVariants")
        if isinstance(variants, list):
            return [variant for variant in variants if isinstance(variant, dict)]
        return []

    def _get_sagemaker_endpoint_instance_count(
        self,
        config: dict[str, Any],
    ) -> int:
        count = 0
        for variant in self._get_sagemaker_endpoint_variants(config):
            count += self._get_int(variant.get("InitialInstanceCount"))
        return count

    def _get_sagemaker_serverless_variant_count(
        self,
        config: dict[str, Any],
    ) -> int:
        return sum(1 for variant in self._get_sagemaker_endpoint_variants(config) if isinstance(variant.get("ServerlessConfig"), dict))

    def _has_async_inference(self, config: dict[str, Any]) -> bool:
        return isinstance(config.get("AsyncInferenceConfig"), dict)

    def _get_endpoint_instance_types(
        self,
        configs: list[dict[str, Any]],
    ) -> list[str]:
        instance_types: list[str] = []
        for config in configs:
            for variant in self._get_sagemaker_endpoint_variants(config):
                instance_type = variant.get("InstanceType")
                if instance_type:
                    instance_types.append(str(instance_type))
        return instance_types

    def _get_bedrock_names(self, items: list[dict[str, Any]]) -> list[str]:
        names: list[str] = []
        for item in items:
            for key in (
                "modelName",
                "agentName",
                "provisionedModelName",
                "inferenceProfileName",
                "name",
                "knowledgeBaseName",
            ):
                if item.get(key):
                    names.append(str(item[key]))
                    break
        return names

    def _get_data_catalog_names(
        self,
        data_catalogs: list[dict[str, Any]],
    ) -> list[str]:
        names: list[str] = []
        for catalog in data_catalogs:
            value = catalog.get("CatalogName") or catalog.get("Name")
            if value:
                names.append(str(value))
        return names

    def _get_named_values(
        self,
        items: list[dict[str, Any]],
        key: str,
    ) -> list[str]:
        return self._values.get_named_values(items, key)

    def _safe_client(
        self,
        service_name: str,
        region: str,
        permission_errors: list[str],
    ) -> Any | None:  # noqa: ANN401
        try:
            return self.session.create_client(
                service_name,
                region_name=region,
                audit_context=self.audit_context,
            )
        except Exception as exc:  # noqa: BLE001
            self._record_collection_error(
                permission_errors,
                method_name=f"{service_name}:CreateClient",
                exc=exc,
            )
            return None

    def _record_collection_error(
        self,
        errors: list[str],
        *,
        method_name: str,
        exc: Exception,
        require_evidence: bool = False,
    ) -> None:
        if not require_evidence and aws_errors.is_expected_absence_error(exc):
            return
        code = aws_errors.get_aws_error_code(exc) or exc.__class__.__name__
        errors.append(f"{method_name}:{code}")

    def _collect_items(
        self,
        pages: list[dict[str, Any]],
        key: str,
    ) -> list[dict[str, Any]]:
        return self._values.collect_dict_items(pages, key)

    def _limit_samples(self, values: list[str]) -> list[str]:
        return self._values.limit_samples(values)

    def _get_int(self, value: Any) -> int:  # noqa: ANN401
        return self._values.get_int(value)

    def _get_float(self, value: Any) -> float:  # noqa: ANN401
        return self._values.get_float(value)

    def get_available_regions(self) -> list[str]:  # noqa: D102
        if self._available_regions_cache is not None:
            return self._available_regions_cache
        if self.selected_regions:
            self._available_regions_cache = sorted(self.selected_regions)
            return self._available_regions_cache
        client = self.session.create_client(
            "ec2",
            region_name=self.session.get_region_name() or "us-east-1",
            audit_context=self.audit_context,
        )
        response = client.describe_regions(AllRegions=False)
        self._available_regions_cache = sorted(region["RegionName"] for region in response.get("Regions", []))
        return self._available_regions_cache
