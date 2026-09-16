# noqa: D100
# pyright: reportAttributeAccessIssue=false
from __future__ import annotations

from typing import Any, TypeVar

from unio_collector.aws import errors as aws_errors

AuditRecordT = TypeVar("AuditRecordT")


class AuditServiceHelperMixin:  # noqa: D101
    def _collect_inspector_summary(
        self,
        region: str,
        permission_errors: list[str],
    ) -> dict[str, Any]:
        client = self.session.create_client(
            "inspector2",
            region_name=region,
            audit_context=self.audit_context,
        )
        response = self._safe_call(
            client,
            "batch_get_account_status",
            {"accountIds": [self.account_id]},
            permission_errors,
        )
        accounts = response.get("accounts", []) if response else []
        if not isinstance(accounts, list) or not accounts:
            return {"status": None, "resource_statuses": []}
        account = accounts[0]
        if not isinstance(account, dict):
            return {"status": None, "resource_statuses": []}
        state = account.get("state")
        if isinstance(state, dict) and state.get("status"):
            status = str(state["status"])
        else:
            raw_status = account.get("status")
            status = str(raw_status) if raw_status else None
        return {
            "status": status,
            "resource_statuses": self._get_inspector_resource_statuses(account),
        }

    def _collect_macie_summary(
        self,
        region: str,
        permission_errors: list[str],
    ) -> dict[str, Any]:
        client = self.session.create_client(
            "macie2",
            region_name=region,
            audit_context=self.audit_context,
        )
        session = self._safe_call(client, "get_macie_session", {}, permission_errors)
        if session is None:
            return {
                "status": None,
                "finding_publishing_frequency": None,
                "job_count": 0,
                "job_statuses": [],
                "job_status_counts": {},
                "sample_job_ids": [],
            }
        status = str(session.get("status") or "") or None
        jobs = self._collect_macie_jobs(client, permission_errors)
        return {
            "status": status,
            "finding_publishing_frequency": (str(session.get("findingPublishingFrequency")) if session.get("findingPublishingFrequency") else None),
            "job_count": len(jobs),
            "job_statuses": self._get_macie_job_statuses(jobs),
            "job_status_counts": self._get_macie_job_status_counts(jobs),
            "sample_job_ids": self._get_macie_job_ids(jobs),
        }

    def _collect_macie_jobs(
        self,
        client: Any,  # noqa: ANN401
        permission_errors: list[str],
    ) -> list[dict[str, Any]]:
        try:
            result = self._pagination.collect_token_pages(
                client,
                "list_classification_jobs",
                result_key="items",
                request_parameters={"maxResults": 50},
                request_cursor_key="nextToken",
                response_cursor_keys=("nextToken", "NextToken"),
            )
        except Exception as exc:  # noqa: BLE001
            self._append_collect_error(
                "list_classification_jobs",
                exc,
                permission_errors,
            )
            return []
        jobs: list[dict[str, Any]] = []
        for page in result.pages:
            page_jobs = page.get("items", [])
            if isinstance(page_jobs, list):
                jobs.extend(page_jobs)
        return jobs

    def _get_securityhub_standard_statuses(
        self,
        standards: list[dict[str, Any]],
    ) -> list[str]:
        return sorted(
            {str(standard.get("StandardsStatus")) for standard in standards if standard.get("StandardsStatus")},
        )

    def _get_inspector_resource_statuses(
        self,
        account: dict[str, Any],
    ) -> list[str]:
        resource_state = account.get("resourceState")
        if not isinstance(resource_state, dict):
            return []
        statuses: set[str] = set()
        for value in resource_state.values():
            if isinstance(value, dict) and value.get("status"):
                statuses.add(str(value["status"]))
            elif value:
                statuses.add(str(value))
        return sorted(statuses)

    def _get_macie_job_statuses(self, jobs: list[dict[str, Any]]) -> list[str]:
        return sorted(
            {str(job.get("jobStatus") or job.get("status")) for job in jobs if job.get("jobStatus") or job.get("status")},
        )

    def _get_macie_job_status_counts(
        self,
        jobs: list[dict[str, Any]],
    ) -> dict[str, int]:
        counts: dict[str, int] = {}
        for job in jobs:
            status = str(job.get("jobStatus") or job.get("status") or "").upper()
            if status:
                counts[status] = counts.get(status, 0) + 1
        return dict(sorted(counts.items()))

    def _get_macie_job_ids(self, jobs: list[dict[str, Any]]) -> list[str]:
        return [str(job.get("jobId") or job.get("jobName")) for job in jobs[:10] if job.get("jobId") or job.get("jobName")]

    def _collect_config_recorders(self, client: Any) -> list[dict[str, Any]]:  # noqa: ANN401
        response = client.describe_configuration_recorders()
        records = response.get("ConfigurationRecorders", [])
        return records if isinstance(records, list) else []

    def _collect_delivery_channels(self, client: Any) -> list[dict[str, Any]]:  # noqa: ANN401
        response = client.describe_delivery_channels()
        records = response.get("DeliveryChannels", [])
        return records if isinstance(records, list) else []

    def _collect_config_recorder_statuses(
        self,
        client: Any,  # noqa: ANN401
        permission_errors: list[str],
    ) -> list[dict[str, Any]]:
        try:
            response = client.describe_configuration_recorder_status()
        except Exception as exc:  # noqa: BLE001
            self._append_collect_error(
                "describe_configuration_recorder_status",
                exc,
                permission_errors,
            )
            return []
        records = response.get("ConfigurationRecordersStatus", [])
        return records if isinstance(records, list) else []

    def _collect_config_rules(self, client: Any) -> list[dict[str, Any]]:  # noqa: ANN401
        records: list[dict[str, Any]] = []
        result = self._pagination.collect_token_pages(
            client,
            "describe_config_rules",
            result_key="ConfigRules",
        )
        for page in result.pages:
            config_rules = page.get("ConfigRules", [])
            if isinstance(config_rules, list):
                records.extend(config_rules)
        return records

    def _collect_conformance_packs(self, client: Any) -> list[dict[str, Any]]:  # noqa: ANN401
        records: list[dict[str, Any]] = []
        result = self._pagination.collect_token_pages(
            client,
            "describe_conformance_packs",
            result_key="ConformancePackDetails",
        )
        for page in result.pages:
            packs = page.get("ConformancePackDetails", [])
            if isinstance(packs, list):
                records.extend(packs)
        return records

    def _get_config_recording_frequency(self, recorder: dict[str, Any]) -> str:
        recording_mode = recorder.get("recordingMode")
        if not isinstance(recording_mode, dict):
            return ""
        return str(recording_mode.get("recordingFrequency") or "").upper()

    def _get_config_recording_frequency_values(
        self,
        recorders: list[dict[str, Any]],
    ) -> list[str]:
        return sorted(
            {frequency for recorder in recorders if (frequency := self._get_config_recording_frequency(recorder))},
        )

    def _get_config_delivery_frequency_values(
        self,
        delivery_channels: list[dict[str, Any]],
    ) -> list[str]:
        frequencies: set[str] = set()
        for channel in delivery_channels:
            properties = channel.get("configSnapshotDeliveryProperties")
            if not isinstance(properties, dict):
                continue
            frequency = properties.get("deliveryFrequency")
            if frequency:
                frequencies.add(str(frequency))
        return sorted(frequencies)

    def _get_config_recorder_last_status_values(
        self,
        statuses: list[dict[str, Any]],
    ) -> list[str]:
        return sorted(
            {str(status.get("lastStatus")) for status in statuses if status.get("lastStatus")},
        )

    def _collect_web_acls(self, client: Any, scope: str) -> list[dict[str, Any]]:  # noqa: ANN401
        records: list[dict[str, Any]] = []
        result = self._pagination.collect_pages(
            client,
            "list_web_acls",
            result_key="WebACLs",
            request_parameters={"Scope": scope},
        )
        for page in result.pages:
            web_acls = page.get("WebACLs", [])
            if isinstance(web_acls, list):
                records.extend(web_acls)
        return records

    def _collect_cloudtrail_event_data_stores(
        self,
        client: Any,  # noqa: ANN401
        permission_errors: list[str],
    ) -> list[dict[str, Any]]:
        try:
            result = self._pagination.collect_token_pages(
                client,
                "list_event_data_stores",
                result_key="EventDataStores",
            )
        except Exception as exc:  # noqa: BLE001
            self._append_collect_error(
                "list_event_data_stores",
                exc,
                permission_errors,
            )
            return []
        stores: list[dict[str, Any]] = []
        for page in result.pages:
            page_stores = page.get("EventDataStores", [])
            if isinstance(page_stores, list):
                stores.extend(
                    self._collect_cloudtrail_event_data_store_details(
                        client,
                        page_stores,
                        permission_errors,
                    ),
                )
        return stores

    def _collect_cloudtrail_event_data_store_details(
        self,
        client: Any,  # noqa: ANN401
        stores: list[Any],
        permission_errors: list[str],
    ) -> list[dict[str, Any]]:
        details: list[dict[str, Any]] = []
        for store in stores:
            if not isinstance(store, dict):
                continue
            identifier = store.get("EventDataStoreArn") or store.get("EventDataStoreId") or store.get("Name")
            if not identifier:
                details.append(store)
                continue
            detail = self._safe_call(
                client,
                "get_event_data_store",
                {"EventDataStore": str(identifier)},
                permission_errors,
            )
            details.append({**store, **detail} if detail else store)
        return details

    def _safe_call(
        self,
        client: Any,  # noqa: ANN401
        method_name: str,
        kwargs: dict[str, Any],
        errors: list[str],
    ) -> dict[str, Any] | None:
        try:
            response = getattr(client, method_name)(**kwargs)
        except Exception as exc:  # noqa: BLE001
            self._append_collect_error(method_name, exc, errors)
            return None
        return response if isinstance(response, dict) else None

    def _append_collect_error(
        self,
        method_name: str,
        error: Exception,
        errors: list[str],
    ) -> None:
        if aws_errors.is_expected_absence_error(error):
            return
        code = aws_errors.get_aws_error_code(error) or error.__class__.__name__
        errors.append(f"{method_name}:{code}")

    def _last_error_is_permission_denied(
        self,
        errors: list[str],
        previous_count: int,
        *,
        method_name: str,
    ) -> bool:
        if len(errors) <= previous_count:
            return False
        prefix = f"{method_name}:"
        error_code = errors[-1].removeprefix(prefix)
        return errors[-1].startswith(prefix) and aws_errors.is_permission_error_code(
            error_code,
        )

    def _count_trails_with_data_events(
        self,
        event_selectors: list[dict[str, Any]],
    ) -> int:
        return sum(1 for selectors in event_selectors if self._count_data_event_selectors(selectors) > 0 or selectors.get("AdvancedEventSelectors"))

    def _count_data_event_selectors(self, selectors: dict[str, Any]) -> int:
        event_selectors = selectors.get("EventSelectors", [])
        if not isinstance(event_selectors, list):
            return 0
        return sum(len(selector.get("DataResources", []) or []) for selector in event_selectors if isinstance(selector, dict))

    def _count_data_resource_values(self, selectors: dict[str, Any]) -> int:
        event_selectors = selectors.get("EventSelectors", [])
        if not isinstance(event_selectors, list):
            return 0
        count = 0
        for selector in event_selectors:
            if not isinstance(selector, dict):
                continue
            for resource in selector.get("DataResources", []) or []:
                if isinstance(resource, dict):
                    values = resource.get("Values", [])
                    if isinstance(values, list):
                        count += len(values)
        return count

    def _count_management_event_selectors(self, selectors: dict[str, Any]) -> int:
        event_selectors = selectors.get("EventSelectors", [])
        if not isinstance(event_selectors, list):
            return 0
        return sum(1 for selector in event_selectors if isinstance(selector, dict) and bool(selector.get("IncludeManagementEvents", True)))
