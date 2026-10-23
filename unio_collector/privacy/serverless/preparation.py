"""Derive existing Lambda bucket-reference semantics before protecting opaque environment text."""

from __future__ import annotations

from typing import Any

from unio_collector.aws.lambda_cost.cycle.environment import environment_mentions_bucket
from unio_collector.privacy.serverless.lambda_cycle.contract import LambdaPrivacyContract


class LambdaInputPreparation:
    """Copy only admitted Lambda records; unknown inputs retain ordinary fail-closed checks."""

    @classmethod
    def prepare(cls, value: object, member: str) -> object:
        """Retain source bytes/objects and never derive facts from unknown or malformed fields."""
        if member != "scan-result/scanner-evidence.json" or not isinstance(value, dict) or not isinstance(value.get("scanner_evidence"), list):
            return value
        rows = []
        for row in value["scanner_evidence"]:
            contract = LambdaPrivacyContract.for_record(row) if isinstance(row, dict) else None
            if contract is None or contract.unknown_record_paths(row, member):
                rows.append(row)
                continue
            payload = row["payload"]
            rows.append({**row, "payload": {**payload, "records": [cls._record(record) for record in payload.get("records", [])]}})
        return {**value, "scanner_evidence": rows}

    @staticmethod
    def _record(record: dict[str, Any]) -> dict[str, Any]:
        """Carry only the previous analyzer's coarse fact; never retain raw text in progress/logs."""
        match = environment_mentions_bucket(record["environment_variables"], (item["bucket_name"] for item in record["s3_notifications"]))
        declared = record.get("environment_bucket_match")
        if declared is not None and declared != match:
            message = "Lambda environment/bucket reference metadata conflicts with source evidence."
            raise ValueError(message)
        return {**record, "environment_bucket_match": match}
