"""Exact serverless implementation identities and registered Lambda ARN syntax."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from unio_collector.collector.protocol import UNIO_PROTOCOL
from unio_collector.privacy.leak.public.region import ARN_PART_COUNT, registered_arn_view
from unio_collector.privacy.serverless.lambda_cycle.contract import LambdaPrivacyContract
from unio_collector.privacy.serverless.lifecycle import LifecyclePrivacyContract
from unio_collector.privacy.serverless.polling import SqsPollingPrivacyContract

if TYPE_CHECKING:
    from unio_collector.privacy.closed_schema import ClosedProducerContract
IDENTITIES = {
    "lambda-cost-cycle-risk-review": ("LambdaCostCycleRiskScanner", "lambda_cost_cycle"),
    "sqs-lambda-polling-cost-review": ("SqsLambdaPollingCostReviewScanner", "serverless_polling"),
    "extended-support-and-eol-review": ("ExtendedSupportAndEolReviewScanner", "lifecycle.eol_scanner"),
}


class ServerlessScanContract:
    """Keep public implementation roles distinct from customer text and arbitrary ARNs."""

    @staticmethod
    def owns(contract: ClosedProducerContract) -> bool:
        """Require the existing selected closed serverless producer contract."""
        return isinstance(contract, (LambdaPrivacyContract, LifecyclePrivacyContract, SqsPollingPrivacyContract))

    @staticmethod
    def implementation(row: dict[str, Any]) -> bool:
        """Admit only exact source-declared class/module pairs under their actual AWS ID."""
        scanner = row.get("scanner_id")
        identity = IDENTITIES.get(scanner) if isinstance(scanner, str) else None
        return (
            identity is not None
            and row.get("provider_id", "aws") == "aws"
            and row.get("implementation_type") == "native"
            and row.get("implementation_class") == identity[0]
            and row.get("implementation_module") in {namespace + ".scanners." + identity[1] for namespace in UNIO_PROTOCOL.accepted_import_namespaces}
        )

    @staticmethod
    def arn_view(contract: ClosedProducerContract, suffix: str, value: str, tokens: frozenset[str], *, mask_regions: bool) -> str:
        """Mask only Lambda syntax in declared roles with complete registered-token ARNs.

        Account/resource text and token boundaries remain scanned. Unknown services,
        malformed ARNs, arbitrary fields and unregistered or suffixed tokens do not
        obtain this view. Archive bytes and raw security scans remain unchanged.
        """
        owned = (
            (isinstance(contract, LambdaPrivacyContract) and suffix in {"records[].function_arn", "records[].s3_notifications[].lambda_function_arn"})
            or (isinstance(contract, SqsPollingPrivacyContract) and suffix == "records[].function_arn")
            or (isinstance(contract, LifecyclePrivacyContract) and contract.service == "AWS Lambda" and suffix == "records[].arn")
        )
        regional = registered_arn_view(value, tokens)
        fallback = regional if mask_regions else value
        parts = value.split(":", 5)
        if not owned or len(parts) != ARN_PART_COUNT or parts[0] != "arn" or parts[2] != "lambda":
            return fallback
        if regional == value:
            return fallback
        return ":".join(("" if mask_regions else parts[3], parts[4], parts[5]))
