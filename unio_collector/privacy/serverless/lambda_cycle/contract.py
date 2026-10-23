"""Closed actual Lambda inventory with opaque environment data and preserved coarse analysis."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, Any, ClassVar, Self

from unio_collector.collector.protocol import UNIO_PROTOCOL
from unio_collector.privacy.closed_schema import PREFIX
from unio_collector.privacy.serverless.lambda_cycle.fields import EVENT, FIELDS, NOTIFICATION
from unio_collector.privacy.serverless.lambda_cycle.literals import SOURCE_TYPES, VOCABULARIES, s3_events
from unio_collector.privacy.serverless.lifecycle_literals import lambda_runtimes
from unio_collector.privacy.serverless.metric import ServerlessMetricContract
from unio_collector.scanners.scanner.schema import admit_evidence_schema

if TYPE_CHECKING:
    from unio_collector.privacy.treatment_decision import PrivacyTreatmentDecision

SCANNER = "lambda-cost-cycle-risk-review"
MAPS = frozenset({"records[].environment_variables", "records[].tags", "records[].tag_evidence.tags"})
REQUIRED = frozenset(
    {
        "function_name",
        "function_arn",
        "account_id",
        "region",
        "runtime",
        "memory_mb",
        "timeout_seconds",
        "architectures",
        "reserved_concurrency",
        "provisioned_concurrency",
        "event_sources",
        "s3_notifications",
        "destination_config",
        "environment_variables",
        "tags",
        "metric_summaries",
    }
)


class LambdaPrivacyContract(ServerlessMetricContract):
    """Protect every arbitrary string; retain only fixed controls and the prior analysis heuristic."""

    fields: ClassVar[dict[str, tuple[str, str, bool]]] = FIELDS
    roles: ClassVar[frozenset[tuple[str, str, str]]] = frozenset(
        {
            ("AWS/Lambda", "Invocations", "Sum"),
            ("AWS/Lambda", "Duration", "Average"),
            ("AWS/Lambda", "Errors", "Sum"),
            ("AWS/Lambda", "Throttles", "Sum"),
            ("AWS/Logs", "IncomingBytes", "Sum"),
        }
    )

    @classmethod
    def for_record(cls, record: dict[str, Any]) -> Self | None:
        """Require the exact legacy AWS inventory identity before any payload inspection."""
        if record.get("scanner_id") != SCANNER:
            return None
        identities = {(namespace + ".scanners.inventory_evidence", "InventoryEvidence") for namespace in UNIO_PROTOCOL.accepted_import_namespaces}
        if (
            admit_evidence_schema(record) is not None
            or record.get("provider_id", "aws") != "aws"
            or (record.get("evidence_module"), record.get("evidence_type")) not in identities
        ):
            message = "Lambda privacy requires its matching legacy AWS evidence identity."
            raise ValueError(message)
        return cls()

    @classmethod
    def _valid(cls, value: object, kind: str, *, nullable: bool) -> bool:
        if value is None:
            return nullable
        if kind == "string_map":
            return isinstance(value, dict) and all(isinstance(key, str) and isinstance(item, str) for key, item in value.items())
        if kind in VOCABULARIES:
            return isinstance(value, str) and value in VOCABULARIES[kind]
        if kind == "lambda_s3_event":
            return isinstance(value, str) and value in s3_events()
        return super()._valid(value, kind, nullable=nullable)

    def unknown_paths(self, value: Any, member: str, suffix: str = "") -> list[str]:  # noqa: ANN401
        """Validate declared maps, required legacy fields and conditional tag evidence."""
        path = member + PREFIX[1:] + "." + suffix
        if suffix in MAPS:
            return [] if self._valid(value, "string_map", nullable=False) else [path]
        failures = super().unknown_paths(value, member, suffix)
        if not isinstance(value, dict):
            return failures
        if suffix == "records[]" and not REQUIRED.issubset(value):
            failures.append(path)
        if suffix == NOTIFICATION and not {"bucket_name", "lambda_function_arn"}.issubset(value):
            failures.append(path)
        if suffix == "records[].tag_evidence" and (set(value) != {"state", "tags", "limitation"} or (value.get("state") != "known" and value.get("tags"))):
            failures.append(path)
        return failures

    def mapping_key_category(self, path: str) -> str | None:
        """Admit dynamic string keys only for the three exact declared protected maps."""
        suffix = path.removeprefix(PREFIX + ".")
        return ("resource_name" if suffix.endswith("environment_variables") else "tag_key") if suffix in MAPS else None

    def resolve(self, path: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Protect entire environment/filter prose and arbitrary tag values, including keys."""
        for suffix in MAPS:
            if path.startswith(PREFIX + "." + suffix + "."):
                decision = super().resolve(PREFIX + ".records[].function_name", profile)
                if decision is not None:
                    return replace(decision, category="free_text" if suffix.endswith("environment_variables") else "tag_value")
        return super().resolve(path, profile)

    def resolve_string(self, path: str, value: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Keep only SDK runtime and finite operational controls public at their exact roles."""
        decision = self.resolve(path, profile)
        return (
            replace(decision, treatment="preserve", category="safe_metadata")
            if decision is not None and self.is_literal(path.removeprefix(PREFIX + "."), value)
            else decision
        )

    def is_literal(self, suffix: str, value: object) -> bool:
        """Never exempt arbitrary environment values, tag data, names or unknown members."""
        if suffix == "records[].runtime":
            return isinstance(value, str) and value in lambda_runtimes()
        if suffix == EVENT + ".source_type":
            return isinstance(value, str) and value in SOURCE_TYPES
        spec = self.fields.get(suffix)
        if spec is not None and (spec[0] in VOCABULARIES or spec[0] == "lambda_s3_event"):
            return self._valid(value, spec[0], nullable=spec[2])
        return super().is_literal(suffix, value)
