"""Identity-bound treatment of neutral network topology and coverage."""

from __future__ import annotations

from dataclasses import replace
from functools import lru_cache
from ipaddress import ip_address
from typing import TYPE_CHECKING, Any, ClassVar, Self

from botocore.loaders import Loader

from unio_collector.collector.protocol import UNIO_PROTOCOL
from unio_collector.privacy.closed_schema import PREFIX, ClosedProducerContract
from unio_collector.privacy.network.facts import NetworkFactsPolicy
from unio_collector.privacy.network.fields import VOCABULARIES
from unio_collector.scanners.scanner.schema import admit_evidence_schema

if TYPE_CHECKING:
    from unio_collector.privacy.treatment_decision import PrivacyTreatmentDecision


@lru_cache(maxsize=1)
def public_services() -> frozenset[str]:
    """Enumerate reviewed AWS service names over finite installed SDK regions."""
    endpoints = Loader().load_data("endpoints")
    regions = {region for partition in endpoints["partitions"] for region in partition["regions"]}
    services = ("s3", "dynamodb", "ecr.api", "ecr.dkr", "ec2", "kms", "logs", "monitoring", "secretsmanager", "ssm", "ssmmessages", "sts")
    return frozenset(f"com.amazonaws.{region}.{service}" for region in regions for service in services)


class NetworkPrivacyContract(ClosedProducerContract):
    """Preflight kind-dependent facts before profile-specific topology removal."""

    collection_names: ClassVar[frozenset[str]]
    scanner_id: ClassVar[str]
    evidence_module: ClassVar[str]
    evidence_type: ClassVar[str]

    @classmethod
    def for_record(cls, record: dict[str, Any]) -> Self | None:
        """Require the exact AWS scanner and registered legacy producer identity."""
        if record.get("scanner_id") != cls.scanner_id:
            return None
        schema = admit_evidence_schema(record)
        if (
            schema is not None
            or record.get("provider_id", "aws") != "aws"
            or (record.get("evidence_module"), record.get("evidence_type"))
            not in {(f"{namespace}.{cls.evidence_module}", cls.evidence_type) for namespace in UNIO_PROTOCOL.accepted_import_namespaces}
        ):
            message = "Network privacy contract requires its matching registered AWS evidence identity."
            raise ValueError(message)
        return cls()

    @classmethod
    def _valid(cls, value: object, kind: str, *, nullable: bool) -> bool:
        """Keep finite metadata and non-negative count types closed."""
        if value is None:
            return nullable
        if kind == "resource_kind":
            return isinstance(value, str) and value in cls.collection_names
        if kind == "operation":
            return isinstance(value, str) and value in VOCABULARIES["operation"] | cls.collection_names
        if kind in VOCABULARIES:
            return isinstance(value, str) and value in VOCABULARIES[kind]
        return super()._valid(value, kind, nullable=nullable)

    def unknown_paths(self, value: Any, member: str, suffix: str = "") -> list[str]:  # noqa: ANN401
        """Validate facts against their own kind, never against the union of fields."""
        if suffix == "topology[].resources[].facts":
            return []
        failures = super().unknown_paths(value, member, suffix)
        if suffix == "topology[].resources[]" and isinstance(value, dict):
            failures.extend(NetworkFactsPolicy.unknown_paths(value.get("facts"), value.get("kind"), member + PREFIX[1:] + "." + suffix + ".facts"))
        return failures

    def resolve(self, path: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Protect whole diagnostics and sensitive leaves without losing limitation presence."""
        decision = super().resolve(path, profile)
        if decision is not None and decision.category in {
            "network_identity",
            "network_service",
            "network_gateway",
            "network_text",
            "cidr",
            "ipv4",
            "tag_key",
            "tag_value",
        }:
            return replace(decision, treatment="tokenise")
        return decision

    def is_tag_record(self, path: str) -> bool:
        """Reuse existing tag-key policy only at the exact preflighted network paths."""
        return path in {PREFIX + ".topology[].resources[].facts.Tags[]", PREFIX + ".topology[].resources[].facts.TagSet[]"}

    def resolve_string(self, path: str, value: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Preserve only explicit public constants; tokenize customer values consistently."""
        decision = self.resolve(path, profile)
        if decision is None:
            return None
        category = decision.category
        if (category == "network_gateway" and value == "local") or (category == "cidr" and value in {"0.0.0.0/0", "::/0"}):
            return replace(decision, treatment="preserve", category="safe_metadata")
        if category in {"network_service", "network_identity"} and profile == "standard" and value in public_services():
            return replace(decision, treatment="preserve", category="safe_metadata")
        if category == "network_identity":
            try:
                ip_address(value)
            except ValueError:
                category = "resource_id"
            else:
                category = "ipv4"
        elif category in {"network_gateway", "network_service"}:
            category = "resource_id"
        elif category == "network_text":
            category = "free_text"
        return replace(decision, category=category)
