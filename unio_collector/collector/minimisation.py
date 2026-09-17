from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class EvidenceMinimisationOptions:  # noqa: D101
    redact_before_export: bool = False
    minimise_export: str = "none"
    exclude_services: tuple[str, ...] = ()
    no_cost_data: bool = False

    @classmethod
    def from_args(cls, args: object) -> EvidenceMinimisationOptions:  # noqa: D102
        return cls(
            redact_before_export=bool(
                getattr(args, "redact_before_export", False),
            ),
            minimise_export=str(getattr(args, "minimise_export", None) or "none"),
            exclude_services=tuple(
                sorted(
                    {normalize_service_name(value) for value in getattr(args, "exclude_service", []) or [] if str(value).strip()},
                ),
            ),
            no_cost_data=bool(getattr(args, "no_cost_data", False)),
        )

    def convert_to_manifest_payload(self) -> dict[str, object]:  # noqa: D102
        enabled = self.redact_before_export or self.minimise_export != "none" or bool(self.exclude_services) or self.no_cost_data
        return {
            "enabled": enabled,
            "mode": self.minimise_export,
            "redact_before_export": self.redact_before_export,
            "excluded_services": list(self.exclude_services),
            "no_cost_data": self.no_cost_data,
        }

    def build_limitations(self) -> list[dict[str, object]]:  # noqa: D102
        limitations: list[dict[str, object]] = [
            {
                "type": "service_excluded",
                "service": service,
                "reason": f"Service evidence was excluded by collector option: {service}.",
            }
            for service in self.exclude_services
        ]
        if self.no_cost_data:
            limitations.append(
                {
                    "type": "cost_data_excluded",
                    "service": "cost-explorer",
                    "reason": "Cost data was excluded by collector option --no-cost-data.",
                },
            )
        if self.redact_before_export:
            limitations.append(
                {
                    "type": "redacted_before_export",
                    "service": "all",
                    "reason": "Evidence was redacted before export; raw identifiers may be unavailable.",
                },
            )
        if self.minimise_export != "none":
            limitations.append(
                {
                    "type": "minimised_export",
                    "service": "all",
                    "reason": f"Collector minimisation mode was {self.minimise_export}.",
                },
            )
        return limitations


def normalize_service_name(value: object) -> str:  # noqa: D103
    return "-".join(str(value).strip().lower().replace("_", "-").split())
