from __future__ import annotations  # noqa: D100

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, ClassVar

if TYPE_CHECKING:
    from unio_collector.collector.package.manifest import CollectorPackageManifest


@dataclass(frozen=True)
class CollectorProviderBoundary:
    """Enforce the provider implementations admitted to the collector wheel."""

    included_implementations: tuple[str, ...]

    PROVIDER_ROOT: ClassVar[str] = "unio_collector.providers"
    PROVIDER_IMPLEMENTATION_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"^unio_collector\.providers\.[a-z][a-z0-9_]*$",
    )
    PROVIDER_NEUTRAL_PREFIXES: ClassVar[tuple[str, ...]] = (
        "unio_collector.providers.capability",
        "unio_collector.providers.evidence",
        "unio_collector.providers.finding",
        "unio_collector.providers.finding_source",
        "unio_collector.providers.identifiers",
        "unio_collector.providers.identity",
        "unio_collector.providers.known",
        "unio_collector.providers.location",
        "unio_collector.providers.registry",
        "unio_collector.providers.report_metadata",
        "unio_collector.providers.resource",
        "unio_collector.providers.runtime",
        "unio_collector.providers.scanner_catalog",
        "unio_collector.providers.scope",
        "unio_collector.providers.selection",
        "unio_collector.providers.types",
    )

    @classmethod
    def from_manifest(
        cls,
        manifest: CollectorPackageManifest,
    ) -> CollectorProviderBoundary:
        """Build the executable boundary declared by a collector manifest."""
        return cls(tuple(manifest.included_provider_implementations))

    def manifest_errors(self) -> tuple[str, ...]:
        """Return validation errors for malformed implementation entries."""
        errors: list[str] = []
        if len(self.included_implementations) != len(set(self.included_implementations)):
            errors.append("Collector provider implementation allow-list contains duplicates.")
        neutral = set(self.PROVIDER_NEUTRAL_PREFIXES)
        for prefix in self.included_implementations:
            if self.PROVIDER_IMPLEMENTATION_PATTERN.fullmatch(prefix) is None:
                errors.append(
                    f"Collector provider implementation must be a direct provider namespace: {prefix}",
                )
            elif prefix in neutral:
                errors.append(
                    f"Collector provider implementation overlaps a provider-neutral contract: {prefix}",
                )
        return tuple(errors)

    def is_module_allowed(self, module: str) -> bool:
        """Return whether a provider module satisfies the collector boundary."""
        if module == self.PROVIDER_ROOT:
            return True
        if not module.startswith(f"{self.PROVIDER_ROOT}."):
            return True
        return self._matches_prefixes(
            module,
            (*self.PROVIDER_NEUTRAL_PREFIXES, *self.included_implementations),
        )

    def module_violations(self, modules: tuple[str, ...]) -> tuple[str, ...]:
        """Return deterministic provider modules outside the executable allow-list."""
        return tuple(
            sorted(
                {module for module in modules if module and not self.is_module_allowed(module)},
            ),
        )

    def wheel_member_violations(self, members: tuple[str, ...]) -> tuple[str, ...]:
        """Return Python wheel members that violate the provider boundary."""
        violations: list[str] = []
        for member in members:
            module = self._module_from_source_path(member)
            if module and not self.is_module_allowed(module):
                violations.append(member)
        return tuple(sorted(set(violations)))

    @staticmethod
    def _matches_prefixes(module: str, prefixes: tuple[str, ...]) -> bool:
        return any(module == prefix or module.startswith(f"{prefix}.") for prefix in prefixes)

    @staticmethod
    def _module_from_source_path(path: str) -> str:
        if not path.endswith(".py"):
            return ""
        module = path[:-3].replace("/", ".")
        if module.endswith(".__init__"):
            return module.removesuffix(".__init__")
        return module
