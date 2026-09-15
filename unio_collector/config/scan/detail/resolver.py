from __future__ import annotations  # noqa: D100

from copy import deepcopy
from typing import TYPE_CHECKING, Any

from unio_collector.config.scan.detail.lower_precedence import (
    OverriddenLowerPrecedenceValue,
)
from unio_collector.config.scan.detail.profile import (
    FULL_SCAN_DETAIL_PROFILE,
    SCAN_DETAIL_OPTION_CONTRACTS,
    SCAN_DETAIL_PROFILE_IDS,
    SCAN_DETAIL_PROFILES,
    ScanDetailProfile,
)
from unio_collector.config.scan.detail.resolution_result import ScanDetailOptionsResolution
from unio_collector.config.scan.detail.selection import ScanDetailProfileSelection
from unio_collector.config.scan.detail.source import ScanDetailProfileSource
from unio_collector.config.schema.scanner_option_names import (
    get_known_scanner_option_names,
)
from unio_collector.scanners.registry.definitions import SCANNERS

if TYPE_CHECKING:
    from unio_collector.config.scan.detail.contract import ScanDetailOptionContract
    from unio_collector.config.scan.detail.override_provenance import ScannerCliOverride


class ScanDetailProfileResolver:
    """Resolve and apply scanner detail profiles to scanner options."""

    def get_profile(self, profile_id: str | None) -> ScanDetailProfile:  # noqa: D102
        self.validate_contract()
        value = (profile_id or FULL_SCAN_DETAIL_PROFILE).strip().lower()
        profile = SCAN_DETAIL_PROFILES.get(value)
        if profile is None:
            allowed = ", ".join(SCAN_DETAIL_PROFILE_IDS)
            msg = f"Scan detail profile must be one of: {allowed}."
            raise ValueError(msg)
        return profile

    def resolve_selection(
        self,
        *,
        cli_profile: object,
        config_profile: str,
        config_profile_is_explicit: bool,
        preset_profile: object,
    ) -> ScanDetailProfileSelection:
        """Resolve the selected profile while all source inputs are distinct."""
        if cli_profile not in (None, ""):
            profile_id = self.get_profile(str(cli_profile)).profile_id
            source = ScanDetailProfileSource.EXPLICIT_CLI
        elif config_profile_is_explicit:
            profile_id = self.get_profile(config_profile).profile_id
            source = ScanDetailProfileSource.CONFIG
        elif preset_profile not in (None, ""):
            profile_id = self.get_profile(str(preset_profile)).profile_id
            source = ScanDetailProfileSource.PRESET
        else:
            profile_id = self.get_profile(FULL_SCAN_DETAIL_PROFILE).profile_id
            source = ScanDetailProfileSource.DEFAULT
        return ScanDetailProfileSelection(profile_id, source)

    def apply_profile(  # noqa: D102
        self,
        options: dict[str, dict[str, Any]],
        profile_id: str | None,
    ) -> dict[str, dict[str, Any]]:
        profile = self.get_profile(profile_id)
        updated = {scanner_id: dict(scanner_options) for scanner_id, scanner_options in options.items()}
        for default in profile.scanner_option_defaults:
            updated.setdefault(default.scanner_id, {}).setdefault(
                default.option_name,
                default.value,
            )
        for override in profile.scanner_option_overrides:
            updated.setdefault(override.scanner_id, {})[override.option_name] = override.value
        return updated

    def resolve_options(
        self,
        scanner_yaml: dict[str, dict[str, Any]],
        profile_id: str | None,
        *,
        profile_is_explicit: bool,
    ) -> dict[str, dict[str, Any]]:
        """Resolve profile defaults, YAML, and an optional authoritative profile."""
        source = ScanDetailProfileSource.EXPLICIT_CLI if profile_is_explicit else ScanDetailProfileSource.DEFAULT
        selection = ScanDetailProfileSelection(
            self.get_profile(profile_id).profile_id,
            source,
        )
        return self.resolve_options_with_audit(scanner_yaml, selection).options

    def resolve_options_with_audit(
        self,
        scanner_yaml: dict[str, dict[str, Any]],
        selection: ScanDetailProfileSelection,
    ) -> ScanDetailOptionsResolution:
        """Resolve options and record YAML displaced by an explicit profile."""
        profile = self.get_profile(selection.profile_id)
        options = self.apply_profile({}, profile.profile_id)
        if profile.profile_id == FULL_SCAN_DETAIL_PROFILE and not selection.authoritative:
            for contract in SCAN_DETAIL_OPTION_CONTRACTS:
                if contract.full_value_requires_explicit_selection:
                    options.get(contract.scanner_id, {}).pop(
                        contract.option_name,
                        None,
                    )
        for scanner_id, scanner_options in deepcopy(scanner_yaml).items():
            options.setdefault(scanner_id, {}).update(scanner_options)
        if not selection.authoritative:
            return ScanDetailOptionsResolution(options=options)
        overridden: list[OverriddenLowerPrecedenceValue] = []
        for override in profile.scanner_option_overrides:
            supplied_options = scanner_yaml.get(override.scanner_id, {})
            if override.option_name in supplied_options and supplied_options[override.option_name] != override.value:
                overridden.append(
                    OverriddenLowerPrecedenceValue(
                        scanner_id=override.scanner_id,
                        option_name=override.option_name,
                        previous_source="scanner_yaml",
                        previous_value=supplied_options[override.option_name],
                        effective_source="explicit_cli_profile",
                        effective_value=override.value,
                    ),
                )
            options.setdefault(override.scanner_id, {})[override.option_name] = override.value
        return ScanDetailOptionsResolution(
            options=options,
            overridden_lower_precedence_values=tuple(
                sorted(overridden, key=lambda item: item.option_key),
            ),
        )

    def build_resolution_summary(
        self,
        options: dict[str, dict[str, Any]],
        profile_id: str | None,
        *,
        profile_is_explicit: bool,
        profile_source: ScanDetailProfileSource | str | None = None,
        overridden_lower_precedence_values: tuple[
            OverriddenLowerPrecedenceValue,
            ...,
        ] = (),
        scanner_cli_overrides: tuple[ScannerCliOverride, ...] = (),
    ) -> dict[str, Any]:
        """Describe normalized effective coverage for the selected profile."""
        profile = self.get_profile(profile_id)
        configured: dict[str, dict[str, object]] = {}
        effective: dict[str, dict[str, object]] = {}
        inactive: list[str] = []
        mismatches: list[str] = []
        for contract in SCAN_DETAIL_OPTION_CONTRACTS:
            scanner_options = options.get(contract.scanner_id, {})
            expected = contract.full_value if profile.profile_id == FULL_SCAN_DETAIL_PROFILE else contract.development_value
            implicit_default = (
                contract.development_value
                if profile.profile_id == FULL_SCAN_DETAIL_PROFILE and not profile_is_explicit and contract.full_value_requires_explicit_selection
                else expected
            )
            raw_value = scanner_options.get(contract.option_name, implicit_default)
            effective_value, is_active = self._normalize_effective_value(
                scanner_options,
                contract.scanner_id,
                contract.option_name,
                raw_value,
                profile.profile_id,
            )
            expected_value, _ = self._normalize_effective_value(
                scanner_options,
                contract.scanner_id,
                contract.option_name,
                expected,
                profile.profile_id,
            )
            configured.setdefault(contract.scanner_id, {})[contract.option_name] = raw_value
            effective.setdefault(contract.scanner_id, {})[contract.option_name] = effective_value
            option_key = f"{contract.scanner_id}.{contract.option_name}"
            if not is_active:
                inactive.append(option_key)
            elif effective_value != expected_value:
                mismatches.append(option_key)
        contract_keys = {f"{contract.scanner_id}.{contract.option_name}" for contract in SCAN_DETAIL_OPTION_CONTRACTS}
        attributable_overrides = [
            override
            for override in scanner_cli_overrides
            if override.option_key in contract_keys and options.get(override.scanner_id, {}).get(override.option_name) == override.value
        ]
        resolved_source = (
            ScanDetailProfileSource(profile_source)
            if profile_source is not None
            else (ScanDetailProfileSource.EXPLICIT_CLI if profile_is_explicit else ScanDetailProfileSource.DEFAULT)
        )
        return {
            "profile_id": profile.profile_id,
            "profile_source": resolved_source.value,
            "explicit_cli_selection": profile_is_explicit,
            "authoritative": profile_is_explicit,
            "canonical": not mismatches,
            "configured_profile_owned_options": configured,
            "effective_profile_owned_options": effective,
            "inactive_profile_owned_options": sorted(inactive),
            "overridden_lower_precedence_values": [value.convert_to_dict() for value in overridden_lower_precedence_values],
            "higher_precedence_scanner_cli_overrides": [override.convert_to_dict() for override in attributable_overrides],
            "coverage_mismatches": sorted(mismatches),
        }

    def validate_contract(self) -> None:
        """Fail closed when scan-detail ownership metadata drifts."""
        keys: set[tuple[str, str]] = set()
        for contract in SCAN_DETAIL_OPTION_CONTRACTS:
            key = (contract.scanner_id, contract.option_name)
            if contract.scanner_id not in SCANNERS:
                msg = f"Unknown scan-detail contract scanner: {contract.scanner_id}."
                raise ValueError(msg)
            if contract.option_name not in get_known_scanner_option_names(
                contract.scanner_id,
            ):
                msg = f"Unknown scan-detail contract option: {contract.scanner_id}.{contract.option_name}."
                raise ValueError(msg)
            if key in keys:
                msg = f"Duplicate scan-detail contract ownership: {contract.scanner_id}.{contract.option_name}."
                raise ValueError(msg)
            keys.add(key)
            self._validate_contract_values(contract)
            if contract.full_value_requires_explicit_selection and not contract.full_value_is_authoritative:
                msg = f"Explicit-only scan-detail full value must be authoritative: {contract.scanner_id}.{contract.option_name}."
                raise ValueError(msg)
        performance_keys = {(default.scanner_id, default.option_name) for default in SCAN_DETAIL_PROFILES["development"].scanner_option_defaults}
        overlap = sorted(keys & performance_keys)
        if overlap:
            scanner_id, option_name = overlap[0]
            msg = f"Scan-detail coverage ownership overlaps a performance default: {scanner_id}.{option_name}."
            raise ValueError(msg)
        for contract in SCAN_DETAIL_OPTION_CONTRACTS:
            if contract.full_value_is_authoritative:
                continue
            controlling_contracts = [
                candidate for candidate in SCAN_DETAIL_OPTION_CONTRACTS if candidate.scanner_id == contract.scanner_id and candidate.full_value_is_authoritative
            ]
            if not controlling_contracts:
                msg = f"Conditionally inactive scan-detail option has no authoritative controlling option: {contract.scanner_id}.{contract.option_name}."
                raise ValueError(msg)

    def _validate_contract_values(
        self,
        contract: ScanDetailOptionContract,
    ) -> None:
        development_value = contract.development_value
        full_value = contract.full_value
        if full_value is not None and type(development_value) is not type(full_value):
            msg = f"Incompatible scan-detail contract value types: {contract.scanner_id}.{contract.option_name}."
            raise ValueError(msg)
        allowed_values = contract.allowed_values
        if allowed_values is None:
            return
        for value in (development_value, full_value):
            if value not in allowed_values:
                msg = f"Unsupported scan-detail contract value {value!r} for {contract.scanner_id}.{contract.option_name}."
                raise ValueError(msg)

    def _normalize_effective_value(
        self,
        scanner_options: dict[str, Any],
        scanner_id: str,
        option_name: str,
        raw_value: object,
        profile_id: str,
    ) -> tuple[object, bool]:
        if profile_id != FULL_SCAN_DETAIL_PROFILE:
            return raw_value, True
        lambda_value = self._normalize_lambda_coverage_value(
            scanner_id,
            option_name,
            raw_value,
        )
        if lambda_value is not None:
            return lambda_value, True
        if scanner_id.startswith("cloudwatch-"):
            metric_mode = scanner_options.get("metric_detail_mode", "full")
            if metric_mode == "full":
                if option_name in {
                    "max_metric_log_groups_per_region",
                    "max_metric_log_groups",
                }:
                    return 0, True
                if option_name == "metric_prioritization_scope":
                    return "inactive", False
        if scanner_id in {
            "s3-lifecycle-cost-review",
            "s3-versioning-and-replication-review",
        }:
            lifecycle_mode = scanner_options.get("lifecycle_detail_mode", "full")
            if lifecycle_mode == "full" and option_name == "prioritized_lifecycle_bucket_count":
                return "inactive", False
        return raw_value, True

    def _normalize_lambda_coverage_value(
        self,
        scanner_id: str,
        option_name: str,
        raw_value: object,
    ) -> object | None:
        if scanner_id != "lambda-cost-cycle-risk-review":
            return None
        if option_name == "s3_policy_scan_max_functions" and raw_value in {
            0,
            None,
            "",
        }:
            return "unbounded"
        if option_name == "max_s3_buckets" and raw_value in {None, ""}:
            return "unbounded"
        return None
