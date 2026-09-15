from __future__ import annotations  # noqa: D100

from typing import Any

from unio_collector.config.scan.detail.override_provenance import ScannerCliOverride


class LambdaScannerCliOverrideResolver:
    """Apply recognized Lambda scanner CLI options consistently."""

    _SCANNER_ID = "lambda-cost-cycle-risk-review"
    _MAPPINGS = (
        (
            "lambda_max_s3_buckets",
            "max_s3_buckets",
            "--lambda-max-s3-buckets",
        ),
        (
            "lambda_s3_worker_count",
            "s3_notification_worker_count",
            "--lambda-s3-worker-count",
        ),
        (
            "lambda_policy_scan_max_functions",
            "s3_policy_scan_max_functions",
            "--lambda-policy-scan-max-functions",
        ),
    )

    def apply(
        self,
        args: object,
        options: dict[str, dict[str, Any]],
    ) -> tuple[ScannerCliOverride, ...]:
        """Apply explicit positive CLI values and return their provenance."""
        overrides: list[ScannerCliOverride] = []
        scanner_options = options.setdefault(self._SCANNER_ID, {})
        for arg_name, option_name, cli_option in self._MAPPINGS:
            raw_value = getattr(args, arg_name, None)
            if raw_value is None:
                continue
            value = int(raw_value)
            if value <= 0:
                msg = f"{cli_option} must be a positive integer."
                raise ValueError(msg)
            scanner_options[option_name] = value
            overrides.append(
                ScannerCliOverride(
                    scanner_id=self._SCANNER_ID,
                    option_name=option_name,
                    cli_option=cli_option,
                    value=value,
                ),
            )
        return tuple(overrides)


__all__ = ["LambdaScannerCliOverrideResolver"]
