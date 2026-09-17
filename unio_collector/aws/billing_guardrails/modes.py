from __future__ import annotations  # noqa: D100

BILLING_SUBSCRIBER_DETAIL_MODES = {"full", "summary"}
BILLING_MONITOR_DETAIL_MODES = {"full", "budgets-only"}
BILLING_SUBSCRIBER_DETAIL_SKIPPED_ERROR = "budgets:describe_subscribers_for_notification:skipped_by_subscriber_detail_mode"
BILLING_ANOMALY_MONITOR_SKIPPED_ERROR = "ce:get_anomaly_monitors:skipped_by_monitor_detail_mode"
BILLING_ANOMALY_SUBSCRIPTION_SKIPPED_ERROR = "ce:get_anomaly_subscriptions:skipped_by_monitor_detail_mode"
BILLING_ALARM_SKIPPED_ERROR = "cloudwatch:describe_alarms:skipped_by_monitor_detail_mode"


def normalize_billing_subscriber_detail_mode(value: object) -> str:  # noqa: D103
    normalized = str(value or "full").strip().lower()
    if normalized in BILLING_SUBSCRIBER_DETAIL_MODES:
        return normalized
    allowed = ", ".join(sorted(BILLING_SUBSCRIBER_DETAIL_MODES))
    msg = f"Billing subscriber_detail_mode must be one of {allowed}; got {value!r}."
    raise ValueError(
        msg,
    )


def normalize_billing_monitor_detail_mode(value: object) -> str:  # noqa: D103
    normalized = str(value or "full").strip().lower().replace("_", "-")
    if normalized in BILLING_MONITOR_DETAIL_MODES:
        return normalized
    allowed = ", ".join(sorted(BILLING_MONITOR_DETAIL_MODES))
    msg = f"Billing monitor_detail_mode must be one of {allowed}; got {value!r}."
    raise ValueError(
        msg,
    )
