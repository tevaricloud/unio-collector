from __future__ import annotations  # noqa: D100

WAF_ASSOCIATION_DETAIL_MODES = frozenset({"full", "summary"})
WAF_ASSOCIATION_SKIP_REASON_DETAIL_MODE = "skipped_by_association_detail_mode"
CONFIG_RULE_DETAIL_MODES = frozenset({"full", "summary"})
CONFIG_RULE_DETAIL_SKIP_REASON_DETAIL_MODE = "skipped_by_rule_detail_mode"


def normalize_config_rule_detail_mode(value: object) -> str:  # noqa: D103
    if value is None:
        return "full"
    normalized = str(value).strip().lower()
    if normalized in CONFIG_RULE_DETAIL_MODES:
        return normalized
    msg = "AWS Config rule_detail_mode must be one of 'full' or 'summary'."
    raise ValueError(msg)


def normalize_waf_association_detail_mode(value: object) -> str:  # noqa: D103
    if value is None:
        return "full"
    normalized = str(value).strip().lower()
    if normalized in WAF_ASSOCIATION_DETAIL_MODES:
        return normalized
    msg = "WAF association_detail_mode must be one of 'full' or 'summary'."
    raise ValueError(msg)
