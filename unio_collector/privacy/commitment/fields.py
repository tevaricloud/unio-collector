"""Complete declared current commitment DTO graph, including nullable provenance."""

from unio_collector.privacy.s3.fields import fields

INVENTORY = "portfolio.inventory[]"
METRIC = "portfolio.observed_metrics[]"
DIMENSION = METRIC + ".dimensions[]"
FIELDS = {
    "": ("object", "safe_metadata", False),
    **fields("evidence_schema_version portfolio.schema_version", "schema", "safe_metadata"),
    **fields("account_id portfolio.account_id", "string", "aws_account_id"),
    **fields("pricing_provider", "pricing", "safe_metadata"),
    **fields("savings_plans_utilization reservation_utilization", "empty_array"),
    **fields("savings_plans_utilization_error reservation_utilization_error", "string", "free_text", nullable=True),
    **fields("portfolio", "object", nullable=True),
    **fields("portfolio.period_start portfolio.period_end_exclusive", "timestamp", "timestamp", nullable=True),
    **fields("portfolio.inventory portfolio.observed_metrics portfolio.source_outcomes portfolio.regions portfolio.limitations", "array"),
    **fields("portfolio.regions[]", "string", "region"),
    **fields("portfolio.limitations[]", "string", "free_text"),
    **fields(INVENTORY, "object"),
    **fields(INVENTORY + ".identity " + INVENTORY + ".specification " + INVENTORY + ".term " + INVENTORY + ".payment", "object"),
    **fields(INVENTORY + ".identity.provider", "provider", "safe_metadata"),
    **fields(INVENTORY + ".identity.service", "service", "safe_metadata"),
    **fields(INVENTORY + ".identity.commitment_type", "string", "free_text"),
    **fields(INVENTORY + ".identity.source_namespace", "namespace", "safe_metadata"),
    **fields(INVENTORY + ".identity.source_id", "string", "resource_id"),
    **fields(INVENTORY + ".identity.account_id", "string", "aws_account_id"),
    **fields(INVENTORY + ".identity.arn", "string", "arn", nullable=True),
    **fields(
        " ".join(
            INVENTORY + ".specification." + key
            for key in ("scope", "instance_family", "instance_type", "commitment_class", "platform", "tenancy", "capacity_unit", "lifecycle_state")
        ),
        "string",
        "free_text",
        nullable=True,
    ),
    **fields(INVENTORY + ".specification.region", "string", "region", nullable=True),
    **fields(INVENTORY + ".specification.availability_zone", "string", "region", nullable=True),
    **fields(INVENTORY + ".specification.quantity", "money", "cost", nullable=True),
    **fields(INVENTORY + ".term.start " + INVENTORY + ".term.end", "timestamp", "timestamp", nullable=True),
    **fields(INVENTORY + ".term.term_seconds " + INVENTORY + ".term.remaining_seconds", "count", "summary_count", nullable=True),
    **fields(INVENTORY + ".term.term_label", "string", "free_text", nullable=True),
    **fields(" ".join(INVENTORY + ".payment." + key for key in ("payment_option", "recurring_unit")), "string", "free_text", nullable=True),
    **fields(INVENTORY + ".payment.currency", "string", "cost", nullable=True),
    **fields(INVENTORY + ".payment.upfront_amount " + INVENTORY + ".payment.recurring_amount", "money", "cost", nullable=True),
    **fields(INVENTORY + ".source_operation", "operation", "safe_metadata", nullable=True),
    **fields(INVENTORY + ".evidence_timestamp", "timestamp", "timestamp", nullable=True),
    **fields(INVENTORY + ".nature", "nature", "safe_metadata"),
    **fields(METRIC, "object"),
    **{
        METRIC + "." + key: (kind, "safe_metadata", False)
        for key, kind in (
            ("service", "service"),
            ("name", "metric"),
            ("unit", "unit"),
            ("source_operation", "operation"),
            ("source_field", "source_field"),
            ("nature", "nature"),
        )
    },
    **fields(METRIC + ".value", "money", "cost", nullable=True),
    **fields(METRIC + ".currency", "string", "cost", nullable=True),
    **fields(METRIC + ".source_id", "string", "resource_id", nullable=True),
    **fields(METRIC + ".evidence_timestamp " + METRIC + ".period_start " + METRIC + ".period_end_exclusive", "timestamp", "timestamp", nullable=True),
    **fields(METRIC + ".dimensions " + METRIC + ".limitations", "array"),
    **fields(METRIC + ".limitations[]", "string", "free_text"),
    **fields(DIMENSION, "pair"),
    **fields(DIMENSION + "[0] " + DIMENSION + "[1]", "string", "free_text"),
    **fields("portfolio.source_outcomes[]", "object"),
    **fields("portfolio.source_outcomes[].source", "string", "free_text"),
    **fields("portfolio.source_outcomes[].limitation", "string", "free_text", nullable=True),
    **fields("portfolio.source_outcomes[].status", "outcome", "safe_metadata"),
    **fields("portfolio.source_outcomes[].record_count", "count", "summary_count"),
}
