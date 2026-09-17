from __future__ import annotations  # noqa: D100

REGION_LOCATION_NAMES = {
    "eu-west-1": "EU (Ireland)",
    "eu-west-2": "EU (London)",
    "eu-west-3": "EU (Paris)",
    "eu-central-1": "EU (Frankfurt)",
    "us-east-1": "US East (N. Virginia)",
    "us-east-2": "US East (Ohio)",
    "us-west-1": "US West (N. California)",
    "us-west-2": "US West (Oregon)",
}

EXPECTED_PRICING_STOP_REASONS = frozenset(
    {
        "timed_out",
        "api_call_limit_reached",
        "lookup_budget_limited",
    },
)
