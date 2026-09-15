from __future__ import annotations  # noqa: D100

from botocore.config import Config


def build_pricing_client_config(api_call_timeout_seconds: int | None) -> Config | None:  # noqa: D103
    if api_call_timeout_seconds is None:
        return None
    return Config(
        connect_timeout=api_call_timeout_seconds,
        read_timeout=api_call_timeout_seconds,
        retries={"mode": "standard", "total_max_attempts": 2},
        max_pool_connections=32,
        user_agent_extra="UnioCollectorScanner/0.1",
        parameter_validation=True,
    )
