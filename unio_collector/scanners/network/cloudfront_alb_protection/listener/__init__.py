"""Typed ALB listener and rule evidence records."""

from unio_collector.scanners.network.cloudfront_alb_protection.listener.record import (
    AlbOriginListenerRecord,
)
from unio_collector.scanners.network.cloudfront_alb_protection.listener.rule_record import (
    AlbOriginListenerRuleRecord,
)

__all__ = ["AlbOriginListenerRecord", "AlbOriginListenerRuleRecord"]
