"""AWS organization configuration."""

from unio_collector.config.organization.config import AwsOrganizationConfig
from unio_collector.config.organization.loader import AwsOrganizationConfigLoader

__all__ = ["AwsOrganizationConfig", "AwsOrganizationConfigLoader"]
