"""Collector-safe environment classification contract."""

from unio_collector.environment.classifier import EnvironmentClassifier
from unio_collector.environment.models import EnvironmentResult
from unio_collector.environment.runtime import configure_environment_alias_file
from unio_collector.environment.signal import EnvironmentSignal
from unio_collector.environment.types import CLASSIFIER_VERSION
from unio_collector.environment.vocabulary import (
    EnvironmentVocabulary,
    load_environment_vocabulary,
)

__all__ = [
    "CLASSIFIER_VERSION",
    "EnvironmentClassifier",
    "EnvironmentResult",
    "EnvironmentSignal",
    "EnvironmentVocabulary",
    "configure_environment_alias_file",
    "load_environment_vocabulary",
]
