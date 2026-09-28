"""Factory for an environment-aware privacy transformer."""

from __future__ import annotations

from typing import TYPE_CHECKING

from unio_collector.environment import EnvironmentClassifier
from unio_collector.privacy.transform import PrivacyTransformer

if TYPE_CHECKING:
    from unio_collector.privacy.protection_state import ProtectionState


def build_environment_transformer(state: ProtectionState) -> PrivacyTransformer:
    """Build the transformer from resolved privacy protection state."""
    alias_file = str(state.environment_alias_file) if state.environment_alias_file else None
    return PrivacyTransformer(
        token_service=state.token_service,
        profile=state.profile,
        allow_unknown_fields=state.profile.preserve_unknown_fields,
        summary=state.classification,
        environment_classifier=EnvironmentClassifier(alias_file=alias_file),
        environment_semantics=state.environment_semantics,
    )
