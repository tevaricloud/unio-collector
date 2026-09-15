from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.providers.identity import ProviderIdentity


@dataclass(frozen=True)
class ProviderIdentityRegistry:
    """Small in-process registry for canonical provider identities."""

    identities: tuple[ProviderIdentity, ...] = ()

    def get_identity(self, provider_id: str) -> ProviderIdentity | None:  # noqa: D102
        for identity in self.identities:
            if identity.provider_id == provider_id:
                return identity
        return None
