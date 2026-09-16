"""Provider facts retain identities and observation order without policy labels."""

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class NetworkResourceFact:
    """One whole provider resource, including its observed relationships."""

    kind: str
    identity: str
    observation_ordinal: int
    facts: dict[str, Any]
    repeated_observation_ordinals: tuple[int, ...] = ()
