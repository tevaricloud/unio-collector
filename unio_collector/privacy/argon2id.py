from __future__ import annotations  # noqa: D100

from dataclasses import dataclass

ARGON2_MEMORY_KIB = 65536
ARGON2_TIME_COST = 3
ARGON2_PARALLELISM = 4
ARGON2_HASH_LENGTH = 32
MAX_ARGON2_MEMORY_KIB = 262144
MAX_ARGON2_TIME_COST = 10
MAX_ARGON2_PARALLELISM = 16


@dataclass(frozen=True)
class Argon2idParameters:
    """Argon2id work-factor parameters for passphrase wrapping."""

    memory_cost_kib: int = ARGON2_MEMORY_KIB
    time_cost: int = ARGON2_TIME_COST
    parallelism: int = ARGON2_PARALLELISM
    hash_length: int = ARGON2_HASH_LENGTH

    def __post_init__(self) -> None:
        """Bound unauthenticated derivation work before allocating memory."""
        values = (self.memory_cost_kib, self.time_cost, self.parallelism, self.hash_length)
        if (
            any(type(value) is not int for value in values)
            or not 1 <= self.parallelism <= MAX_ARGON2_PARALLELISM
            or not 8 * self.parallelism <= self.memory_cost_kib <= MAX_ARGON2_MEMORY_KIB
            or not 1 <= self.time_cost <= MAX_ARGON2_TIME_COST
            or self.hash_length != ARGON2_HASH_LENGTH
        ):
            message = "Vault Argon2id parameters are invalid or exceed supported work limits."
            raise ValueError(message)

    def convert_to_dict(self) -> dict[str, int]:
        """Return serializable parameter metadata."""
        return {
            "memory_cost_kib": self.memory_cost_kib,
            "time_cost": self.time_cost,
            "parallelism": self.parallelism,
            "hash_length": self.hash_length,
        }

    @classmethod
    def from_payload(cls, payload: object) -> Argon2idParameters:
        """Admit typed parameters, preserving absent legacy defaults."""
        if payload is None:
            return cls()
        if not isinstance(payload, dict):
            message = "Vault Argon2id parameters must be an object."
            raise ValueError(message)
        return cls(
            memory_cost_kib=payload.get("memory_cost_kib", ARGON2_MEMORY_KIB),
            time_cost=payload.get("time_cost", ARGON2_TIME_COST),
            parallelism=payload.get("parallelism", ARGON2_PARALLELISM),
            hash_length=payload.get("hash_length", ARGON2_HASH_LENGTH),
        )
