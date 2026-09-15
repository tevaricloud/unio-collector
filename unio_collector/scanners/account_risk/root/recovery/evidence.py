from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class RootAccountRecoveryAdvisoryEvidence:  # noqa: D101
    account_id: str

    def convert_to_dict(self) -> dict[str, str]:  # noqa: D102
        return {"account_id": self.account_id}
