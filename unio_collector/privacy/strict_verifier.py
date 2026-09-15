from __future__ import annotations  # noqa: D100

# ruff: noqa: C901,PLR1714,PLR2004,TC001
import json
from typing import Any

from unio_collector.privacy.patterns import TIMESTAMP_RE
from unio_collector.privacy.profiles import PrivacyProfile
from unio_collector.privacy.rules import (
    is_strict_cost_key,
    is_strict_log_key,
    is_strict_region_key,
    is_strict_timestamp_key,
    is_strict_topology_key,
)


class StrictTransformationVerifier:
    """Verify strict transformations against staged content, not metadata."""

    def verify(self, files: dict[str, bytes], profile: PrivacyProfile) -> None:
        """Fail when strict-sensitive values remain in supported JSON members."""
        if profile.profile_id != "strict":
            return
        failures: list[str] = []
        for name, data in sorted(files.items()):
            if name.startswith("privacy/"):
                continue
            if name.endswith(".json"):
                self._walk(json.loads(data.decode("utf-8")), profile, name, None, failures)
            elif name.endswith(".jsonl"):
                for index, line in enumerate(data.decode("utf-8").splitlines()):
                    if line.strip():
                        self._walk(json.loads(line), profile, f"{name}[{index}]", None, failures)
        if failures:
            raise ValueError("Strict privacy transformation verification failed: " + "; ".join(failures[:20]))

    def _walk(
        self,
        value: Any,  # noqa: ANN401
        profile: PrivacyProfile,
        path: str,
        key: str | None,
        failures: list[str],
    ) -> None:
        if is_strict_cost_key(profile, key) and value is not None and value != "":
            failures.append(path)
            return
        if is_strict_region_key(profile, key) and value not in ("aws-region", None, ""):
            if value != [] and value != ["aws-region"]:
                failures.append(path)
            return
        if is_strict_topology_key(profile, key) and value is not None and value != "":
            if value != [] and value != {}:
                failures.append(path)
            return
        if is_strict_log_key(profile, path.split("$", 1)[0], key) and value is not None and value != "":
            if value != [] and value != {}:
                failures.append(path)
            return
        if is_strict_timestamp_key(profile, key):
            if value in (None, ""):
                return
            if not isinstance(value, str) or len(value) != 7 or not TIMESTAMP_RE.match(f"{value}-01"):
                failures.append(path)
            return
        if isinstance(value, dict):
            for child_key, child in value.items():
                self._walk(child, profile, f"{path}.${child_key}", str(child_key), failures)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                self._walk(child, profile, f"{path}[{index}]", key, failures)
