"""Actual analyzer names colliding with protocol and regional metadata."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from tests.standalone.test_identity_producer import _bundle_case
from tools.collector_identity_fixture import ANALYZER_ALIAS_VARIANTS

if TYPE_CHECKING:
    from pathlib import Path
pytestmark = pytest.mark.offline


@pytest.mark.parametrize("variant", ANALYZER_ALIAS_VARIANTS)
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_actual_analyzer_alias_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, variant: str, profile: str) -> None:
    """Actual collection, callbacks, serialization, receipt and independent validation."""
    _bundle_case(tmp_path, monkeypatch, "iam-access-analyzer-evidence-review", profile, variant)
