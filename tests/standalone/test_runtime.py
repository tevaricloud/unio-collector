"""Synthetic offline collection, bundle integrity and privacy smoke coverage."""

from __future__ import annotations

import io
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from unio_collector.collector_cli.app import main

if TYPE_CHECKING:
    from _pytest.monkeypatch import MonkeyPatch

pytestmark = [pytest.mark.offline]


def test_fixture_collection_and_privacy(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    """Collect without AWS, validate the archive and protect its identity fields."""
    fixture = Path(__file__).parent / "fixtures/cost.json"
    bundle = tmp_path / "evidence.zip"
    protected = tmp_path / "protected.zip"
    vault = tmp_path / "private/vault.json"
    assert main(["version"]) == 0
    assert main(["collect", "--fixture", str(fixture), "--output", str(bundle), "--quiet"]) == 0
    assert main(["validate-bundle", str(bundle)]) == 0
    assert main(["doctor", "--fixture", str(fixture), "--output", str(tmp_path / "doctor.zip"), "--json-output", str(tmp_path / "doctor.json"), "--quiet"]) == 0
    assert main(["privacy", "preview", "--bundle", str(bundle), "--json"]) == 0
    monkeypatch.setattr("sys.stdin", io.StringIO("synthetic-test-passphrase\n"))
    assert (
        main(
            [
                "privacy",
                "protect",
                "--bundle",
                str(bundle),
                "--output",
                str(protected),
                "--vault",
                str(vault),
                "--passphrase-stdin",
                "--acknowledge-vault-loss-risk",
            ]
        )
        == 0
    )
    assert protected.is_file()
    assert vault.is_file()
    assert main(["validate-bundle", str(protected)]) == 0
    bundle.write_bytes(b"invalid archive")
    assert main(["validate-bundle", str(bundle)]) != 0
