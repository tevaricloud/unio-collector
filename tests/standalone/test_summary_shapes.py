"""Complete collection-summary producer contract through public namespaces."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.collector_summary_fixture import collection_summary_shapes
from unio_collector.privacy.producer_fields import unknown_producer_paths

pytestmark = pytest.mark.offline


def test_actual_complete_collection_summaries_are_classified() -> None:
    """Prevent empty fixture maps hiding finite live producer fields."""
    provenance = json.loads((Path(__file__).parent / "fixtures/protection-producers.json").read_text())
    for summary in collection_summary_shapes(provenance).values():
        assert unknown_producer_paths(summary, "collection-summary.json") == []


@pytest.mark.parametrize("value", [None, {}, [], True, -1, "us-east-1", 1.5])
def test_summary_counters_require_nonnegative_integers(value: object) -> None:
    """Finite status keys must never admit sensitive strings or malformed counts."""
    assert unknown_producer_paths({"limitation_counts": {"unsupported_region": value}}, "collection-summary.json")


def test_complete_summary_fixture_matches_actual_producer_and_vocabulary() -> None:
    """Exercise success and all degraded variants after namespace projection."""
    from unio_collector.evidence.permission.planning.limitation_category import STABLE_LIMITATION_CATEGORIES  # noqa: PLC0415
    from unio_collector.evidence.permission.planning.summary_stats import LIMITATION_CATEGORY_BY_OUTCOME  # noqa: PLC0415
    from unio_collector.privacy.provenance_fields import SUMMARY_COUNTS  # noqa: PLC0415

    provenance = json.loads((Path(__file__).parent / "fixtures/protection-producers.json").read_text())
    actual = collection_summary_shapes(provenance)
    assert actual == provenance["collection_summary_shapes"]
    assert set(actual) == {"success", "populated", "denied", "partial", "unavailable", "unsupported", "degraded"}
    assert set(SUMMARY_COUNTS["limitation_counts"]) == set(LIMITATION_CATEGORY_BY_OUTCOME.values())
    assert set(actual["populated"]["stable_limitation_counts"]) == set(STABLE_LIMITATION_CATEGORIES)
    for summary in actual.values():
        assert unknown_producer_paths(summary, "collection-summary.json") == []


@pytest.mark.parametrize("variant", ["success", "populated", "denied", "partial", "unavailable", "unsupported", "degraded"])
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_actual_summary_variants_protect_validate_and_receipt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, variant: str, profile: str) -> None:
    """Run actual producer variants through the exported CLI without AWS."""
    import io  # noqa: PLC0415
    from zipfile import ZipFile  # noqa: PLC0415

    from tools.build_native_collector import _add_synthetic_region_scope  # noqa: PLC0415
    from unio_collector.collector_cli.app import main  # noqa: PLC0415
    from unio_collector.collector_launcher.protection import ProtectionOperation  # noqa: PLC0415

    fixtures = Path(__file__).parent / "fixtures"
    local = tmp_path / "fixtures"
    local.mkdir()
    (local / "region-scope.json").write_bytes((fixtures / "region-scope.json").read_bytes())
    provenance = json.loads((fixtures / "protection-producers.json").read_text())
    provenance["summary_variant"] = variant
    (local / "protection-producers.json").write_text(json.dumps(provenance))
    source = tmp_path / "input.zip"
    assert main(["collect", "--fixture", str(fixtures / "cost.json"), "--output", str(source), "--quiet"]) == 0
    _add_synthetic_region_scope(source, local / "region-scope.json")
    output = tmp_path / "protected.zip"
    monkeypatch.setattr("sys.stdin", io.StringIO("synthetic-test-only-input\n"))
    assert (
        main(
            [
                "privacy",
                "protect",
                "--bundle",
                str(source),
                "--output",
                str(output),
                "--vault",
                str(tmp_path / "private/vault.json"),
                "--profile",
                profile,
                "--passphrase-stdin",
                "--acknowledge-vault-loss-risk",
            ]
        )
        == 0
    )
    assert main(["validate-bundle", str(output)]) == 0
    from dataclasses import asdict  # noqa: PLC0415

    from unio_collector.privacy.inspector import ProtectedBundleInspector  # noqa: PLC0415

    assert ProtectionOperation._verified(json.dumps(asdict(ProtectedBundleInspector().inspect(output)), default=str))  # noqa: SLF001
    with ZipFile(output) as archive:
        summary = json.loads(archive.read("collection-summary.json"))
        actual = collection_summary_shapes(provenance)[variant]
        for field in ("limitation_counts", "stable_limitation_counts", "secondary_classification_counts"):
            assert summary[field] == actual[field]
        assert "123456789012" not in json.dumps(summary["limitations"])


@pytest.mark.parametrize("value", ["us-east-1", True, -1, None])
def test_independent_strict_verifier_rejects_malformed_summary_counts(value: object) -> None:
    """The strict verifier must not trust a known path with a non-count value."""
    from unio_collector.privacy.profiles import load_privacy_profile  # noqa: PLC0415
    from unio_collector.privacy.strict_verifier import StrictTransformationVerifier  # noqa: PLC0415

    with pytest.raises(ValueError, match="Strict privacy transformation verification failed"):
        StrictTransformationVerifier().verify(
            {"collection-summary.json": json.dumps({"limitation_counts": {"unsupported_region": value}}).encode()}, load_privacy_profile("strict")
        )
