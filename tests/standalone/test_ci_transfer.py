"""Same-attempt source transfer rejects incomplete and mismatched native inputs."""

from __future__ import annotations

import shutil
import subprocess
from typing import TYPE_CHECKING, Any

import pytest

from tests.standalone.test_identity import _identity
from tools.collector_repository.evidence import SOURCE_STEPS, SourceValidationEvidence
from tools.collector_repository.identity import canonical_json, read_json, sha256
from tools.collector_repository.secrets import CONFIG_SHA256, GITLEAKS_VERSION

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def transfer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path, Path, dict[str, Any]]:
    """Produce byte-bound evidence against a real synthetic Git/export identity."""
    root, bundle, output = (tmp_path / name for name in ("source", "bundle", "output"))
    identity = _identity(root)
    identity["sensitive_data_validation"] = {
        "project_disclosure": "clean",
        "gitleaks": "clean",
        "gitleaks_version": GITLEAKS_VERSION,
        "gitleaks_config_sha256": CONFIG_SHA256,
    }
    (root / "export-provenance.json").write_bytes(canonical_json(identity))
    git = shutil.which("git")
    assert git is not None
    for args in (
        ["init", "-q"],
        ["add", "."],
        [
            "-c",
            "user.name=Synthetic",
            "-c",
            "user.email=synthetic",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=absent-hooks",
            "commit",
            "-qm",
            "Synthetic identity",
        ],
    ):
        subprocess.run([git, "-C", str(root), *args], check=True, capture_output=True)  # noqa: S603
    monkeypatch.setenv("GITHUB_RUN_ID", "synthetic-run")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    bundle.mkdir()
    output.mkdir()
    (bundle / "wheel").mkdir()
    inventory = bundle / "dependency-inventory.log"
    inventory.write_text('[{"name":"pytest","version":"8.4.2"}]')
    evidence = SourceValidationEvidence()
    context = evidence.context(root, None, inventory, 4)
    wheel_name = "unio_collector-0.1.7-py3-none-any.whl"
    (bundle / "wheel" / wheel_name).write_bytes(b"synthetic wheel bytes, never installed")
    summary = {
        "status": "passed",
        "pristine_export": True,
        "validation_scope": "source-for-native",
        "pytest_workers": 4,
        "project_disclosure": "verified-publication-attestation",
        "secret_scan": {"status": "clean", "findings": []},
        "steps": [{"name": name, "status": "passed", "exit_code": 0} for name in SOURCE_STEPS],
        "wheel": wheel_name,
    }
    (bundle / "validation-summary.json").write_bytes(canonical_json(summary))
    (bundle / "dependency-inventory-final.log").write_bytes(inventory.read_bytes())
    evidence.write(root, bundle, None, 4)
    (bundle / "dependency-inventory-final.log").unlink()
    inventory.unlink()
    return root, bundle, output, context


def test_transfer_accepts_only_exact_completed_source(transfer: tuple[Path, Path, Path, dict[str, Any]]) -> None:
    """The packaging job uses the exact validated wheel and preserves source evidence."""
    root, bundle, output, context = transfer
    wheel, result = SourceValidationEvidence().accept(root, bundle, output, context)
    assert wheel.read_bytes() == b"synthetic wheel bytes, never installed"
    assert result["status"] == "verified"
    assert [step["name"] for step in result["steps"]] == list(SOURCE_STEPS)


@pytest.mark.parametrize("field", ["checkout_sha", "export_provenance", "target", "python", "dependencies", "pytest_workers", "workflow"])
def test_transfer_rejects_context_mismatch(transfer: tuple[Path, Path, Path, dict[str, Any]], field: str) -> None:
    """Cross-source/OS/dependency/configuration/workflow evidence cannot skip validation."""
    root, bundle, output, context = transfer
    context[field] = "different synthetic value"
    with pytest.raises(ValueError, match="mismatch"):
        SourceValidationEvidence().accept(root, bundle, output, context)
    assert not list(output.iterdir())


@pytest.mark.parametrize("name", ["source-evidence.json", "validation-summary.json", "wheel/unio_collector-0.1.7-py3-none-any.whl"])
def test_transfer_rejects_missing_files(transfer: tuple[Path, Path, Path, dict[str, Any]], name: str) -> None:
    """A partial upload is never a source-validation pass."""
    root, bundle, output, context = transfer
    (bundle / name).unlink()
    with pytest.raises((ValueError, FileNotFoundError)):
        SourceValidationEvidence().accept(root, bundle, output, context)
    assert not list(output.iterdir())


@pytest.mark.parametrize("mutation", ["wheel", "extra", "failed", "missing-stage", "workers", "secret", "wheel-path"])
def test_transfer_rejects_tampering_and_nonpassing_contracts(transfer: tuple[Path, Path, Path, dict[str, Any]], mutation: str) -> None:
    """Even a rehashed summary must satisfy all mandatory acceptance contracts."""
    root, bundle, output, context = transfer
    summary_path = bundle / "validation-summary.json"
    summary = read_json(summary_path)
    if mutation == "wheel":
        (bundle / "wheel/unio_collector-0.1.7-py3-none-any.whl").write_bytes(b"different bytes")
    elif mutation == "extra":
        (bundle / "unexpected.json").write_text("{}")
    elif mutation == "failed":
        summary["steps"][0]["status"] = "timed-out"
    elif mutation == "missing-stage":
        summary["steps"].pop()
    elif mutation == "workers":
        summary["pytest_workers"] = 2
    elif mutation == "secret":
        summary["secret_scan"]["findings"] = ["synthetic leak"]
    elif mutation == "wheel-path":
        summary["wheel"] = "../outside.whl"
    summary_path.write_bytes(canonical_json(summary))
    if mutation not in {"wheel", "extra"}:
        proof = read_json(bundle / "source-evidence.json")
        for name in ("validation-summary.json",):
            proof["files"][name] = sha256((bundle / name).read_bytes())
        (bundle / "source-evidence.json").write_bytes(canonical_json(proof))
    before = {str(p): sha256(p.read_bytes()) for p in root.rglob("*") if p.is_file() and ".git" not in p.parts}
    with pytest.raises(ValueError, match="mismatch|Incomplete|Mandatory|Invalid|Unexpected|configuration|secret|isolation|checks"):
        SourceValidationEvidence().accept(root, bundle, output, context)
    assert not list(output.iterdir())
    assert before == {str(p): sha256(p.read_bytes()) for p in root.rglob("*") if p.is_file() and ".git" not in p.parts}


def test_context_rejects_checkout_and_export_mutation(transfer: tuple[Path, Path, Path, dict[str, Any]]) -> None:
    """Actual current bytes and Git HEAD are authoritative at packaging time."""
    root, _bundle, output, _context = transfer
    inventory = output / "inventory.json"
    inventory.write_text('[{"name":"pytest","version":"8.4.2"}]')
    with pytest.raises(ValueError, match="SHA mismatch"):
        SourceValidationEvidence().context(root, "f" * 40, inventory, 4)
    (root / "source.py").write_bytes(b"changed = True\n")
    with pytest.raises(ValueError, match="Export bytes differ"):
        SourceValidationEvidence().context(root, None, inventory, 4)
