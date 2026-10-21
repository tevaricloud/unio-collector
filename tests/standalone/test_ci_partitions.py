"""Exhaustive test sharding and negative evidence-admission regressions."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from tests.standalone import test_ci_transfer as transfer_tests
from tools.collector_repository.evidence import SourceValidationEvidence
from tools.collector_repository.identity import canonical_json, read_json, sha256
from tools.collector_repository.partition import TestPartition

transfer = transfer_tests.transfer


def test_partitions_cover_every_case_once() -> None:
    """Stable selection is independent of collection ordering and exhausts all IDs."""
    nodes = [f"tests/test_synthetic.py::test_case[{index}]" for index in range(101)]
    reports = [TestPartition.select(nodes, index, 2) for index in range(2)]
    TestPartition.complete(reports, 2)
    assert reports == [TestPartition.select(list(reversed(nodes)), index, 2) for index in range(2)]


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "collection", "selection", "count", "bool", "empty"])
def test_partition_tampering_rejects(mutation: str) -> None:
    """Incomplete or fabricated coverage cannot satisfy native prerequisites."""
    nodes = [f"test_case[{index}]" for index in range(101)]
    reports = [TestPartition.select(nodes, index, 2) for index in range(2)]
    if mutation == "missing":
        reports.pop()
    elif mutation == "duplicate":
        reports[1] = reports[0]
    elif mutation == "collection":
        reports[1] = TestPartition.select([*nodes, "test_added"], 1, 2)
    elif mutation == "selection":
        reports[0]["selected"].pop()
    elif mutation == "count":
        reports[1]["count"] = 3
    elif mutation == "bool":
        reports[0]["index"] = False
    else:
        reports[0]["collected"] = []
    with pytest.raises(ValueError, match="test|Test|shard|Shard|source"):
        TestPartition.complete(reports, 2)


@pytest.mark.parametrize("workers", [1, 2])
def test_real_pytest_shards_execute_the_complete_collection(tmp_path: Path, workers: int) -> None:
    """Real serial/xdist collection executes every synthetic case exactly once."""
    project = tmp_path / "synthetic"
    project.mkdir()
    (project / "pytest.ini").write_text("[pytest]\n")
    (project / "test_cases.py").write_text(
        "import os\nfrom pathlib import Path\nimport pytest\n"
        "@pytest.mark.parametrize('value', range(32))\n"
        "def test_case(value):\n"
        "    target = Path(os.environ['SYNTHETIC_RESULT']) / str(value)\n"
        "    assert not target.exists()\n"
        "    target.write_text('passed')\n"
    )
    results = tmp_path / "executed"
    results.mkdir()
    reports = []
    for index in range(2):
        partitions = tmp_path / f"partitions-{index}"
        environment = dict(
            os.environ,
            PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",
            PYTHONDONTWRITEBYTECODE="1",
            SYNTHETIC_RESULT=str(results),
            UNIO_TEST_SHARD_INDEX=str(index),
            UNIO_TEST_SHARD_COUNT="2",
            UNIO_TEST_SHARD_OUTPUT=str(partitions),
        )
        command = [
            sys.executable,
            "-B",
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
            "-p",
            "tools.collector_repository.pytest_partition",
            "-c",
            str(project / "pytest.ini"),
            "--basetemp",
            str(tmp_path / f"pytest-{index}"),
        ]
        if workers > 1:
            command.extend(["-p", "xdist.plugin", "-n", str(workers), "--dist", "loadscope"])
        command.append(str(project / "test_cases.py"))
        result = subprocess.run(command, cwd=Path(__file__).resolve().parents[2], env=environment, capture_output=True, text=True, timeout=90, check=False)  # noqa: S603
        assert result.returncode == 0, result.stdout + result.stderr
        reports.append(read_json(partitions / "partition.json"))
    TestPartition.complete(reports, 2)
    assert {path.name for path in results.iterdir()} == {str(index) for index in range(32)}


def test_aggregate_transfer_requires_both_byte_bound_shards(transfer: tuple[Path, Path, Path, dict[str, Any]]) -> None:
    """Packaging verifies all source shards before accepting any wheel."""
    root, bundle, output, context = transfer
    context["test_shards"] = 2
    incoming = bundle.parent / "shards"
    incoming.mkdir()
    nodes = [f"test_case[{index}]" for index in range(32)]
    for index in range(2):
        target = incoming / f"shard-{index}"
        (target / "wheel").mkdir(parents=True)
        summary = read_json(bundle / "validation-summary.json")
        summary["test_partition"] = TestPartition.select(nodes, index, 2)
        (target / "validation-summary.json").write_bytes(canonical_json(summary))
        wheel_name = f"wheel/{summary['wheel']}"
        (target / wheel_name).write_bytes((bundle / wheel_name).read_bytes())
        proof = {
            "schema_version": read_json(bundle / "source-evidence.json")["schema_version"],
            "context": context,
            "files": {name: sha256((target / name).read_bytes()) for name in ("validation-summary.json", wheel_name)},
        }
        (target / "source-evidence.json").write_bytes(canonical_json(proof))
    wheel, result = SourceValidationEvidence().accept(root, incoming, output, context)
    assert wheel.is_file()
    assert result["status"] == "verified"
    assert len(result["shards"]) == context["test_shards"]
    assert read_json(output / "source-evidence.json")["shards"] == result["shards"]
    lone_output = output.parent / "lone-rejected"
    lone_output.mkdir()
    with pytest.raises(ValueError, match="shards"):
        SourceValidationEvidence().accept(root, incoming / "shard-0", lone_output, context)
    assert not (lone_output / "source-evidence.json").exists()
    rejected = output.parent / "rejected"
    rejected.mkdir()
    (incoming / "shard-1/source-evidence.json").unlink()
    with pytest.raises(ValueError, match="Missing regular repository file: source-evidence.json"):
        SourceValidationEvidence().accept(root, incoming, rejected, context)
    assert not (rejected / "source-evidence.json").exists()


def test_shard_cli_options_reach_the_coordinator(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Additive source-shard options are explicit and preserve default validation."""
    from tools.collector_repository.__main__ import main  # noqa: PLC0415

    calls: list[dict[str, Any]] = []

    def validate(_self: object, _root: Path, _output: Path, **options: object) -> dict[str, str]:
        calls.append(options)
        return {"status": "synthetic"}

    monkeypatch.setattr("tools.collector_repository.validation.RepositoryValidator.validate", validate)
    assert main(["native-source", "--output", str(tmp_path / "output"), "--test-shard", "1", "--test-shards", "2"]) == 0
    assert calls[-1]["test_shard"] == 1
    assert calls[-1]["test_shards"] == len((0, 1))
    assert calls[-1]["emit_source_evidence"] is True
