"""Public package and source-boundary contracts without private test helpers."""

from __future__ import annotations

import tomllib
from importlib import import_module
from pathlib import Path

import pytest

from tools.collector_repository.identity import read_json
from tools.collector_repository.validation import RepositoryValidator
from unio_collector.collector.package.manifest import build_collector_package_file_plan
from unio_collector.collector.package.provider_boundary import CollectorProviderBoundary

pytestmark = [pytest.mark.offline, pytest.mark.repository_scan]
ROOT = Path(__file__).resolve().parents[2]


def test_collector_plan_closure_and_entrypoint() -> None:
    """The executable package plan admits only its declared collector closure."""
    plan = build_collector_package_file_plan(root=ROOT)
    assert plan.validate() == []
    boundary = CollectorProviderBoundary.from_manifest(plan.manifest)
    assert boundary.wheel_member_violations(plan.source_files) == ()
    for name in plan.source_files:
        module = name.removesuffix(".py").replace("/", ".").removesuffix(".__init__")
        assert not any(module == prefix or module.startswith(prefix + ".") for prefix in plan.manifest.exclude_package_prefixes)
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["scripts"]["unio-collector"] == "unio_collector.collector_cli.app:main"
    if project["name"] == "unio-collector":
        assert set(project["scripts"]) == {"unio-collector"}
        assert set(project["dependencies"]) == set(plan.manifest.required_dependencies)
        manifest = read_json(ROOT / "export-manifest.json")
        build_support = {
            row["path"]
            for row in manifest["files"]
            if row["category"] == "repository_metadata" and row["path"].startswith("unio_collector/") and row["path"].endswith(".py")
        }
        assert not build_support.intersection(plan.source_files)
        assert {path.relative_to(ROOT).as_posix() for path in (ROOT / "unio_collector").rglob("*.py")} == set(plan.source_files) | build_support


def test_representative_import_origins() -> None:
    """Source tests must import this checkout rather than another installation."""
    for name in (
        "unio_collector.collector_cli.app",
        "unio_collector.collector.package.manifest",
        "unio_collector.collector.bundle.validator",
        "unio_collector.privacy.metadata_validation",
    ):
        module = import_module(name)
        assert module.__file__ is not None
        assert Path(module.__file__).resolve().is_relative_to(ROOT / "unio_collector")


def test_provider_boundary_rejects_undeclared_implementation() -> None:
    """Neutral provider architecture does not admit arbitrary implementations."""
    boundary = CollectorProviderBoundary(("unio_collector.providers.aws",))
    assert boundary.is_module_allowed("unio_collector.providers.aws.identity")
    assert not boundary.is_module_allowed("unio_collector.providers.undeclared.identity")


def test_validation_workspace_uses_output_parent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Validation scratch space stays inside the approved external output area."""
    root = tmp_path / "source"
    root.mkdir()
    output_parent = tmp_path / "runner-temp"
    output_parent.mkdir()
    output = output_parent / "validation"

    captured: dict[str, object] = {}

    def temporary_directory(*, prefix: str, **kwargs: object) -> None:
        captured["prefix"] = prefix
        captured["dir"] = kwargs["dir"]
        message = "workspace captured"
        raise RuntimeError(message)

    monkeypatch.setattr(
        "tools.collector_repository.validation.tempfile.TemporaryDirectory",
        temporary_directory,
    )

    with pytest.raises(RuntimeError, match="workspace captured"):
        RepositoryValidator().validate(root, output)

    assert captured == {
        "prefix": "unio-collector-standalone-validation-",
        "dir": output_parent.resolve(),
    }


def test_standalone_licence_metadata() -> None:
    """Custom source-available terms retain a direct file reference and separate notices."""
    from tools.collector_repository.identity import LICENCE_NAME, LICENCE_SHA256, RepositoryIdentity, sha256  # noqa: PLC0415

    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    if project["name"] != "unio-collector":
        return
    identity = RepositoryIdentity().verify(ROOT)
    assert identity["licence_name"] == LICENCE_NAME
    assert identity["licence_version"] == "1.0"
    assert identity["licence_status"] == "approved"
    assert project["license"] == {"file": "LICENSE"}
    assert not any(value.startswith("License ::") for value in project.get("classifiers", []))
    assert sha256((ROOT / "LICENSE").read_bytes()) == LICENCE_SHA256
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "It is not open-source software." in readme
    assert "pending" not in readme
    assert "](LICENSE)" in readme
    assert (ROOT / "THIRD_PARTY_NOTICES").is_file()
