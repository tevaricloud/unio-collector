"""Byte identity and malformed-export regression tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from tools.collector_repository.identity import RepositoryIdentity, canonical_json, read_json
from tools.collector_repository.naming import TRANSFORMATION_VERSION
from tools.collector_repository.paths import external_output, regular_file, relative_path

pytestmark = [pytest.mark.offline, pytest.mark.unit]


def _identity(root: Path) -> dict[str, object]:
    root.mkdir()
    (root / "source.py").write_bytes(b"value = 'caf\xc3\xa9'\r\n")
    source_root = Path(__file__).resolve().parents[2]
    asset = source_root / "LICENSE"
    if not asset.exists():
        asset = source_root / "tools/collector_export/assets/LICENSE"
    (root / "LICENSE").write_bytes(asset.read_bytes().replace(b"\r\n", b"\n"))
    provenance: dict[str, object] = {
        "source_repository": "tevari-cloud/unio-private-source",
        "source_sha": "a" * 40,
        "source_git_tree": "b" * 40,
        "source_state_clean": True,
        "publication_ready": True,
        "policy_schema_version": "test-policy",
        "policy_sha256": "c" * 64,
        "envelope_policy_version": "test-envelope",
        "envelope_policy_sha256": "d" * 64,
        "package_plan_version": "test-plan",
        "publication_transformation_version": TRANSFORMATION_VERSION,
        "publication_transformation_sha256": "e" * 64,
        "source_byte_identity": False,
        "licence_status": "approved",
        "licence_name": "Tevari Cloud Unio Collector Source-Available License",
        "licence_version": "1.0",
    }
    return RepositoryIdentity().write(root, {"source.py": "collector_source", "LICENSE": "repository_metadata"}, provenance)


def test_identity_preserves_bytes_and_is_deterministic(tmp_path: Path) -> None:
    """CRLF and UTF-8 source bytes remain untouched and fully hashed."""
    first, second = tmp_path / "first", tmp_path / "second"
    assert _identity(first) == _identity(second)
    assert {path.name: path.read_bytes() for path in first.iterdir()} == {path.name: path.read_bytes() for path in second.iterdir()}
    assert b"\r\n" in (first / "source.py").read_bytes()
    assert RepositoryIdentity().verify(first)["file_count"] == len(list(first.iterdir()))


def test_identity_rejects_explanatory_comment(tmp_path: Path) -> None:
    """An injected comment fails the policy gate before manifest verification."""
    root = tmp_path / "export"
    _identity(root)
    source = root / "source.py"
    source.write_bytes(b"# sensitive sentinel\n" + source.read_bytes())
    with pytest.raises(ValueError, match="Public comment remains: source.py") as error:
        RepositoryIdentity().verify(root)
    assert "sensitive sentinel" not in str(error.value)


@pytest.mark.parametrize("name", ["AGENTS.md", "nested/.cursor/rules/example.mdc", "nested/ClAuDe.md"])
def test_identity_rejects_assistant_artifact(tmp_path: Path, name: str) -> None:
    """Publication verification independently rejects injected agent paths."""
    root = tmp_path / "export"
    _identity(root)
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("sensitive sentinel", encoding="utf-8")
    with pytest.raises(ValueError, match="Prohibited public assistant artefact") as error:
        RepositoryIdentity().verify(root)
    assert name in str(error.value)
    assert "sensitive sentinel" not in str(error.value)


@pytest.mark.parametrize("damage", ["missing", "unexpected", "changed", "manifest", "provenance"])
def test_identity_rejects_damaged_export(tmp_path: Path, damage: str) -> None:
    """Neither tampering nor an incomplete export can pass verification."""
    root = tmp_path / "export"
    _identity(root)
    if damage == "missing":
        (root / "source.py").unlink()
    elif damage == "unexpected":
        (root / "extra.py").write_bytes(b"extra")
    elif damage == "changed":
        (root / "source.py").write_bytes((root / "source.py").read_bytes().replace(b"\r\n", b"\n"))
    else:
        (root / f"export-{damage}.json").write_bytes(b'{"schema_version":"invalid"}')
    with pytest.raises(ValueError, match="Missing|Unexpected|differ"):
        RepositoryIdentity().verify(root)


@pytest.mark.parametrize("name", ["../escape", "C:/escape", "one\\two", "one//two", "/absolute", "CON", "name."])
def test_portable_paths_fail_closed(name: str) -> None:
    """Unsafe Windows and POSIX path spellings cannot enter a manifest."""
    with pytest.raises(ValueError, match="path"):
        relative_path(name)


def test_output_refuses_source_and_populated_destination(tmp_path: Path) -> None:
    """Export operations cannot overwrite source or an existing directory."""
    root = tmp_path / "source"
    root.mkdir()
    with pytest.raises(ValueError, match="outside"):
        external_output(root, root / "output", empty=True)
    output = tmp_path / "output"
    output.mkdir()
    (output / "keep.txt").write_text("existing", encoding="utf-8")
    with pytest.raises(ValueError, match="empty"):
        external_output(root, output, empty=True)


def test_paths_allow_symlinked_host_ancestor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Host-managed ancestors may be links without weakening repository checks."""
    host = tmp_path / "host"
    host.mkdir()

    root = host / "source"
    root.mkdir()
    source = root / "source.py"
    source.write_text("value = 1\n", encoding="utf-8")

    original_is_symlink = Path.is_symlink
    monkeypatch.setattr(
        Path,
        "is_symlink",
        lambda self: self == host or original_is_symlink(self),
    )

    assert regular_file(root, "source.py").resolve() == source.resolve()

    output = host / "output"
    assert external_output(root, output) == output.resolve()


def test_regular_file_rejects_repository_internal_symlink(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Repository-controlled symlinks remain fail-closed."""
    root = tmp_path / "source"
    root.mkdir()
    linked = root / "linked.py"
    linked.write_text("value = 1\n", encoding="utf-8")

    original_is_symlink = Path.is_symlink
    monkeypatch.setattr(
        Path,
        "is_symlink",
        lambda self: self == linked or original_is_symlink(self),
    )

    with pytest.raises(ValueError, match="links or reparse points"):
        regular_file(root, "linked.py")


def test_external_output_rejects_symlink_below_shared_boundary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Output paths cannot traverse caller-controlled links below the shared boundary."""
    root = tmp_path / "source"
    root.mkdir()

    linked_output = tmp_path / "linked-output"
    linked_output.mkdir()

    original_is_symlink = Path.is_symlink
    monkeypatch.setattr(
        Path,
        "is_symlink",
        lambda self: self == linked_output or original_is_symlink(self),
    )

    with pytest.raises(ValueError, match="links or reparse points"):
        external_output(root, linked_output / "nested")


@pytest.mark.parametrize("damage", ["missing", "changed"])
def test_identity_rejects_damaged_licence(tmp_path: Path, damage: str) -> None:
    """The reviewed licence is mandatory and cannot be modified."""
    root = tmp_path / "export"
    _identity(root)
    if damage == "missing":
        (root / "LICENSE").unlink()
    else:
        (root / "LICENSE").write_bytes(b"Changed licence.\n")
    with pytest.raises(ValueError, match="Missing|differ"):
        RepositoryIdentity().verify(root)


@pytest.mark.parametrize(("field", "value"), [("licence_status", "pending"), ("licence_version", "1.1"), ("licence_name", "Other licence")])
def test_identity_rejects_unapproved_licence_metadata(tmp_path: Path, field: str, value: str) -> None:
    """Publication readiness requires the exact user-approved name and version."""
    root = tmp_path / "export"
    _identity(root)
    path = root / "export-provenance.json"
    provenance = read_json(path)
    provenance[field] = value
    path.write_bytes(canonical_json(provenance))
    with pytest.raises(ValueError, match="licence"):
        RepositoryIdentity().verify(root)


def test_identity_rejects_rehashed_licence(tmp_path: Path) -> None:
    """Regenerating the manifest cannot approve altered legal content."""
    root = tmp_path / "export"
    provenance = _identity(root)
    (root / "LICENSE").write_bytes(b"Changed licence.\n")
    (root / "export-manifest.json").unlink()
    (root / "export-provenance.json").unlink()
    with pytest.raises(ValueError, match="Altered approved LICENSE"):
        RepositoryIdentity().write(root, {"source.py": "collector_source", "LICENSE": "repository_metadata"}, provenance)
