"""Build labelled lab-only MSI inputs for the guarded isolated rehearsal."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from tools.package_native_collector import _wix_source
from tools.windows_installer.identity import WindowsInstallerIdentity
from tools.windows_installer.metadata import WindowsMsiInspector


class WindowsRehearsalFixtures:
    """Use the real payload; alter only lab build metadata and failure authoring."""

    def build(self, payload: Path, legacy: dict[str, object], output: Path) -> dict[str, object]:
        """Require a fresh external directory and a checksum-verified old MSI."""
        root = Path(__file__).resolve().parents[2]
        if output.resolve().is_relative_to(root) or output.exists():
            message = "Rehearsal fixture output must be fresh and outside the checkout."
            raise ValueError(message)
        legacy_msi = Path(str(legacy["msi"]))
        if _hash(legacy_msi) != legacy["sha256"] or legacy.get("application_version") != "0.1.6":
            message = "Legacy input must be verified released 0.1.6 evidence."
            raise ValueError(message)
        if any(not isinstance(legacy.get(key), str) or not re.fullmatch(r"[0-9a-f]{64}", str(legacy[key])) for key in ("cli_sha256", "gui_sha256")):
            message = "Legacy executable hashes must come from retained release evidence."
            raise ValueError(message)
        wix = shutil.which("wix")
        if wix is None:
            message = "WiX 5 is required for lab fixtures."
            raise FileNotFoundError(message)
        identity = json.loads((payload / "collector-build.json").read_text(encoding="utf-8"))
        output.mkdir(parents=True)
        legacy_copy = output / "REHEARSAL-ONLY-legacy.msi"
        shutil.copy2(legacy_msi, legacy_copy)
        plan: dict[str, object] = {"legacy": {**legacy, "msi": legacy_copy.name}, "lab_only": True, "schema_version": 1}
        for name, revision in (("first", 1), ("replacement", 2), ("equal", 2), ("rollback", 3)):
            with tempfile.TemporaryDirectory(prefix="Unio-msi-fixture-") as raw:
                workspace = Path(raw)
                staged = workspace / "payload"
                shutil.copytree(payload, staged)
                allocation = WindowsInstallerIdentity(identity["application_version"], revision)
                build_identity = {**identity, "installer_revision": revision, "installer_version": allocation.installer_version, "channel": "test"}
                (staged / "collector-build.json").write_text(json.dumps(build_identity, indent=2, sort_keys=True) + "\n", encoding="utf-8")
                source = _wix_source(staged, allocation.application_version, identity=allocation)
                if name == "rollback":
                    source = source.replace(
                        "  </Package>",
                        (
                            '<CustomAction Id="UnioRehearsalFailure" Error="Synthetic rollback rehearsal only." />\n'
                            "<InstallExecuteSequence>"
                            '<Custom Action="UnioRehearsalFailure" After="InstallExecute" Condition="NOT Installed" /></InstallExecuteSequence>\n'
                            "  </Package>"
                        ),
                    )
                wxs = workspace / "Package.wxs"
                wxs.write_text(source, encoding="utf-8")
                artifact = output / f"REHEARSAL-ONLY-{name}.msi"
                subprocess.run((wix, "build", str(wxs), "-arch", "x64", "-o", str(artifact)), check=True, cwd=workspace)  # noqa: S603
                metadata = WindowsMsiInspector().read(artifact)
                WindowsMsiInspector().validate(metadata, allocation)
                plan[name] = {
                    "msi": artifact.name,
                    "sha256": _hash(artifact),
                    "application_version": allocation.application_version,
                    "source_commit": identity["source_commit"],
                    "cli_sha256": _hash(staged / "unio-collector.exe"),
                    "gui_sha256": _hash(staged / "Unio Collector.exe"),
                    "build_info": True,
                }
                (output / f"{name}-msi-metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (output / "rehearsal-plan.json").write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return plan


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    """Prepare fixtures only; never install them on this host."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--payload", required=True, type=Path)
    parser.add_argument("--legacy-evidence", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    WindowsRehearsalFixtures().build(args.payload.resolve(), json.loads(args.legacy_evidence.read_text(encoding="utf-8")), args.output.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
