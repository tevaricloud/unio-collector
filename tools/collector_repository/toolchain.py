"""Reviewed public CI tool identities and integrity-checked provisioning."""

from __future__ import annotations

import json
import platform
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

from tools.collector_repository.identity import sha256
from tools.collector_repository.paths import external_output, require
from tools.collector_repository.secrets import GITLEAKS_VERSION


class CiToolchain:
    """Provision exact reviewed releases without extracting archive paths."""

    def configuration(self, root: Path) -> dict[str, Any]:
        """Read the deliberately public, centrally reviewed tool contract."""
        value = json.loads((root / "requirements/ci-tools.json").read_bytes())
        require(value["schema_version"] == "unio-public-ci-v1", "Unsupported CI tool contract.")
        require(set(value["python"]) == {"bandit", "pip-audit", "zizmor"}, "Unexpected Python security tools.")
        require(all(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) for version in value["python"].values()), "Security tool versions must be exact.")
        require(value["binaries"]["gitleaks"]["version"] == GITLEAKS_VERSION, "Gitleaks version contract differs.")
        return value

    def bootstrap(self, root: Path) -> dict[str, Any]:
        """Install the minimal validator import dependency from reviewed pins."""
        constraints = root / "requirements/dev-constraints.txt"
        pins = [line.strip() for line in constraints.read_text(encoding="utf-8").splitlines() if re.fullmatch(r"PyYAML==[0-9]+\.[0-9]+\.[0-9]+", line.strip())]
        require(len(pins) == 1, "PyYAML must have one exact reviewed bootstrap pin.")
        command = [
            sys.executable,
            "-I",
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-input",
            "--no-deps",
            "--constraint",
            str(constraints),
            pins[0],
        ]
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=120, check=False)  # noqa: S603
        except (OSError, subprocess.SubprocessError, UnicodeError):
            message = "Validation bootstrap dependency installation failed."
            raise ValueError(message) from None
        require(result.returncode == 0, "Validation bootstrap dependency installation failed.")
        return {"status": "bootstrapped", "dependencies": pins}

    def provision(self, root: Path, output: Path, tools: list[str]) -> None:
        """Download, authenticate, extract and version-check required binaries."""
        config = self.configuration(root)
        output = external_output(root, output, empty=True)
        output.mkdir(parents=True, exist_ok=True)
        system = {"Windows": "windows", "Linux": "linux", "Darwin": "macos"}.get(platform.system())
        machine = {"AMD64": "x86_64", "x86_64": "x86_64", "arm64": "arm64", "aarch64": "arm64"}.get(platform.machine())
        target = f"{system}-{machine}"
        for name in tools:
            require(name in {"gitleaks", "actionlint"}, "Unsupported CI binary.")
            tool = config["binaries"][name]
            require(tool["repository"] == {"gitleaks": "gitleaks/gitleaks", "actionlint": "rhysd/actionlint"}[name], "Unexpected binary origin.")
            require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", tool["version"]) is not None, "Binary version must be exact.")
            require(target in tool["platforms"], "Unsupported CI binary platform.")
            asset = tool["platforms"][target]
            require(re.fullmatch(r"[a-zA-Z0-9_.-]+", asset["asset"]) is not None, "Unsafe release asset name.")
            require(re.fullmatch(r"[0-9a-f]{64}", asset["sha256"]) is not None, "Missing reviewed binary digest.")
            url = f"https://github.com/{tool['repository']}/releases/download/v{tool['version']}/{asset['asset']}"
            with tempfile.TemporaryDirectory(prefix="Unio-ci-download-", dir=output.parent) as raw:
                archive = Path(raw) / asset["asset"]
                try:
                    with urllib.request.urlopen(url, timeout=60) as response:
                        content = response.read(32 * 1024 * 1024 + 1)
                except OSError:
                    message = "Required CI binary download failed."
                    raise ValueError(message) from None
                require(len(content) <= 32 * 1024 * 1024 and sha256(content) == asset["sha256"], "CI binary release integrity failed.")
                archive.write_bytes(content)
                executable = name + (".exe" if system == "windows" else "")
                if archive.suffix == ".zip":
                    with zipfile.ZipFile(archive) as bundle:
                        member = bundle.getinfo(executable)
                        require(not member.is_dir() and not stat.S_ISLNK(member.external_attr >> 16), "Invalid binary archive member.")
                        payload = bundle.read(member)
                else:
                    with tarfile.open(archive) as bundle:
                        member = bundle.getmember(executable)
                        require(member.isfile() and member.size <= 32 * 1024 * 1024, "Invalid binary archive member.")
                        stream = bundle.extractfile(member)
                        if stream is None:
                            message = "Missing binary archive member."
                            raise ValueError(message)
                        with stream:
                            payload = stream.read()
                destination = output / executable
                destination.write_bytes(payload)
                destination.chmod(0o755)
                self.verify_binary(destination, name, tool["version"])

    def verify_binary(self, executable: Path, name: str, version: str) -> None:
        """Reject missing, broken and wrong-version executables without echoing output."""
        try:
            result = subprocess.run([str(executable), "version" if name == "gitleaks" else "-version"], capture_output=True, text=True, timeout=30, check=False)  # noqa: S603
        except (OSError, subprocess.SubprocessError, UnicodeError):
            message = "Required CI binary version could not be established."
            raise ValueError(message) from None
        require(result.returncode == 0 and result.stdout.splitlines()[:1] == [version], "Required CI binary version differs.")
