"""Verify packaged malformed-value and plaintext-leak rejection on synthetic producers."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from unio_collector.collector.bundle.checksums import build_checksums
from unio_collector.scanners.collection.class_paths import COLLECTOR_SCANNER_CLASS_PATHS


class NativeProtectionGuards:
    """Run actual packaged CLI negatives without accepting unrelated failures."""

    def run(self, cli: Path, workspace: Path, environment: dict[str, str]) -> dict[str, object]:
        """Require typed rejection, leak rejection, source preservation and no outputs."""
        source = workspace / "evidence.zip"
        source_hash = self._digest(source)
        with ZipFile(source) as archive:
            rows = json.loads(archive.read("scan-result/scanner-evidence.json"))["scanner_evidence"]
        ids = sorted(row["scanner_id"] for row in rows)
        if ids != sorted(COLLECTOR_SCANNER_CLASS_PATHS):
            raise RuntimeError("Native protection input does not cover the complete registry.")  # noqa: EM101, TRY003
        checks: dict[str, object] = {}
        for kind, profiles in (("malformed", ("standard", "strict")), ("plaintext", ("standard",))):
            fixture = workspace / f"guard-{kind}.zip"
            self.prepare(source, fixture, kind)
            validation = subprocess.run(  # noqa: S603
                [str(cli), "validate-bundle", str(fixture)], cwd=workspace, env=environment, capture_output=True, text=True, check=False
            )
            if validation.returncode:
                raise RuntimeError("Native negative fixture failed prerequisite bundle validation.")  # noqa: EM101, TRY003
            for profile in profiles:
                name = f"{kind}-{profile}"
                output = workspace / f"guard-output-{name}.zip"
                vault = workspace / f"guard-private-{name}" / "vault.json"
                before = self._digest(fixture)
                command = [
                    str(cli),
                    "privacy",
                    "protect",
                    "--bundle",
                    str(fixture),
                    "--output",
                    str(output),
                    "--vault",
                    str(vault),
                    "--profile",
                    profile,
                    "--passphrase-stdin",
                    "--acknowledge-vault-loss-risk",
                ]
                completed = subprocess.run(  # noqa: S603
                    command, cwd=workspace, env=environment, capture_output=True, text=True, input="synthetic-native-guard-only\n", check=False
                )
                self.verify(completed, kind, fixture, before, output, vault)
                checks[name] = {"exit_code": completed.returncode, "rejected_for_expected_reason": True, "input_preserved": True, "artifacts_absent": True}
        if self._digest(source) != source_hash:
            raise RuntimeError("Native protection changed the positive source bundle.")  # noqa: EM101, TRY003
        return {"producer_ids": ids, "producer_count": len(ids), "source_sha256": source_hash, "source_preserved": True, "checks": checks}

    def prepare(self, source: Path, target: Path, kind: str) -> None:
        """Mutate one classified field in an actual producer; preserve valid bundle checksums."""
        with ZipFile(source) as archive:
            files = {name: archive.read(name) for name in archive.namelist()}
        member = "scan-result/scanner-evidence.json"
        value = json.loads(files[member])
        scanner = "tagging-missing-cost-tags" if kind == "malformed" else "billing-alerts-and-budgets-review"
        row = next(row for row in value["scanner_evidence"] if row["scanner_id"] == scanner)
        if kind == "malformed":
            row["payload"]["analysis_inputs_version"] = True
        elif kind == "plaintext":
            row["payload"]["budgets"][0]["budget"]["BudgetLimit"]["Unit"] = ":".join(  # noqa: FLY002
                ("arn", "aws", "ec2", "eu-west-2", "123456789012", "instance/i-synthetic-leak")
            )
        else:
            raise ValueError("Unknown native negative fixture kind.")  # noqa: EM101, TRY003
        files[member] = json.dumps(value, sort_keys=True).encode()
        checksums = build_checksums(files)
        manifest = json.loads(files["manifest.json"])
        manifest["checksums"] = checksums
        files["manifest.json"] = json.dumps(manifest, sort_keys=True).encode()
        files["checksums.json"] = json.dumps({"algorithm": "sha256", "checksums": checksums}, sort_keys=True).encode()
        with ZipFile(target, "w", compression=ZIP_DEFLATED) as archive:
            for name, content in files.items():
                archive.writestr(name, content)

    def verify(self, completed: subprocess.CompletedProcess[str], kind: str, source: Path, before: str, output: Path, vault: Path) -> None:
        """Reject unrelated errors, changed inputs or any falsely completed artifact."""
        diagnostic = "".join((completed.stdout + completed.stderr).split())
        expected = ("unclassified", "analysis_inputs_version") if kind == "malformed" else ("leakscan", "aws_arn")
        if completed.returncode != 1 or not all(marker in diagnostic for marker in expected):
            raise RuntimeError("Native protection guard failed for an unrelated reason.")  # noqa: EM101, TRY003
        if self._digest(source) != before:
            raise RuntimeError("Native protection guard changed its input.")  # noqa: EM101, TRY003
        if any(path.exists() for path in (output, vault, Path(str(output) + ".receipt.json"))):
            raise RuntimeError("Native protection guard published an artifact.")  # noqa: EM101, TRY003

    @staticmethod
    def verify_source(source: Path, expected: str) -> None:
        """Require positive protection to leave the source unchanged."""
        if NativeProtectionGuards._digest(source) != expected:
            raise RuntimeError("Native protection changed its source bundle.")  # noqa: EM101, TRY003

    @staticmethod
    def _digest(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()
