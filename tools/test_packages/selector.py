"""Trusted local selection of original unsigned test packages; never execution."""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

from tools.collector_repository.identity import canonical_json, read_json
from tools.collector_repository.paths import external_output, relative_path, require
from tools.test_packages.approval import RetentionApproval
from tools.test_packages.archive import SafeArtifactArchive
from tools.test_packages.checks import MatrixAcceptance
from tools.test_packages.context import TARGETS, CandidateContext
from tools.test_packages.evidence import NativeEvidence
from tools.test_packages.executables import host_executable
from tools.test_packages.packet import NATIVE_PROOFS, PROOFS, TestPackagePacket
from tools.test_packages.transport import ArtifactTransport
from tools.test_packages.trust import TrustedCheckout
from tools.windows_installer.identity import WindowsInstallerIdentity
from tools.windows_installer.metadata import WindowsMsiInspector

if TYPE_CHECKING:
    from tools.test_packages.api import GitHubReadClient


def normalized(metadata: dict[str, Any]) -> dict[str, Any]:
    """Ignore database row ordering while retaining every field and identity."""
    return {key: sorted(value) if isinstance(value, list) else value for key, value in metadata.items()}


class TestPackageSelector:
    """Admit a complete approved matrix before producing a manual-test directory."""

    def __init__(self, trusted: Path, api: GitHubReadClient) -> None:
        """Bind the authenticated transport and explicit source context."""
        self.trusted = trusted
        self.api = api
        self.archive = SafeArtifactArchive()

    def select(self, trust_sha: str, run_id: int, attempt: int, parent: Path, checks: dict[str, int]) -> Path:
        """Require a reviewed local trust anchor before any network or file selection."""
        TrustedCheckout().verify(self.trusted, trust_sha)
        require(bool(self.api.get("user").get("id")), "Authenticated local GitHub identity required.")
        parent = external_output(self.trusted, parent)
        run = self.api.get(self.api.prefix + f"actions/runs/{run_id}/attempts/{attempt}")
        transport = ArtifactTransport(self.api, run)
        with tempfile.TemporaryDirectory(prefix="Unio-test-selection-") as raw:
            scratch = Path(raw)
            archive, hashes, request_artifact = transport.fetch(f"unsigned-test-request-{run_id}-{attempt}", scratch)
            require(set(hashes) == {"request.json"}, "Unexpected request artifact membership.")
            request = self.archive.document(archive, "request.json")
            context = request["context"]
            require(context["run_id"] == run_id and context["attempt"] == attempt, "Selected request attempt mismatch.")
            CandidateContext(self.api).verify(context)
            approval = RetentionApproval(self.api).verify(context, request["environment"])
            matrix = MatrixAcceptance(self.api, self.trusted)
            matrix.controls(context)
            jobs = matrix.native(run, context)
            complementary = matrix.complementary(context, checks)
            versions: set[str] = set()
            receipts = {}
            for target in TARGETS:
                packet_archive, inventory, artifact = transport.fetch(f"unsigned-test-{target}-{run_id}-{attempt}", scratch)
                packet = self.archive.document(packet_archive, "packet.json")
                require(packet["target"] == target and packet["job_id"] == jobs[target] and packet["request"] == request, "Packet job/candidate mismatch.")
                self._membership(packet_archive, inventory, packet)
                directory = scratch / target
                self.archive.extract(packet_archive, directory, inventory)
                TestPackagePacket().verify(directory, packet, request)
                manifest = NativeEvidence(self.trusted).verify(directory, context, target)
                self._source_bindings(directory, context)
                versions.add(manifest["version"])
                receipts[target] = {
                    "artifact_id": artifact["id"],
                    "artifact_digest": artifact["digest"],
                    "job_id": jobs[target],
                    "files": packet["files"],
                    "installer_identity": self._msi(directory, manifest) if target == "windows-x86_64" else None,
                }
            require(len(versions) == 1, "Mixed application versions.")

            CandidateContext(self.api).verify(context)
            RetentionApproval(self.api).verify(context, request["environment"])
            name = f"UNSIGNED-TEST-{next(iter(versions))}-{context['private_source'][:12]}-run{run_id}-attempt{attempt}"
            destination = parent / name
            require(not destination.exists() and not destination.is_symlink(), "Manual-test selection already exists.")
            destination.mkdir(parents=True)
            for target in TARGETS:
                import shutil  # noqa: PLC0415

                shutil.copytree(scratch / target, destination / target)
                TestPackagePacket().verify(destination / target, read_json(destination / target / "packet.json"), request)
            receipt = {
                "schema_version": 1,
                "purpose": "unsigned-manual-test-only",
                "status": "verified-for-manual-testing",
                "trusted_local_source": trust_sha,
                "context": context,
                "approval": approval,
                "request_artifact_id": request_artifact["id"],
                "complementary": complementary,
                "targets": receipts,
                "not_proven": ["production signing/publication", "installed GUI/manual lifecycle"],
            }
            (destination / "VERIFICATION-RECEIPT.json").write_bytes(canonical_json(receipt))
            (destination / "READ-ME-FIRST.txt").write_text(
                "UNSIGNED TEST packages. Verified original bytes, not installed or production-approved. See VERIFICATION-RECEIPT.json.\n", encoding="utf-8"
            )
            return destination

    def _membership(self, archive: Path, hashes: dict[str, str], packet: dict[str, Any]) -> None:
        require(
            set(packet) == {"schema_version", "purpose", "request", "target", "job_id", "files"}
            and packet["schema_version"] == 1
            and packet["purpose"] == "unsigned-manual-test-only",
            "Invalid packet schema.",
        )
        manifest = self.archive.document(archive, "native/native-release-manifest.json")
        names = set(PROOFS) | {"native/" + n for n in NATIVE_PROOFS}
        for name in manifest["artifact_hashes"]:
            require(
                relative_path(name) == Path(name).name and name.endswith((".json", ".txt", ".zip", ".tar.gz", ".msi", ".deb", ".pkg")),
                "Unexpected native asset type/path.",
            )
            names.add("native/" + name)
        if packet["target"] == "windows-x86_64":
            names.add("native/native-msi-metadata.json")
        for number in range(2):
            prefix = f"source/{number}/"
            proof = self.archive.document(archive, prefix + "source-evidence.json")
            summary = self.archive.document(archive, prefix + "validation-summary.json")
            require(
                set(proof["files"]) == {"validation-summary.json", "wheel/" + summary["wheel"]}
                and Path(summary["wheel"]).name == summary["wheel"]
                and summary["wheel"].endswith(".whl"),
                "Unexpected shard membership.",
            )
            names.add(prefix + "source-evidence.json")
            names.update(prefix + n for n in proof["files"])
        require(
            set(packet["files"]) == names and set(hashes) == names | {"packet.json"} and all(hashes[n] == packet["files"][n] for n in names),
            "Missing, extra or altered packet member.",
        )

    def _source_bindings(self, root: Path, context: dict[str, Any]) -> None:
        source = read_json(root / "source-evidence.json")["context"]["export_provenance"]
        remote = json.loads(self.api.file("export-provenance.json", context["checkout"]))
        require(
            source == remote and source["source_sha"] == context["private_source"] and source["tree_digest"] == context["projection"],
            "Authenticated source/projection differs from claims.",
        )
        lock = read_json(root / "native/native-hash-lock-evidence.json")
        content = self.api.file("requirements/" + lock["lock_filename"], context["checkout"]).replace(b"\r\n", b"\n")
        require(lock["lock_sha256"] == hashlib.sha256(content).hexdigest(), "Authenticated native lock mismatch.")
        policy = self.api.file("tools/windows_installer/policy.json", context["checkout"])
        require(json.loads(policy) == read_json(self.trusted / "tools/windows_installer/policy.json"), "Installer policy is not the reviewed policy.")

    def _msi(self, root: Path, manifest: dict[str, Any]) -> dict[str, Any]:
        installers = [name for name in manifest["artifact_hashes"] if name.endswith(".msi")]
        require(len(installers) == 1, "Exactly one Windows installer required.")
        path = root / "native" / installers[0]
        before = hashlib.sha256(path.read_bytes()).hexdigest()
        inspector = WindowsMsiInspector(executable=host_executable("powershell"))
        metadata = inspector.read(path)
        inspector.validate(metadata, WindowsInstallerIdentity.for_repository(self.trusted, manifest["version"]))
        require(
            normalized(metadata)
            == normalized(read_json(root / "native/native-msi-metadata.json"))
            == normalized(read_json(root / "native/native-installer-summary.json")["msi_metadata"]),
            "Compiled MSI identity differs from retained evidence.",
        )
        require(hashlib.sha256(path.read_bytes()).hexdigest() == before, "MSI inspection changed original bytes.")
        return {
            "sha256": before,
            "properties": dict(normalized(metadata)["Property"]),
            "package_code": metadata["PackageCode"],
            "inspection": "read-only COM OpenDatabase mode0",
        }
