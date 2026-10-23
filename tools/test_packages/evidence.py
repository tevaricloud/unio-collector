"""Complete source, wheel, native and malware acceptance for test packets."""

from __future__ import annotations

import ast
import hashlib
from typing import TYPE_CHECKING, Any

from tools.collector_repository.evidence import SCHEMA, SourceValidationEvidence
from tools.collector_repository.identity import read_json
from tools.collector_repository.partition import TestPartition
from tools.collector_repository.paths import regular_file, require
from tools.test_packages.context import TARGETS

if TYPE_CHECKING:
    from pathlib import Path

REQUIRED_SHARDS = 2

BATCHES = (
    "",
    "logs-",
    "nat-",
    "network-",
    "audit-",
    "governance-",
    "quota-",
    "freetier-",
    "delta-",
    "recommendation-",
    "billing-",
    "rds-",
    "compute-",
    "final-",
)
NATIVE_STEPS = ["dependencies", "dependency-check", "dependency-inventory", "installed-wheel", "native-build", "native-installer", "native-malware"]


def expected_smoke() -> dict[str, int]:
    """Own the full existing smoke contract, including every negative family."""
    checks: dict[str, int] = dict.fromkeys(
        ("version", "version_flag", "build_identity", "profiles", "scanners", "launcher", "collect_fixture", "validate_bundle"), 0
    )
    checks.update({"validate_unknown_" + batch.replace("-", "_") + "bundle": 0 for batch in BATCHES})
    checks.update({f"{operation}_{profile}": 0 for operation in ("protect", "validate_protected", "receipt") for profile in ("standard", "strict")})
    checks.update({f"protect_unknown_{batch}{profile}": 1 for batch in BATCHES for profile in ("standard", "strict")})
    return checks


def producer_ids(root: Path) -> list[str]:
    """Read the trusted static registry as data; never import downloaded code."""
    path = next(folder / "scanners/collection/class_paths.py" for folder in root.iterdir() if (folder / "scanners/collection/class_paths.py").is_file())
    nodes = ast.parse(path.read_text(encoding="utf-8")).body
    value = next(n.value for n in nodes if isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name) and n.target.id == "COLLECTOR_SCANNER_CLASS_PATHS")
    if value is None:
        message = "Missing trusted producer registry."
        raise ValueError(message)
    return sorted(ast.literal_eval(value))


class NativeEvidence:
    """Check semantic obligations in addition to packet hash consistency."""

    def __init__(self, trusted: Path) -> None:
        """Bind the authenticated transport and explicit source context."""
        self.ids = producer_ids(trusted)
        fixture = trusted / "tests/standalone/fixtures/protection-producers.json"
        self.fixture_hash = hashlib.sha256(fixture.read_bytes().replace(b"\r\n", b"\n")).hexdigest()
        self.wire_namespace = read_json(fixture)["collection_log"]["eventVersion"].rsplit("-", 1)[0]

    def verify(self, root: Path, context: dict[str, Any], target: str) -> dict[str, Any]:
        """Require every existing phase and exact source/wheel/target binding."""
        summary = read_json(root / "validation-summary.json")
        require(
            summary["status"] == "passed" and summary["pristine_export"] is True and summary["validation_scope"] == "native-packaging",
            "Native validation incomplete.",
        )
        require(
            summary["project_disclosure"] == "verified-publication-attestation"
            and summary["secret_scan"]["status"] == "clean"
            and summary["secret_scan"]["findings"] == [],
            "Disclosure/secret scan failed.",
        )
        steps = summary["steps"]
        require(
            [s["name"] for s in steps] == NATIVE_STEPS and all(s["status"] == "passed" and type(s["exit_code"]) is int and s["exit_code"] == 0 for s in steps),
            "Missing/failed native phase.",
        )
        require(read_json(root / "process-progress.json")["steps"] == steps, "Nonterminal progress evidence.")
        source = read_json(root / "source-evidence.json")
        require(source == summary["source_validation"] and source["status"] == "verified", "Source transfer mismatch.")
        self._source(root, source, context, target)
        wheel = read_json(root / "installed-wheel-summary.json")
        isolation = wheel["source_isolation"]
        require(
            wheel["status"] == "passed"
            and wheel["source_sha"] == context["checkout"]
            and isolation["status"] == "ok"
            and not isolation["prohibited_importable"]
            and not isolation["origin_under_source_root"],
            "Installed wheel isolation failed.",
        )
        require(
            wheel["validation"] == dict.fromkeys(("clean_install", "cli_runtime", "privacy_restoration", "source_isolation"), "passed"),
            "Wheel acceptance incomplete.",
        )
        native = read_json(root / "native/native-build-summary.json")
        manifest = read_json(root / "native/native-release-manifest.json")
        chosen = source["shards"][0]["files"]["wheel/" + summary["wheel"]]
        require(
            native["validation_status"] == "valid" and native["collector_wheel_sha256"] == manifest["collector_wheel_sha256"] == chosen,
            "Native wheel mismatch.",
        )
        require(
            native["operating_system"] + "-" + native["architecture"] == target and manifest["operating_system"] + "-" + manifest["architecture"] == target,
            "Native platform mismatch.",
        )
        require(
            manifest["source_commit"] == context["private_source"]
            and manifest["signing_status"] == "unsigned"
            and manifest["version"] == context["version"]
            and native["smoke"]["expected_version"] == context["version"],
            "Native source/signing mismatch.",
        )
        repro = native["reproducibility"]
        require(
            repro["checked"]
            and repro["normalized_match"]
            and not repro["normalized_differences"]
            and native["normalized_payload_sha256"] == manifest["normalized_payload_sha256"],
            "Reproducibility failed.",
        )
        self._smoke(native["smoke"], self.ids, self.fixture_hash)
        self._assets(root, manifest, target)
        require(read_json(root / "native/native-installer-summary.json")["status"] == "built", "Installer not built.")
        lock = read_json(root / "native/native-hash-lock-evidence.json")
        require(
            lock["target"] == target
            and lock["lock_filename"] == f"native-{target}.lock"
            and lock["collector_wheel_sha256"] == chosen
            and lock["pip_check"] == "passed"
            and lock["resolved_packages"]
            and lock["protected_mode"] is True,
            "Native dependency lock incomplete.",
        )
        return manifest

    def _source(self, root: Path, source: dict[str, Any], candidate: dict[str, Any], target: str) -> None:
        context = source["context"]
        require(
            context["checkout_sha"] == candidate["checkout"]
            and context["target"] == target
            and context["pytest_workers"] == TARGETS[target][1]
            and context["test_shards"] == REQUIRED_SHARDS,
            "Source context mismatch.",
        )
        require(
            context["python"] == {"implementation": "CPython", "version": "3.12.10", "abi": "cpython-312"} and context["dependencies"],
            "Interpreter/dependencies missing.",
        )
        workflow = context["workflow"]
        require(
            all(
                workflow[k] == str(v)
                for k, v in {
                    "GITHUB_REPOSITORY": candidate["repository"],
                    "GITHUB_RUN_ID": candidate["run_id"],
                    "GITHUB_RUN_ATTEMPT": candidate["attempt"],
                    "GITHUB_EVENT_NAME": "pull_request",
                }.items()
            )
            and workflow["ImageOS"]
            and workflow["ImageVersion"],
            "Source attempt/image mismatch.",
        )
        identity = context["export_provenance"]
        require(
            identity["source_sha"] == candidate["private_source"]
            and identity["tree_digest"] == candidate["projection"]
            and identity["publication_ready"]
            and identity["source_state_clean"],
            "Projection mismatch.",
        )
        reports = []
        for number, shard in enumerate(source["shards"]):
            directory = root / "source" / str(number)
            proof = read_json(directory / "source-evidence.json")
            summary = read_json(directory / "validation-summary.json")
            SourceValidationEvidence._summary(summary, context["pytest_workers"])  # noqa: SLF001
            require(
                proof["schema_version"] == SCHEMA
                and proof["context"] == context
                and set(proof) == {"schema_version", "context", "files"}
                and set(proof["files"]) == {"validation-summary.json", "wheel/" + summary["wheel"]}
                and proof["files"] == shard["files"]
                and shard["status"] == "verified"
                and shard["steps"] == summary["steps"]
                and shard["context"] == context
                and shard["test_partition"] == summary["test_partition"],
                "Shard proof mismatch.",
            )
            for name, expected in proof["files"].items():
                require(hashlib.sha256(regular_file(directory, name).read_bytes()).hexdigest() == expected, "Shard member changed.")
            reports.append(summary["test_partition"])
        TestPartition.complete(reports, 2)

    def _smoke(self, smoke: dict[str, Any], ids: list[str], fixture_hash: str) -> None:
        require(
            smoke["checks"] == smoke["expected_exit_codes"] == expected_smoke()
            and smoke["version_verified"]
            and smoke["positive_source_preserved"]
            and smoke["ledger_namespace"] == self.wire_namespace
            and smoke["producer_fixture_sha256"] == fixture_hash,
            "Smoke/receipt coverage incomplete.",
        )
        guards = smoke["protection_guards"]
        require(guards["producer_ids"] == ids and guards["producer_count"] == len(ids) and guards["source_preserved"], "Producer coverage incomplete.")
        expected = {"exit_code": 1, "rejected_for_expected_reason": True, "input_preserved": True, "artifacts_absent": True}
        require(
            guards["checks"] == {name: expected.copy() for name in ("malformed-standard", "malformed-strict", "plaintext-standard")},
            "Adversarial cleanup checks incomplete.",
        )

    def _assets(self, root: Path, manifest: dict[str, Any], target: str) -> None:
        assets = manifest["artifact_hashes"]
        installer = ".msi" if target.startswith("windows-") else ".deb" if target.startswith("linux-") else ".pkg"
        require(
            sum(name.endswith(installer) for name in assets) == 1
            and sum(name.endswith(".zip" if target.startswith("windows-") else ".tar.gz") for name in assets) == 1,
            "Installer/portable payload incomplete.",
        )
        malware = read_json(root / "native/native-malware-scan-summary.json")
        require(
            malware["status"] == "clean"
            and malware["evidence_status"] == "passed"
            and malware["results"]
            and malware["scanner"]
            and malware["scanner_version"],
            "Malware acceptance missing.",
        )
        require(all(r["exit_code"] == 0 and r["status"] == "clean" for r in malware["results"]), "Malware scan failed.")
        require(bool(manifest["artifact_hashes"]), "No distributables.")
        for name, expected in manifest["artifact_hashes"].items():
            require(
                hashlib.sha256(regular_file(root / "native", name).read_bytes()).hexdigest() == expected and malware["artifact_hashes"].get(name) == expected,
                "Asset/malware hash binding mismatch.",
            )
