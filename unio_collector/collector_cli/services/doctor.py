from __future__ import annotations  # noqa: D100

import importlib.util
import json
from pathlib import Path
from typing import Any

from botocore.exceptions import ProfileNotFound

from unio_collector.aws.session import AwsSessionConfig, create_boto3_session
from unio_collector.collector.bundle.validator import EvidenceBundleValidator
from unio_collector.collector_cli.services.config import CollectorConfigResolver
from unio_collector.collector_cli.services.doctor_check import CollectorDoctorCheck

AZURE_IDENTITY_MODULE = ("azure", "identity")
GCP_AUTH_MODULE = ("google", "auth")


class CollectorDoctorService:
    """Run collector-safe local preflight checks."""

    def __init__(self, console: Any) -> None:  # noqa: ANN401
        """Store the output console."""
        self.console = console

    def run(self, args: object) -> int:
        """Run local collector checks."""
        checks: list[CollectorDoctorCheck] = []
        resolved = CollectorConfigResolver(self.console).resolve(
            args,
            output=Path(str(getattr(args, "output", "evidence-bundle.zip"))).parent,
        )
        checks.append(
            CollectorDoctorCheck(
                name="config_loaded",
                status="ok",
                message="Collector configuration resolved successfully.",
            ),
        )
        checks.append(self._provider_check(resolved.config.provider_id))
        checks.append(
            self._output_writable(
                Path(str(getattr(args, "output", "evidence-bundle.zip"))),
            ),
        )
        checks.extend(self._dependency_checks(resolved.config.provider_id))
        checks.append(self._bundle_validator_check())
        checks.append(self._identity_check(args, resolved.config))
        self._print_checks(checks)
        exit_code = 1 if any(check.status == "failed" for check in checks) else 0
        self._write_json(args, checks, exit_code)
        return exit_code

    def _provider_check(self, provider_id: str) -> CollectorDoctorCheck:
        return CollectorDoctorCheck(
            name="provider",
            status="ok",
            message=f"Provider resolved to {provider_id}.",
        )

    def _dependency_checks(self, provider_id: str) -> list[CollectorDoctorCheck]:
        checks = [
            self._dependency_check("yaml", "PyYAML is available."),
            self._dependency_check("boto3", "boto3 is available."),
            self._dependency_check("botocore", "botocore is available."),
        ]
        if provider_id == "azure":
            checks.append(
                self._dependency_check(
                    _module_name(AZURE_IDENTITY_MODULE),
                    "Azure identity dependency is available.",
                ),
            )
        if provider_id == "gcp":
            checks.append(
                self._dependency_check(
                    _module_name(GCP_AUTH_MODULE),
                    "Google auth dependency is available.",
                ),
            )
        return checks

    def _dependency_check(
        self,
        module_name: str,
        ok_message: str,
    ) -> CollectorDoctorCheck:
        if importlib.util.find_spec(module_name) is None:
            return CollectorDoctorCheck(
                name=f"dependency_{module_name.replace('.', '_')}",
                status="warning",
                message=f"Optional dependency is not installed: {module_name}.",
            )
        return CollectorDoctorCheck(
            name=f"dependency_{module_name.replace('.', '_')}",
            status="ok",
            message=ok_message,
        )

    def _bundle_validator_check(self) -> CollectorDoctorCheck:
        if EvidenceBundleValidator is None:  # pragma: no cover
            return CollectorDoctorCheck(
                name="bundle_validator",
                status="failed",
                message="Evidence bundle validator is unavailable.",
            )
        return CollectorDoctorCheck(
            name="bundle_validator",
            status="ok",
            message="Evidence bundle validator is available.",
        )

    def _output_writable(self, output_path: Path) -> CollectorDoctorCheck:
        target = output_path.parent if output_path.suffix else output_path
        if not target.exists():
            return CollectorDoctorCheck(
                name="output_writable",
                status="warning",
                message=f"Output parent does not exist yet: {target}",
            )
        probe = target / ".unio-collector-doctor-write-test"
        try:
            probe.write_text("ok", encoding="utf-8")
            probe.unlink(missing_ok=True)
        except OSError as exc:
            return CollectorDoctorCheck(
                name="output_writable",
                status="failed",
                message=f"Output path is not writable: {exc}",
            )
        return CollectorDoctorCheck(
            name="output_writable",
            status="ok",
            message=f"Output path is writable: {target}",
        )

    def _identity_check(self, args: object, config: object) -> CollectorDoctorCheck:
        if not bool(getattr(args, "check_identity", False)):
            return CollectorDoctorCheck(
                name="identity",
                status="skipped",
                message="Identity lookup skipped. Pass --check-identity to run it.",
            )
        if getattr(config, "fixture", None) is not None:
            return CollectorDoctorCheck(
                name="identity",
                status="skipped",
                message="Fixture mode does not require cloud identity lookup.",
            )
        if getattr(config, "provider_id", "aws") != "aws":
            return CollectorDoctorCheck(
                name="identity",
                status="skipped",
                message="Read-only identity check is currently implemented for AWS.",
            )
        try:
            session = create_boto3_session(
                AwsSessionConfig(
                    profile=getattr(config, "profile", None),
                    region=(getattr(config, "regions", ()) or (None,))[0],
                ),
            )
            identity = session.client("sts").get_caller_identity()
        except ProfileNotFound as exc:
            return CollectorDoctorCheck(
                name="identity",
                status="failed",
                message=f"AWS profile could not be found: {exc}",
            )
        except Exception as exc:  # noqa: BLE001
            return CollectorDoctorCheck(
                name="identity",
                status="failed",
                message=f"Read-only identity check failed: {exc}",
            )
        return CollectorDoctorCheck(
            name="identity",
            status="ok",
            message=f"Read-only identity resolved for account {identity.get('Account', 'unknown-account')}.",
        )

    def _print_checks(self, checks: list[CollectorDoctorCheck]) -> None:
        for check in checks:
            self.console.print(f"{check.name}: {check.status} - {check.message}")

    def _write_json(
        self,
        args: object,
        checks: list[CollectorDoctorCheck],
        exit_code: int,
    ) -> None:
        output = str(getattr(args, "json_output", "") or "")
        if not output:
            return
        payload = {
            "checks": [check.convert_to_dict() for check in checks],
            "command": "doctor",
            "exit_code": exit_code,
            "schema_version": 1,
            "status": _doctor_status(checks),
        }
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self.console.print(f"Wrote collector doctor JSON to {output_path}")


def _doctor_status(checks: list[CollectorDoctorCheck]) -> str:
    statuses = {check.status for check in checks}
    if "failed" in statuses:
        return "failed"
    if "warning" in statuses:
        return "warning"
    return "ok"


def _module_name(parts: tuple[str, ...]) -> str:
    return ".".join(parts)


__all__ = ["CollectorDoctorCheck", "CollectorDoctorService"]
