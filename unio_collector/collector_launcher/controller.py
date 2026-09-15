from __future__ import annotations  # noqa: D100

import json
import os
import subprocess
import sys
import tempfile
import threading
from collections.abc import Callable, Sequence
from pathlib import Path

from unio_collector.collector_launcher.result import CommandResult
from unio_collector.collector_launcher.selection import LauncherSelection

OutputCallback = Callable[[str], None]
ProgressCallback = Callable[[dict[str, object]], None]


class LauncherController:
    """Invoke the companion collector CLI without duplicating collection logic."""

    def __init__(self, command_prefix: Sequence[str] | None = None) -> None:
        """Resolve the installed or development collector command."""
        self.command_prefix = tuple(command_prefix or _collector_command_prefix())
        self._process: subprocess.Popen[str] | None = None

    def profiles(self) -> tuple[str, ...]:
        """Return local AWS profile names from the authoritative CLI service."""
        payload = self._json_command(("profiles", "--json"))
        profiles = payload.get("profiles", [])
        return tuple(str(value) for value in profiles) if isinstance(profiles, list) else ()

    def scanners(self) -> tuple[dict[str, object], ...]:
        """Return canonical AWS scanner metadata from the CLI."""
        payload = self._json_command(("scanners", "--json"))
        scanners = payload.get("scanners", [])
        return tuple(item for item in scanners if isinstance(item, dict)) if isinstance(scanners, list) else ()

    def doctor_argv(self, selection: LauncherSelection, json_output: Path) -> tuple[str, ...]:
        """Build doctor arguments from guided selections."""
        args = ["doctor", "--provider", "aws", "--output", str(selection.output), "--json-output", str(json_output)]
        self._add_profile(args, selection.profile)
        self._add_scan_scope(args, selection)
        if selection.check_identity:
            args.append("--check-identity")
        return tuple(args)

    def collect_argv(self, selection: LauncherSelection, progress_path: Path) -> tuple[str, ...]:
        """Build collection arguments while preserving collector defaults."""
        args = [
            "collect",
            "--provider",
            "aws",
            "--output",
            str(selection.output),
            "--progress-jsonl",
            str(progress_path),
        ]
        self._add_profile(args, selection.profile)
        self._add_scan_scope(args, selection)
        if not selection.include_cost_data:
            args.append("--no-cost-data")
        return tuple(args)

    def policy_argv(self, selection: LauncherSelection) -> tuple[str, ...]:
        """Build the least-permission summary command for current selections."""
        args = ["policy", "aws", "--provider", "aws", "--format", "summary"]
        self._add_profile(args, selection.profile)
        self._add_scan_scope(args, selection)
        return tuple(args)

    def permission_preview_argv(self, selection: LauncherSelection) -> tuple[str, ...]:
        """Build the read-only permission preview command for current selections."""
        args = ["permission-preview", "--provider", "aws"]
        self._add_profile(args, selection.profile)
        self._add_scan_scope(args, selection)
        return tuple(args)

    def protect_argv(
        self,
        *,
        bundle: Path,
        output: Path,
        vault: Path,
        profile: str,
    ) -> tuple[str, ...]:
        """Build privacy-protection arguments with passphrase input on stdin."""
        return (
            "privacy",
            "protect",
            "--bundle",
            str(bundle),
            "--output",
            str(output),
            "--vault",
            str(vault),
            "--profile",
            profile,
            "--passphrase-stdin",
            "--acknowledge-vault-loss-risk",
        )

    def restore_argv(
        self,
        *,
        package: Path,
        vault: Path,
        output_dir: Path,
        public_key: Path | None,
    ) -> tuple[str, ...]:
        """Build protected-report restoration arguments."""
        args = [
            "privacy",
            "restore-report",
            "--package",
            str(package),
            "--vault",
            str(vault),
            "--output-dir",
            str(output_dir),
            "--passphrase-stdin",
        ]
        if public_key is not None:
            args.extend(("--tevari-public-key", str(public_key)))
        return tuple(args)

    def run(
        self,
        argv: Sequence[str],
        *,
        stdin_text: str | None = None,
    ) -> CommandResult:
        """Run one collector command and capture its sanitized user-facing output."""
        command = (*self.command_prefix, *argv)
        completed = subprocess.run(  # noqa: S603
            command,
            check=False,
            capture_output=True,
            input=stdin_text,
            text=True,
        )
        output = "\n".join(value for value in (completed.stdout.strip(), completed.stderr.strip()) if value)
        return CommandResult(tuple(argv), completed.returncode, output)

    def run_streaming(
        self,
        argv: Sequence[str],
        *,
        progress_path: Path,
        on_output: OutputCallback,
        on_progress: ProgressCallback,
    ) -> CommandResult:
        """Run collection while forwarding console and structured progress events."""
        command = (*self.command_prefix, *argv)
        self._process = subprocess.Popen(  # noqa: S603
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        stop = threading.Event()
        progress_thread = threading.Thread(
            target=_follow_progress,
            args=(progress_path, stop, on_progress),
            daemon=True,
        )
        progress_thread.start()
        lines: list[str] = []
        stream = self._process.stdout
        if stream is None:
            message = "Collector subprocess output stream is unavailable."
            raise RuntimeError(message)
        for line in stream:
            text = line.rstrip("\r\n")
            lines.append(text)
            on_output(text)
        exit_code = self._process.wait()
        stop.set()
        progress_thread.join(timeout=2)
        self._process = None
        return CommandResult(tuple(argv), exit_code, "\n".join(lines))

    def cancel(self) -> None:
        """Terminate only the active local collector child process."""
        if self._process is not None and self._process.poll() is None:
            self._process.terminate()

    def temporary_path(self, name: str) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        """Create labelled disposable launcher state outside user destinations."""
        temporary = tempfile.TemporaryDirectory(prefix="unio-collector-launcher-")
        return temporary, Path(temporary.name) / name

    def _json_command(self, argv: Sequence[str]) -> dict[str, object]:
        result = self.run(argv)
        if result.exit_code != 0:
            message = result.output or f"Collector command failed with exit code {result.exit_code}."
            raise RuntimeError(message)
        payload = json.loads(result.output)
        if not isinstance(payload, dict):
            message = "Collector command did not return a JSON object."
            raise RuntimeError(message)
        return payload

    def _add_profile(self, args: list[str], profile: str) -> None:
        if profile:
            args.extend(("--profile", profile))

    def _add_scan_scope(self, args: list[str], selection: LauncherSelection) -> None:
        if selection.preset:
            args.extend(("--preset", selection.preset))
        if selection.detail_profile:
            args.extend(("--scan-detail-profile", selection.detail_profile))
        for pillar in selection.pillars:
            args.extend(("--scan-pillar", pillar))
        for scanner_id in selection.scanner_ids:
            args.extend(("--only-scanner", scanner_id))
        if selection.allow_chargeable_scanners:
            args.append("--allow-chargeable-scanners")


def _collector_command_prefix() -> tuple[str, ...]:
    if getattr(sys, "frozen", False):
        suffix = ".exe" if os.name == "nt" else ""
        companion = Path(sys.executable).with_name(f"unio-collector{suffix}")
        return (str(companion),)
    return (sys.executable, "-B", "-m", "unio_collector.collector_cli.app")


def _follow_progress(
    path: Path,
    stop: threading.Event,
    callback: ProgressCallback,
) -> None:
    offset = 0
    while not stop.wait(0.1):
        if not path.is_file():
            continue
        with path.open("r", encoding="utf-8") as stream:
            stream.seek(offset)
            for line in stream:
                payload = json.loads(line)
                if isinstance(payload, dict):
                    callback(payload)
            offset = stream.tell()


__all__ = ["CommandResult", "LauncherController", "LauncherSelection"]
