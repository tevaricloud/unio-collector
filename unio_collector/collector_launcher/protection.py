"""Cancellable protection, independent validation and receipt verification."""

from __future__ import annotations

import json
import threading
from typing import TYPE_CHECKING

from unio_collector.collector_launcher.result import CommandResult
from unio_collector.collector_launcher.stage import ProtectionStage

if TYPE_CHECKING:
    from collections.abc import Callable

    from unio_collector.collector_launcher.controller import LauncherController


class ProtectionOperation:
    """Return success only after every authoritative child gate passes."""

    def __init__(self, controller: LauncherController, argv: tuple[str, ...], stdin_text: str | None, on_stage: Callable[[ProtectionStage], None]) -> None:
        """Retain secret input only for the child stdin, never progress output."""
        self.controller = controller
        self.argv = argv
        self._stdin = stdin_text
        self._on_stage = on_stage
        self._cancel = threading.Event()

    def cancel(self) -> None:
        """Cancel an active child or prevent a child starting between stages."""
        self._cancel.set()
        threading.Thread(target=self.controller.cancel, kwargs={"cancel_event": self._cancel}, daemon=True).start()

    def __call__(self) -> CommandResult:
        """Run actual stages; do not expose inspection JSON in the transcript."""
        try:
            return self._execute()
        finally:
            self._stdin = None

    def _execute(self) -> CommandResult:
        bundle = self.argv[self.argv.index("--output") + 1]
        stages = (
            (ProtectionStage.PROTECT, self.argv),
            (ProtectionStage.VALIDATE, ("validate-bundle", bundle)),
            (ProtectionStage.RECEIPT, ("privacy", "inspect", "--bundle", bundle, "--json")),
        )
        protected_output = ""
        for stage, argv in stages:
            if self._cancel.is_set():
                return self._cancelled()
            self._on_stage(stage)
            try:
                result = self.controller.run(argv, stdin_text=self._stdin if stage == ProtectionStage.PROTECT else None, cancel_event=self._cancel)
            finally:
                self._stdin = None
            if self._cancel.is_set():
                return self._cancelled()
            if result.exit_code != 0:
                output = "Completion receipt verification failed." if stage == ProtectionStage.RECEIPT else result.output
                return CommandResult(argv, result.exit_code, output)
            if stage == ProtectionStage.PROTECT:
                protected_output = result.output
        if not self._verified(result.output):
            return CommandResult(self.argv, 1, "Completion receipt verification failed.")
        return CommandResult(self.argv, 0, protected_output)

    def _cancelled(self) -> CommandResult:
        return CommandResult(
            self.argv, 130, "Protection cancelled. Validate any existing output before use; interrupted protection may leave incomplete local staging files."
        )

    @staticmethod
    def _verified(output: str) -> bool:
        try:
            payload = json.loads(output)
        except (ValueError, TypeError):
            return False
        if not isinstance(payload, dict) or payload.get("protected") is not True or payload.get("validation_passed") is not True or payload.get("errors") != []:
            return False
        summary = payload.get("summary")
        receipt = summary.get("receipt") if isinstance(summary, dict) else None
        return isinstance(receipt, dict) and receipt.get("available") is True and receipt.get("verified") is True
