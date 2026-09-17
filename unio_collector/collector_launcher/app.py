from __future__ import annotations  # noqa: D100

import os
import threading
from pathlib import Path
from tkinter import END, MULTIPLE, BooleanVar, StringVar, Tk, filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

from unio_collector import __version__
from unio_collector.collector.config.presets import SCAN_PRESET_IDS
from unio_collector.collector_launcher.controller import LauncherController
from unio_collector.collector_launcher.result import CommandResult
from unio_collector.collector_launcher.selection import LauncherSelection
from unio_collector.config.scan.profiles import SCAN_DETAIL_PROFILE_IDS
from unio_collector.scanners.pillars import SCAN_PILLAR_IDS


class CollectorLauncherApp:
    """Small native guided surface over the authoritative collector CLI."""

    def __init__(self, root: Tk, controller: LauncherController | None = None) -> None:
        """Build launcher state and views."""
        self.root = root
        self.controller = controller or LauncherController()
        client_documents = _client_documents()
        self.profile = StringVar(value="")
        self.bundle = StringVar(value=str(client_documents / "evidence-bundle.zip"))
        self.check_identity = BooleanVar(value=False)
        self.include_cost = BooleanVar(value=True)
        self.allow_chargeable = BooleanVar(value=False)
        self.preset = StringVar(value="")
        self.detail_profile = StringVar(value="")
        self.privacy_profile = StringVar(value="standard")
        self.protected_bundle = StringVar(value=str(client_documents / "protected-evidence-bundle.zip"))
        self.vault = StringVar(value=str(client_documents / "identity-vault.json"))
        self.passphrase = StringVar(value="")
        self.restore_package = StringVar(value="")
        self.restore_output = StringVar(value=str(client_documents / "restored-report"))
        self.public_key = StringVar(value="")
        self._scanner_records: tuple[dict[str, object], ...] = ()
        self._busy = False
        self._build()
        self._load_catalogues()

    def _build(self) -> None:
        self.root.title(f"Unio Collector {__version__}")
        self.root.geometry("920x720")
        header = ttk.Label(
            self.root,
            text="Local-only, read-only AWS evidence collection. Credentials never leave this device.",
        )
        header.pack(fill="x", padx=12, pady=8)
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=12)
        collect = ttk.Frame(notebook, padding=10)
        privacy = ttk.Frame(notebook, padding=10)
        restore = ttk.Frame(notebook, padding=10)
        notebook.add(collect, text="Collect evidence")
        notebook.add(privacy, text="Protect bundle")
        notebook.add(restore, text="Restore report")
        self._build_collect(collect)
        self._build_privacy(privacy)
        self._build_restore(restore)
        self.log = ScrolledText(self.root, height=12, state="disabled")
        self.log.pack(fill="both", padx=12, pady=8)
        ttk.Button(self.root, text="Cancel current operation", command=self._cancel).pack(pady=(0, 10))

    def _build_collect(self, frame: ttk.Frame) -> None:
        ttk.Label(frame, text="AWS profile (blank uses the default credential chain)").grid(row=0, column=0, sticky="w")
        self.profile_box = ttk.Combobox(frame, textvariable=self.profile)
        self.profile_box.grid(row=0, column=1, sticky="ew")
        ttk.Label(frame, text="Evidence bundle destination").grid(row=1, column=0, sticky="w")
        ttk.Entry(frame, textvariable=self.bundle).grid(row=1, column=1, sticky="ew")
        ttk.Button(frame, text="Browse", command=lambda: self._save_path(self.bundle, ".zip")).grid(row=1, column=2)
        ttk.Checkbutton(
            frame,
            text="Confirm read-only AWS identity during doctor",
            variable=self.check_identity,
        ).grid(row=2, column=0, columnspan=2, sticky="w")
        ttk.Checkbutton(frame, text="Include previous complete month Cost Explorer baseline", variable=self.include_cost).grid(
            row=3,
            column=0,
            columnspan=2,
            sticky="w",
        )
        ttk.Checkbutton(frame, text="Allow explicitly selected chargeable scanners", variable=self.allow_chargeable).grid(
            row=4,
            column=0,
            columnspan=2,
            sticky="w",
        )
        ttk.Label(frame, text="Preset").grid(row=5, column=0, sticky="w")
        ttk.Combobox(frame, textvariable=self.preset, values=("", *SCAN_PRESET_IDS), state="readonly").grid(
            row=5,
            column=1,
            sticky="ew",
        )
        ttk.Label(frame, text="Evidence detail").grid(row=6, column=0, sticky="w")
        ttk.Combobox(
            frame,
            textvariable=self.detail_profile,
            values=("", *SCAN_DETAIL_PROFILE_IDS),
            state="readonly",
        ).grid(row=6, column=1, sticky="ew")
        ttk.Label(frame, text="Pillars (optional)").grid(row=7, column=0, sticky="nw")
        self.pillars = __import__("tkinter").Listbox(frame, selectmode=MULTIPLE, height=4, exportselection=False)
        self.pillars.grid(row=7, column=1, columnspan=2, sticky="ew")
        for pillar in SCAN_PILLAR_IDS:
            self.pillars.insert(END, pillar)
        ttk.Label(frame, text="Scanners (no selection preserves collector defaults)").grid(row=8, column=0, columnspan=2, sticky="w", pady=(8, 0))
        self.scanners = __import__("tkinter").Listbox(frame, selectmode=MULTIPLE, height=12)
        self.scanners.grid(row=9, column=0, columnspan=3, sticky="nsew")
        buttons = ttk.Frame(frame)
        buttons.grid(row=10, column=0, columnspan=3, sticky="w", pady=8)
        ttk.Button(buttons, text="1. Run doctor", command=self._doctor).pack(side="left", padx=3)
        ttk.Button(buttons, text="2. View permissions", command=self._permissions).pack(side="left", padx=3)
        ttk.Button(buttons, text="3. Collect", command=self._collect).pack(side="left", padx=3)
        ttk.Button(buttons, text="4. Validate bundle", command=self._validate).pack(side="left", padx=3)
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(9, weight=1)

    def _build_privacy(self, frame: ttk.Frame) -> None:
        self._path_row(frame, 0, "Input evidence bundle", self.bundle, save=False)
        self._path_row(frame, 1, "Protected bundle to transfer", self.protected_bundle, save=True)
        self._path_row(frame, 2, "Private vault (keep with client)", self.vault, save=True)
        ttk.Label(frame, text="Privacy profile").grid(row=3, column=0, sticky="w")
        ttk.Combobox(frame, textvariable=self.privacy_profile, values=("standard", "strict"), state="readonly").grid(row=3, column=1, sticky="ew")
        ttk.Label(frame, text="Passphrase (not stored or placed on the command line)").grid(row=4, column=0, sticky="w")
        ttk.Entry(frame, textvariable=self.passphrase, show="*").grid(row=4, column=1, sticky="ew")
        ttk.Button(frame, text="Protect and inspect", command=self._protect).grid(row=5, column=0, pady=8)
        ttk.Label(
            frame,
            text="Transfer only the protected bundle. Never transfer the vault, passphrase, recovery material, or restored output.",
            wraplength=700,
        ).grid(row=6, column=0, columnspan=3, sticky="w")
        frame.columnconfigure(1, weight=1)

    def _build_restore(self, frame: ttk.Frame) -> None:
        self._path_row(frame, 0, "Protected report package", self.restore_package, save=False)
        self._path_row(frame, 1, "Private vault", self.vault, save=False)
        self._path_row(frame, 2, "Restore destination", self.restore_output, save=True)
        self._path_row(frame, 3, "Trusted Tevari public key", self.public_key, save=False)
        ttk.Label(frame, text="Vault passphrase").grid(row=4, column=0, sticky="w")
        ttk.Entry(frame, textvariable=self.passphrase, show="*").grid(row=4, column=1, sticky="ew")
        ttk.Button(frame, text="Restore locally", command=self._restore).grid(row=5, column=0, pady=8)
        frame.columnconfigure(1, weight=1)

    def _path_row(self, frame: ttk.Frame, row: int, label: str, variable: StringVar, *, save: bool) -> None:
        ttk.Label(frame, text=label).grid(row=row, column=0, sticky="w")
        ttk.Entry(frame, textvariable=variable).grid(row=row, column=1, sticky="ew")
        command = (lambda: self._save_path(variable, "")) if save else (lambda: self._open_path(variable))
        ttk.Button(frame, text="Browse", command=command).grid(row=row, column=2)

    def _load_catalogues(self) -> None:
        def load() -> None:
            try:
                profiles = self.controller.profiles()
                scanners = self.controller.scanners()
            except Exception as exc:  # noqa: BLE001
                self._append(f"Catalogue loading failed: {exc}")
                return
            self._scanner_records = scanners
            self.root.after(0, lambda: self.profile_box.configure(values=("", *profiles)))
            self.root.after(0, self._populate_scanners)

        threading.Thread(target=load, daemon=True).start()

    def _populate_scanners(self) -> None:
        for record in self._scanner_records:
            suffix = " [may incur charges]" if record.get("may_incur_charges") else ""
            self.scanners.insert(END, f"{record.get('display_name')} ({record.get('scanner_id')}){suffix}")

    def _selection(self) -> LauncherSelection:
        selected = tuple(str(self._scanner_records[index]["scanner_id"]) for index in self.scanners.curselection())
        pillars = tuple(str(self.pillars.get(index)) for index in self.pillars.curselection())
        if self.allow_chargeable.get():
            chargeable = [record for record in self._scanner_records if record.get("scanner_id") in selected and record.get("may_incur_charges")]
            if chargeable and not messagebox.askyesno(
                "Chargeable scanners",
                "The following scanners may create request-priced AWS API usage:\n\n"
                + "\n".join(f"{record['scanner_id']}: {record.get('chargeable_reason') or 'chargeable AWS API'}" for record in chargeable)
                + "\n\nContinue?",
            ):
                message = "Chargeable scanner acknowledgement was declined."
                raise RuntimeError(message)
        return LauncherSelection(
            output=Path(self.bundle.get()),
            profile=self.profile.get().strip(),
            scanner_ids=selected,
            preset=self.preset.get(),
            detail_profile=self.detail_profile.get(),
            pillars=pillars,
            allow_chargeable_scanners=self.allow_chargeable.get(),
            include_cost_data=self.include_cost.get(),
            check_identity=self.check_identity.get(),
        )

    def _doctor(self) -> None:
        temporary, path = self.controller.temporary_path("doctor.json")
        try:
            argv = self.controller.doctor_argv(self._selection(), path)
        except RuntimeError as exc:
            temporary.cleanup()
            self._append(str(exc))
            return
        self._run_async(argv, cleanup=temporary.cleanup)

    def _collect(self) -> None:
        temporary, path = self.controller.temporary_path("progress.jsonl")
        try:
            argv = self.controller.collect_argv(self._selection(), path)
        except RuntimeError as exc:
            temporary.cleanup()
            self._append(str(exc))
            return

        def task() -> CommandResult:
            return self.controller.run_streaming(
                argv,
                progress_path=path,
                on_output=self._append,
                on_progress=lambda payload: self._append(_progress_text(payload)),
            )

        self._run_task(task, cleanup=temporary.cleanup)

    def _permissions(self) -> None:
        try:
            selection = self._selection()
        except RuntimeError as exc:
            self._append(str(exc))
            return

        def task() -> CommandResult:
            policy = self.controller.run(self.controller.policy_argv(selection))
            if policy.exit_code != 0:
                return policy
            preview = self.controller.run(self.controller.permission_preview_argv(selection))
            output = f"{policy.output}\n{preview.output}".strip()
            return CommandResult(preview.argv, preview.exit_code, output)

        self._run_task(task)

    def _validate(self) -> None:
        self._run_async(("validate-bundle", self.bundle.get()))

    def _protect(self) -> None:
        passphrase = self.passphrase.get()
        if not passphrase:
            self._append("A non-empty client-held passphrase is required.")
            return
        argv = self.controller.protect_argv(
            bundle=Path(self.bundle.get()),
            output=Path(self.protected_bundle.get()),
            vault=Path(self.vault.get()),
            profile=self.privacy_profile.get(),
        )
        self.passphrase.set("")
        self._run_async(argv, stdin_text=passphrase + "\n", then=("privacy", "inspect", "--bundle", self.protected_bundle.get()))

    def _restore(self) -> None:
        passphrase = self.passphrase.get()
        if not passphrase:
            self._append("A non-empty client-held passphrase is required.")
            return
        key = Path(self.public_key.get()) if self.public_key.get() else None
        argv = self.controller.restore_argv(
            package=Path(self.restore_package.get()),
            vault=Path(self.vault.get()),
            output_dir=Path(self.restore_output.get()),
            public_key=key,
        )
        self.passphrase.set("")
        self._run_async(argv, stdin_text=passphrase + "\n")

    def _run_async(
        self,
        argv: tuple[str, ...],
        *,
        stdin_text: str | None = None,
        then: tuple[str, ...] | None = None,
        cleanup: object | None = None,
    ) -> None:
        def task() -> CommandResult:
            result = self.controller.run(argv, stdin_text=stdin_text)
            if result.exit_code == 0 and then:
                return self.controller.run(then)
            return result

        self._run_task(task, cleanup=cleanup)

    def _run_task(self, task: object, *, cleanup: object | None = None) -> None:
        if self._busy:
            self._append("Another collector operation is already running.")
            return
        self._busy = True

        def worker() -> None:
            try:
                result = task()  # type: ignore[operator]
                if result.output:
                    self._append(result.output)
                self._append(f"Command completed with exit code {result.exit_code}.")
            except Exception as exc:  # noqa: BLE001
                self._append(f"Operation failed: {exc}")
            finally:
                if callable(cleanup):
                    cleanup()
                self._busy = False

        threading.Thread(target=worker, daemon=True).start()

    def _cancel(self) -> None:
        self.controller.cancel()
        self._append("Cancellation requested. Any incomplete output must not be treated as a valid evidence bundle.")

    def _append(self, text: str) -> None:
        self.root.after(0, lambda: self._append_now(text))

    def _append_now(self, text: str) -> None:
        self.log.configure(state="normal")
        self.log.insert(END, text + "\n")
        self.log.see(END)
        self.log.configure(state="disabled")

    def _save_path(self, variable: StringVar, extension: str) -> None:
        path = filedialog.asksaveasfilename(defaultextension=extension)
        if path:
            variable.set(path)

    def _open_path(self, variable: StringVar) -> None:
        path = filedialog.askopenfilename()
        if path:
            variable.set(path)


def _progress_text(payload: dict[str, object]) -> str:
    event_type = str(payload.get("event_type") or "progress")
    scanner = str(payload.get("scanner_display_name") or payload.get("scanner_id") or "")
    index = payload.get("scanner_index")
    total = payload.get("scanner_total")
    prefix = f"[{index}/{total}] " if index is not None and total is not None else ""
    return f"{prefix}{event_type.replace('_', ' ').title()}: {scanner}".rstrip(": ")


def _client_documents() -> Path:
    documents = Path.home() / "Documents"
    return documents if documents.is_dir() else Path.home()


def main() -> int:
    """Start the native collector launcher."""
    root = Tk()
    if os.getenv("UNIO_COLLECTOR_LAUNCHER_SMOKE_TEST") == "1":
        root.update_idletasks()
        root.destroy()
        return 0
    CollectorLauncherApp(root)
    root.mainloop()
    return 0


__all__ = ["CollectorLauncherApp", "main"]


if __name__ == "__main__":
    raise SystemExit(main())
