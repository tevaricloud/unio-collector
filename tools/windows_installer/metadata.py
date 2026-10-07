"""Read and enforce compiled MSI semantics without installing the package."""

from __future__ import annotations

import json
import os
import subprocess
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

from tools.windows_installer.identity import UPGRADE_CODE, WindowsInstallerIdentity

EQUAL_VERSION_ATTRIBUTES = 2 | 256 | 512

TABLE_FIELDS = {
    "CustomAction": 4,
    "Directory": 3,
    "RemoveFile": 5,
    "Property": 2,
    "Upgrade": 7,
    "InstallExecuteSequence": 3,
    "Component": 6,
    "Shortcut": 12,
    "Environment": 4,
    "LaunchCondition": 2,
}


class WindowsMsiInspector:
    """Inspect the actual database, including WiX-generated default actions."""

    def read(self, installer: Path) -> dict[str, object]:
        """Use read-only Windows Installer COM; never invoke installation APIs."""
        counts = json.dumps(TABLE_FIELDS)
        script = """
$ErrorActionPreference='Stop'
$i=New-Object -ComObject WindowsInstaller.Installer
$d=$i.GetType().InvokeMember('OpenDatabase','InvokeMethod',$null,$i,@($env:UNIO_MSI,0))
$out=@{}
$tables=@(); $view=$d.OpenView('SELECT `Name` FROM `_Tables`');$view.Execute()
while($record=$view.Fetch()) { $tables += $record.StringData(1) };$view.Close()
$counts=ConvertFrom-Json $env:UNIO_MSI_TABLE_FIELDS
foreach($entry in $counts.PSObject.Properties) {
 $table=$entry.Name
 if ($table -notin $tables) { $out[$table]=@();continue }
 $v=$d.OpenView(('SELECT * FROM `{0}`' -f $table))
 $v.Execute(); $rows=@()
 while($r=$v.Fetch()) {
  $row=@(); for($n=1;$n -le $entry.Value;$n++){ $row += $r.StringData($n) }; $rows += ,$row
 }
 $out[$table]=$rows; $v.Close()
}
$out['PackageCode']=$d.SummaryInformation(0).Property(9)
$out['SummaryTemplate']=$d.SummaryInformation(0).Property(7)
$out | ConvertTo-Json -Depth 8 -Compress
"""
        environment = {**os.environ, "UNIO_MSI": str(installer.resolve()), "UNIO_MSI_TABLE_FIELDS": counts}
        result = subprocess.run(  # noqa: S603
            ("powershell", "-NoProfile", "-NonInteractive", "-Command", script),  # noqa: S607
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
        return json.loads(result.stdout)

    def validate(self, metadata: dict[str, object], identity: WindowsInstallerIdentity) -> None:
        """Require ordered replacement, equality rejection and transactional removal."""
        properties = dict(_rows(metadata, "Property"))
        sequence = {row[0]: int(row[2]) for row in _rows(metadata, "InstallExecuteSequence")}
        if (
            properties.get("ProductVersion") != identity.installer_version
            or str(properties.get("UpgradeCode", "")).strip("{}").upper() != UPGRADE_CODE
            or properties.get("ALLUSERS")
        ):
            message = "MSI version, upgrade family or per-user scope is inconsistent."
            raise ValueError(message)
        if not properties.get("ProductCode") or not metadata.get("PackageCode") or properties.get("ProductCode") == metadata.get("PackageCode"):
            message = "MSI product/package identity is missing."
            raise ValueError(message)
        if (
            not sequence["InstallInitialize"] < sequence["RemoveExistingProducts"] < sequence["InstallFiles"]
            or sequence["FindRelatedProducts"] >= sequence["InstallInitialize"]
        ):
            message = "MSI replacement must occur inside the rollback transaction."
            raise ValueError(message)
        self._upgrades(metadata, identity)
        if not str(metadata.get("SummaryTemplate", "")).startswith("x64;"):
            message = "MSI platform must be x64 for the Windows native target."
            raise ValueError(message)
        self._integration(metadata)

    def _upgrades(self, metadata: dict[str, object], identity: WindowsInstallerIdentity) -> None:
        """Check older/equal/newer detection and admission conditions."""
        upgrades = _rows(metadata, "Upgrade")
        equal = [row for row in upgrades if row[6] == "UNIO_EQUAL_VERSION_FOUND"]
        older = [row for row in upgrades if row[6] == "WIX_UPGRADE_DETECTED"]
        newer = [row for row in upgrades if row[6] == "WIX_DOWNGRADE_DETECTED"]
        if len(equal) != 1 or equal[0][1:3] != [identity.installer_version] * 2 or int(equal[0][4]) & EQUAL_VERSION_ATTRIBUTES != EQUAL_VERSION_ATTRIBUTES:
            message = "MSI must detect equal versions without removing them."
            raise ValueError(message)
        if len(older) != 1 or older[0][2] != identity.installer_version or int(older[0][4]) & 514:
            message = "MSI must replace strictly older products only."
            raise ValueError(message)
        if len(newer) != 1 or newer[0][1] != identity.installer_version or not int(newer[0][4]) & 2:
            message = "MSI downgrade detection is missing."
            raise ValueError(message)
        conditions = _rows(metadata, "LaunchCondition")
        if not any(row[0] == "Installed OR NOT UNIO_EQUAL_VERSION_FOUND" for row in conditions):
            message = "MSI equal-version launch rejection is missing."
            raise ValueError(message)
        if not any(row[0] == "NOT WIX_DOWNGRADE_DETECTED" for row in conditions):
            message = "MSI downgrade launch rejection is missing."
            raise ValueError(message)

    def _integration(self, metadata: dict[str, object]) -> None:
        """Check component identity and bounded per-user integration."""
        if any("*" in row[2] or "?" in row[2] for row in _rows(metadata, "RemoveFile")):
            message = "MSI must not wildcard-remove unrelated files."
            raise ValueError(message)
        components = _rows(metadata, "Component")
        guids = [row[1] for row in components]
        if not guids or len(guids) != len(set(guids)):
            message = "MSI component identities must be unique."
            raise ValueError(message)
        if not any(row[0] == "CollectorShortcut" and row[4] == "[INSTALLFOLDER]Unio Collector.exe" for row in _rows(metadata, "Shortcut")):
            message = "MSI GUI shortcut target is incorrect."
            raise ValueError(message)
        if not any(
            row[0] == "CollectorCliShortcut" and row[4] == "[SystemFolder]cmd.exe" and "unio-collector.exe" in row[5] and "version --build-info" in row[5]
            for row in _rows(metadata, "Shortcut")
        ):
            message = "MSI CLI shortcut must launch this installed executable."
            raise ValueError(message)
        if not any(row[:3] == ["CollectorPath", "=-PATH", "[~];[INSTALLFOLDER]"] for row in _rows(metadata, "Environment")):
            message = "MSI must append/remove only its own per-user PATH entry."
            raise ValueError(message)


def _rows(metadata: dict[str, object], table: str) -> list[list[str]]:
    """Require the exact inspected table shape before interpreting rows."""
    value = metadata.get(table)
    if not isinstance(value, list) or any(
        not isinstance(row, list) or len(row) != TABLE_FIELDS[table] or any(not isinstance(field, str) for field in row) for row in value
    ):
        message = f"Invalid MSI table shape: {table}"
        raise ValueError(message)
    return value
