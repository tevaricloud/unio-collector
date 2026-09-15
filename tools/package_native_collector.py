"""Create the current platform installer for a frozen collector payload."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import uuid
from importlib import import_module
from pathlib import Path

CHECKSUM_FIELD_COUNT = 2


def main() -> int:
    """Package one native collector payload using platform-owned tools."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--payload", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--require-installer", action="store_true")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    result = NativeInstallerBuilder().build(
        payload=args.payload.resolve(),
        output=output,
        require_installer=args.require_installer,
    )
    (output / "native-installer-summary.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))  # noqa: T201
    return 0 if result["status"] in {"built", "unavailable"} and not (args.require_installer and result["status"] != "built") else 1


class NativeInstallerBuilder:
    """Create MSI, PKG, or DEB output without embedding signing credentials."""

    def build(self, *, payload: Path, output: Path, require_installer: bool) -> dict[str, object]:
        """Dispatch to the current native package builder."""
        if not payload.is_dir():
            message = f"Native payload does not exist: {payload}"
            raise ValueError(message)
        native_module = import_module("unio_collector.collector.package.native.manifest")
        operating_system, architecture = native_module.current_native_target()
        manifest = native_module.build_native_collector_manifest()
        target = next(
            (item for item in manifest.targets if (item.operating_system, item.architecture) == (operating_system, architecture)),
            None,
        )
        if target is None:
            message = f"Unsupported native installer target: {operating_system}/{architecture}."
            raise RuntimeError(message)
        try:
            if operating_system == "windows":
                artifact = self._windows_msi(payload, output, manifest.version)
            elif operating_system == "macos":
                artifact = self._macos_pkg(payload, output, manifest.version, architecture)
            else:
                artifact = self._linux_deb(payload, output, manifest.version, architecture)
        except FileNotFoundError as exc:
            if require_installer:
                raise
            return {
                "architecture": architecture,
                "format": target.installer_format,
                "reason": str(exc),
                "signing_status": "unsigned",
                "status": "unavailable",
            }
        _record_installer(output, artifact)
        return {
            "architecture": architecture,
            "artifact": str(artifact),
            "embedded_app_signing_status": (
                "verified" if operating_system == "macos" and bool(os.getenv("UNIO_COLLECTOR_MACOS_SIGNING_IDENTITY")) else "not_applicable"
            ),
            "format": target.installer_format,
            "signing_status": "unsigned",
            "status": "built",
        }

    def _windows_msi(self, payload: Path, output: Path, version: str) -> Path:
        wix = shutil.which("wix")
        if wix is None:
            message = "WiX v5 command 'wix' is unavailable."
            raise FileNotFoundError(message)
        with tempfile.TemporaryDirectory(prefix="unio-collector-wix-") as raw:
            workspace = Path(raw)
            staged_payload = workspace / "payload"
            shutil.copytree(payload, staged_payload)
            wxs = workspace / "Package.wxs"
            wxs.write_text(_wix_source(staged_payload, version), encoding="utf-8")
            artifact = output / f"unio-collector-{version}-windows-x86_64.msi"
            staged_artifact = workspace / "collector.msi"
            subprocess.run([wix, "build", str(wxs), "-o", str(staged_artifact)], check=True, cwd=workspace)  # noqa: S603
            shutil.copy2(staged_artifact, artifact)
        return artifact

    def _macos_pkg(self, payload: Path, output: Path, version: str, architecture: str) -> Path:
        pkgbuild = shutil.which("pkgbuild")
        productbuild = shutil.which("productbuild")
        if pkgbuild is None or productbuild is None:
            message = "macOS pkgbuild/productbuild tools are unavailable."
            raise FileNotFoundError(message)
        with tempfile.TemporaryDirectory(prefix="unio-collector-pkg-") as raw:
            stage = Path(raw)
            app_macos = stage / "root" / "Applications" / "Unio Collector.app" / "Contents" / "MacOS"
            app_macos.parent.mkdir(parents=True)
            shutil.copytree(payload, app_macos)
            info = app_macos.parent / "Info.plist"
            info.write_text(_info_plist(version), encoding="utf-8")
            identity = os.getenv("UNIO_COLLECTOR_MACOS_SIGNING_IDENTITY", "")
            if identity:
                codesign = shutil.which("codesign")
                spctl = shutil.which("spctl")
                if codesign is None or spctl is None:
                    message = "Protected macOS app signing tools are unavailable."
                    raise FileNotFoundError(message)
                app = app_macos.parents[1]
                subprocess.run(  # noqa: S603
                    (codesign, "--force", "--options", "runtime", "--timestamp", "--sign", identity, str(app)),
                    check=True,
                )
                subprocess.run((codesign, "--verify", "--strict", "--verbose=2", str(app)), check=True)  # noqa: S603
                subprocess.run((spctl, "--assess", "--type", "execute", "--verbose=2", str(app)), check=True)  # noqa: S603
            bin_dir = stage / "root" / "usr" / "local" / "bin"
            bin_dir.mkdir(parents=True)
            (bin_dir / "unio-collector").symlink_to(
                "/Applications/Unio Collector.app/Contents/MacOS/unio-collector",
            )
            component = stage / "component.pkg"
            subprocess.run(  # noqa: S603
                [pkgbuild, "--root", str(stage / "root"), "--identifier", "uk.co.tevari.unio.collector", "--version", version, str(component)],
                check=True,
            )
            artifact = output / f"unio-collector-{version}-macos-{architecture}.pkg"
            subprocess.run([productbuild, "--package", str(component), str(artifact)], check=True)  # noqa: S603
        return artifact

    def _linux_deb(self, payload: Path, output: Path, version: str, architecture: str) -> Path:
        dpkg_deb = shutil.which("dpkg-deb")
        if dpkg_deb is None:
            message = "Linux dpkg-deb is unavailable."
            raise FileNotFoundError(message)
        with tempfile.TemporaryDirectory(prefix="unio-collector-deb-") as raw:
            root = Path(raw) / "unio-collector"
            install = root / "opt" / "unio-collector"
            install.parent.mkdir(parents=True)
            shutil.copytree(payload, install)
            bin_dir = root / "usr" / "bin"
            bin_dir.mkdir(parents=True)
            (bin_dir / "unio-collector").symlink_to("/opt/unio-collector/unio-collector")
            applications = root / "usr" / "share" / "applications"
            applications.mkdir(parents=True)
            (applications / "unio-collector.desktop").write_text(_desktop_entry(), encoding="utf-8")
            debian = root / "DEBIAN"
            debian.mkdir()
            (debian / "control").write_text(_deb_control(version, architecture), encoding="utf-8")
            artifact = output / f"unio-collector-{version}-linux-{architecture}.deb"
            subprocess.run([dpkg_deb, "--build", "--root-owner-group", str(root), str(artifact)], check=True)  # noqa: S603
        return artifact


def _wix_source(payload: Path, version: str) -> str:
    source = str(payload / "**").replace("&", "&amp;")
    upgrade_code = str(uuid.uuid5(uuid.NAMESPACE_URL, "https://tevari.co.uk/unio-collector/windows"))
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs">
  <Package Name="Unio Collector" Manufacturer="Tevari Ltd" Version="{version}" UpgradeCode="{upgrade_code}" Scope="perUser">
    <MediaTemplate EmbedCab="yes" />
    <StandardDirectory Id="LocalAppDataFolder">
      <Directory Id="ProgramsFolder" Name="Programs">
        <Directory Id="INSTALLFOLDER" Name="Unio Collector">
          <Component Id="ClientIntegration" Guid="*">
            <Environment Id="CollectorPath" Name="PATH" Value="[INSTALLFOLDER]" Permanent="no" Part="last" Action="set" System="no" />
            <Shortcut Id="CollectorShortcut" Directory="ProgramMenuFolder" Name="Unio Collector"
                      Target="[INSTALLFOLDER]Unio Collector.exe" WorkingDirectory="INSTALLFOLDER" />
            <RegistryValue Root="HKCU" Key="Software&#92;Tevari&#92;Unio Collector" Name="installed"
                           Type="integer" Value="1" KeyPath="yes" />
          </Component>
        </Directory>
      </Directory>
    </StandardDirectory>
    <StandardDirectory Id="ProgramMenuFolder" />
    <ComponentGroup Id="PayloadComponents" Directory="INSTALLFOLDER">
      <Files Include="{source}" />
    </ComponentGroup>
    <Feature Id="MainFeature" Title="Unio Collector" Level="1">
      <ComponentRef Id="ClientIntegration" />
      <ComponentGroupRef Id="PayloadComponents" />
    </Feature>
  </Package>
</Wix>
"""


def _info_plist(version: str) -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>Unio Collector</string>
<key>CFBundleIdentifier</key><string>uk.co.tevari.unio.collector</string>
<key>CFBundleName</key><string>Unio Collector</string>
<key>CFBundleShortVersionString</key><string>{version}</string>
<key>CFBundlePackageType</key><string>APPL</string>
</dict></plist>
"""


def _desktop_entry() -> str:
    return """[Desktop Entry]
Type=Application
Name=Unio Collector
Comment=Local read-only AWS evidence collector
Exec="/opt/unio-collector/Unio Collector"
Terminal=false
Categories=Utility;
"""


def _deb_control(version: str, architecture: str) -> str:
    deb_arch = "amd64" if architecture == "x86_64" else architecture
    return f"""Package: unio-collector
Version: {version}
Section: utils
Priority: optional
Architecture: {deb_arch}
Maintainer: Tevari Ltd
Description: Local read-only AWS evidence collector
"""


def _record_installer(output: Path, artifact: Path) -> None:
    release_path = output / "native-release-manifest.json"
    if release_path.is_file():
        release = json.loads(release_path.read_text(encoding="utf-8"))
        artifact_hashes = release.setdefault("artifact_hashes", {})
        if not isinstance(artifact_hashes, dict):
            message = "Native release manifest artifact hashes are invalid."
            raise RuntimeError(message)
        artifact_hashes[artifact.name] = _sha256(artifact)
        release["installer_artifact"] = artifact.name
        release["installer_signing_status"] = "unsigned"
        release_path.write_text(json.dumps(release, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    checksum_path = output / "SHA256SUMS"
    names: set[str] = {artifact.name}
    if checksum_path.is_file():
        for line in checksum_path.read_text(encoding="utf-8").splitlines():
            fields = line.split(maxsplit=1)
            if len(fields) == CHECKSUM_FIELD_COUNT:
                names.add(fields[1].strip())
    if release_path.is_file():
        names.add(release_path.name)
    checksums = {name: _sha256(output / name) for name in sorted(names) if (output / name).is_file()}
    checksum_path.write_text(
        "".join(f"{digest}  {name}\n" for name, digest in checksums.items()),
        encoding="utf-8",
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
