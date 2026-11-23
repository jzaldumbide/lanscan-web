#!/usr/bin/env python3
"""Cross-platform PyInstaller build script for macOS (.app + .dmg) and Windows (.exe + .zip)."""

from __future__ import annotations

import os
import platform
import plistlib
import shutil
import subprocess
import sys
import zipfile

ROOT = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(ROOT, "dist")
APP_NAME = "LanScan Web"


def run(cmd: list[str]) -> None:
    print(">>", " ".join(cmd), flush=True)
    subprocess.check_call(cmd, cwd=ROOT)


def main() -> None:
    sys_name = platform.system()
    machine = platform.machine().lower()
    arch = "arm64" if machine in ("arm64", "aarch64") else "x64"
    sep = ";" if sys_name == "Windows" else ":"

    static_src = os.path.join(ROOT, "app", "static")
    data_src = os.path.join(ROOT, "app", "data")

    hidden_imports = [
        "uvicorn.logging",
        "uvicorn.loops",
        "uvicorn.loops.auto",
        "uvicorn.protocols",
        "uvicorn.protocols.http",
        "uvicorn.protocols.http.auto",
        "uvicorn.protocols.http.h11_impl",
        "uvicorn.protocols.websockets",
        "uvicorn.protocols.websockets.auto",
        "uvicorn.lifespan",
        "uvicorn.lifespan.on",
        "uvicorn.lifespan.off",
        "app.main",
        "app.db",
        "app.scanner",
        "app.enrichment",
        "app.advisor",
    ]

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--windowed",
        "--collect-all=webview",
        f"--name={APP_NAME}",
        f"--add-data={static_src}{sep}app/static",
        f"--add-data={data_src}{sep}app/data",
    ]

    if sys_name == "Windows":
        cmd.append("--onefile")
    else:
        cmd.append("--onedir")
        cmd.append("--osx-bundle-identifier=com.jzaldumbide.lanscanweb")

    for mod in hidden_imports:
        cmd.append(f"--hidden-import={mod}")

    cmd.append(os.path.join(ROOT, "desktop.py"))
    run(cmd)

    if sys_name == "Darwin":
        app_bundle = os.path.join(DIST, f"{APP_NAME}.app")
        plist_path = os.path.join(app_bundle, "Contents", "Info.plist")
        if os.path.exists(plist_path):
            with open(plist_path, "rb") as f:
                pl = plistlib.load(f)
            pl["NSLocalNetworkUsageDescription"] = (
                "LanScan Web needs local network access to discover devices, MAC addresses, and open ports on your LAN."
            )
            pl["CFBundleDisplayName"] = APP_NAME
            pl["CFBundleShortVersionString"] = os.environ.get("RELEASE_VERSION", "1.0.0").lstrip("v")
            with open(plist_path, "wb") as f:
                plistlib.dump(pl, f)

        # Re-sign ad-hoc after modifying Info.plist so macOS arm64 accepts the bundle
        try:
            run(["codesign", "--force", "--deep", "--sign", "-", app_bundle])
        except Exception as exc:
            print(f"Warning: ad-hoc codesign skipped ({exc})")

        # Create clean DMG with Applications symlink
        dmg_stage = os.path.join(DIST, "dmg_stage")
        shutil.rmtree(dmg_stage, ignore_errors=True)
        os.makedirs(dmg_stage, exist_ok=True)
        shutil.copytree(app_bundle, os.path.join(dmg_stage, f"{APP_NAME}.app"), symlinks=True)
        os.symlink("/Applications", os.path.join(dmg_stage, "Applications"))

        dmg_out = os.path.join(DIST, f"LanScan-Web-macOS-{arch}.dmg")
        if os.path.exists(dmg_out):
            os.remove(dmg_out)
        run(
            [
                "hdiutil",
                "create",
                "-volname",
                APP_NAME,
                "-srcfolder",
                dmg_stage,
                "-ov",
                "-format",
                "UDZO",
                dmg_out,
            ]
        )
        shutil.rmtree(dmg_stage, ignore_errors=True)
        print(f"Created macOS DMG: {dmg_out}")

    elif sys_name == "Windows":
        exe_src = os.path.join(DIST, f"{APP_NAME}.exe")
        exe_out = os.path.join(DIST, f"LanScan-Web-Windows-{arch}.exe")
        if os.path.exists(exe_src):
            shutil.copy2(exe_src, exe_out)
        zip_out = os.path.join(DIST, f"LanScan-Web-Windows-{arch}.zip")
        with zipfile.ZipFile(zip_out, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(exe_out, arcname=os.path.basename(exe_out))
        print(f"Created Windows release artifacts: {exe_out} and {zip_out}")


if __name__ == "__main__":
    main()
