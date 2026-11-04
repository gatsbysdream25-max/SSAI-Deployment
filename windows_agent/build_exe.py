"""Build ssai-agent.exe: one file that runs on any Windows 10/11 PC with no Python installed, plus its checksum.

Run this on Windows, with PyInstaller available:
    python -m venv buildenv && buildenv\\Scripts\\pip install pyinstaller
    buildenv\\Scripts\\python windows_agent\\build_exe.py --out C:\\ssai-dist

The output folder gets ssai-agent.exe and ssai-agent.exe.sha256 (the installer checks the checksum before it installs).
"""
import argparse
import hashlib
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ICON = os.path.join(os.path.dirname(HERE), "deploy", "assets", "ssai.ico")      # the SSAI shield, shown on the exe and its shortcuts


def build(out_folder):
    """Run PyInstaller, then write the checksum file beside the exe. Returns the exe's path."""
    os.makedirs(out_folder, exist_ok=True)
    with tempfile.TemporaryDirectory() as scratch:
        subprocess.run([sys.executable, "-m", "PyInstaller", "--onefile", "--clean", "--noconfirm",
                        "--name", "ssai-agent", "--icon", ICON, "--distpath", out_folder,
                        "--workpath", os.path.join(scratch, "work"), "--specpath", scratch,
                        os.path.join(HERE, "main.py")], check=True)
    exe = os.path.join(out_folder, "ssai-agent.exe")
    with open(exe, "rb") as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    with open(exe + ".sha256", "w", encoding="ascii", newline="\n") as handle:
        handle.write(f"{digest} *ssai-agent.exe\n")
    return exe


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", required=True, help="folder for ssai-agent.exe and its .sha256")
    print("built", build(parser.parse_args().out))
