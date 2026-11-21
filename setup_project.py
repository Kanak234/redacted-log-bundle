"""Install the English recognizer model and a checksum-pinned Gitleaks binary."""

import hashlib
import platform
import shutil
import subprocess
import sys
import sysconfig
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path

DIGESTS = {
    "windows_x64.zip": "d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e",
    "windows_arm64.zip": "b95f5e4f5c425cedca7ee203d9afd29597e692c4924a12ed42f970537c72cc0f",
    "linux_x64.tar.gz": "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
    "linux_arm64.tar.gz": "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080",
}


def main():
    # Keep native binaries inside the selected environment. Verify downloads before extraction.
    os_name = platform.system().lower()
    arch = {"amd64": "x64", "x86_64": "x64", "aarch64": "arm64", "arm64": "arm64"}[
        platform.machine().lower()
    ]
    suffix = ".zip" if os_name == "windows" else ".tar.gz"
    asset = f"{os_name}_{arch}{suffix}"
    binary = "gitleaks.exe" if os_name == "windows" else "gitleaks"
    target = Path(sysconfig.get_path("scripts")) / binary
    if not target.exists():
        with tempfile.TemporaryDirectory() as folder:
            archive = Path(folder) / "release"
            url = (
                "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_"
                + asset
            )
            urllib.request.urlretrieve(url, archive)
            if hashlib.sha256(archive.read_bytes()).hexdigest() != DIGESTS[asset]:
                raise ValueError("Scanner checksum mismatch")
            if suffix == ".zip":
                with zipfile.ZipFile(archive) as z:
                    payload = z.read(binary)
            else:
                with tarfile.open(archive) as t:
                    payload = t.extractfile(binary).read()
            target.write_bytes(payload)
            target.chmod(0o755)
    # Presidio and spaCy use a local named model at runtime, so setup is the network step.
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "presidio-analyzer==2.2.366",
            "spacy==3.8.18",
            "pytest",
            "https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl",
        ],
        check=True,
    )


if __name__ == "__main__":
    main()
