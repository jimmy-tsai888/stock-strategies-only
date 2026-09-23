"""Install the reviewed Linux Gitleaks binary only after archive verification."""

from __future__ import annotations

import hashlib
import io
import os
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path


VERSION = "8.30.0"
ARCHIVE_SHA256 = "79a3ab579b53f71efd634f3aaf7e04a0fa0cf206b7ed434638d1547a2470a66e"
ARCHIVE_URL = f"https://github.com/gitleaks/gitleaks/releases/download/v{VERSION}/gitleaks_{VERSION}_linux_x64.tar.gz"
MAX_ARCHIVE_BYTES = 30_000_000


def install_verified_archive(data: bytes, target: Path, expected_sha256: str = ARCHIVE_SHA256) -> None:
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        raise ValueError("Gitleaks archive SHA256 mismatch")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        matches = [member for member in archive.getmembers() if member.name in {"gitleaks", "./gitleaks"}]
        if len(matches) != 1 or not matches[0].isfile() or matches[0].size > MAX_ARCHIVE_BYTES:
            raise ValueError("Gitleaks archive lacks one bounded regular executable")
        source = archive.extractfile(matches[0])
        if source is None:
            raise ValueError("Gitleaks executable cannot be read")
        executable = source.read(MAX_ARCHIVE_BYTES + 1)
        if len(executable) != matches[0].size:
            raise ValueError("Gitleaks executable size mismatch")
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=target.parent, prefix=".gitleaks-", delete=False) as temporary:
        temporary.write(executable)
        temporary_path = Path(temporary.name)
    try:
        temporary_path.chmod(0o755)
        os.replace(temporary_path, target)
    finally:
        temporary_path.unlink(missing_ok=True)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: install_gitleaks.py TARGET", file=sys.stderr)
        return 2
    try:
        with urllib.request.urlopen(ARCHIVE_URL, timeout=30) as response:
            data = response.read(MAX_ARCHIVE_BYTES + 1)
        if len(data) > MAX_ARCHIVE_BYTES:
            raise ValueError("Gitleaks archive exceeds size limit")
        install_verified_archive(data, Path(argv[1]))
    except (OSError, ValueError, tarfile.TarError) as exc:
        print(f"Gitleaks installation failed: {type(exc).__name__}", file=sys.stderr)
        return 2
    print(f"Verified Gitleaks {VERSION} archive SHA256 and installed executable")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
