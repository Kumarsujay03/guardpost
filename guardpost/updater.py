"""Self-update from GitHub releases.

A release carries guardpost-<version>.tar.gz and its .sha256. The update
downloads both, checks the checksum, unpacks the archive and runs its
install.sh, which installs it next to the old version under
~/.local/share/guardpost/app/ and switches the `current` link to it, so a
failed update leaves the old version working.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
from pathlib import Path

from . import __version__

REPO = os.environ.get("GUARDPOST_REPO", "Kumarsujay03/guardpost")
API = f"https://api.github.com/repos/{REPO}/releases/latest"


def _v(s: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", s)[:3])


def _get(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "guardpost", "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def latest() -> tuple[str, str, str, str]:
    """(version, archive url, checksum url, release page)"""
    rel = json.loads(_get(API, 30))
    version = rel["tag_name"].lstrip("v")
    assets = {a["name"]: a["browser_download_url"] for a in rel.get("assets", [])}
    name = f"guardpost-{version}.tar.gz"
    if name not in assets or name + ".sha256" not in assets:
        raise RuntimeError(f"release {version} has no {name} and checksum")
    return version, assets[name], assets[name + ".sha256"], rel.get("html_url", "")


def newer(version: str) -> bool:
    return _v(version) > _v(__version__)


def _extract(data: bytes, dest: Path) -> None:
    with tarfile.open(fileobj=io.BytesIO(data)) as t:
        try:
            t.extractall(dest, filter="data")
        except TypeError:  # Python without extraction filters
            for m in t.getmembers():
                if m.name.startswith("/") or ".." in Path(m.name).parts or m.issym() or m.islnk():
                    raise RuntimeError(f"unsafe path in archive: {m.name}")
            t.extractall(dest)


def install(version: str, tar_url: str, sum_url: str) -> None:
    data = _get(tar_url, 300)
    want = _get(sum_url, 30).decode().split()[0].strip().lower()
    got = hashlib.sha256(data).hexdigest()
    if got != want:
        raise RuntimeError(f"checksum mismatch (got {got[:12]}, release says {want[:12]}); not installed")
    tmp = Path(tempfile.mkdtemp(prefix="guardpost-update-"))
    try:
        _extract(data, tmp)
        src = tmp / f"guardpost-{version}"
        if not (src / "install.sh").is_file():
            raise RuntimeError("archive has no install.sh")
        r = subprocess.run(["bash", str(src / "install.sh"), "--update"], capture_output=True, text=True, timeout=600)
        if r.returncode != 0:
            raise RuntimeError("install.sh failed: " + (r.stderr or r.stdout).strip()[-300:])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
