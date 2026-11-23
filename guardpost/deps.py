"""Layer 2: the packages an install pulls in, not just the repo you cloned.

Before the install (nothing from the packages runs):
  npm  - resolve the full tree in a temp folder (npm --package-lock-only
         --ignore-scripts), look every package up in OSV (malicious and
         vulnerable versions), then download and read every package that has
         an install script, plus the ones you asked for, before npm runs them.
  pip  - resolve with `pip install --dry-run --report --only-binary=:all:`
         (wheels only, so no setup.py runs), look everything up in OSV,
         download the wheels and read them, including .pth files that run
         at every Python start. Packages that only come as source get their
         setup code downloaded and read first.
After the install:
  read what actually landed (new folders in node_modules or site-packages)
  and look the installed versions up in OSV again.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from . import osv, ui
from .scanner import HIGH, LOW, MEDIUM, Finding, Scan

MAX_DOWNLOAD = 40 * 1024 * 1024
MAX_PACKAGES_READ = 40
AFTER_BUDGET = 60  # seconds the after-install check may take


@dataclass
class Report:
    tool: str
    packages: int = 0
    malicious: list = field(default_factory=list)      # (name@ver, ids, summary)
    vulns: list = field(default_factory=list)          # osv.Hit
    install_scripts: list = field(default_factory=list)  # name@ver
    findings: list = field(default_factory=list)       # (name@ver, Finding)
    notes: list = field(default_factory=list)
    skipped: str = ""

    def danger(self) -> bool:
        return bool(self.malicious or any(f.severity == HIGH for _, f in self.findings))


def _fetch(url: str, limit: int = MAX_DOWNLOAD) -> bytes | None:
    req = urllib.request.Request(url, headers={"User-Agent": "guardpost"})
    with urllib.request.urlopen(req, timeout=60) as r:
        n = int(r.headers.get("Content-Length") or 0)
        if n > limit:
            return None
        data = r.read(limit + 1)
    return None if len(data) > limit else data


def _safe_extract(data: bytes, kind: str, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    if kind == "zip":
        with zipfile.ZipFile(__import__("io").BytesIO(data)) as z:
            for info in z.infolist():
                name = info.filename
                if name.startswith("/") or ".." in Path(name).parts or info.is_dir():
                    continue
                out = dest / name
                out.parent.mkdir(parents=True, exist_ok=True)
                with z.open(info) as src, open(out, "wb") as f:
                    shutil.copyfileobj(src, f)
    else:
        with tarfile.open(fileobj=__import__("io").BytesIO(data)) as t:
            try:
                t.extractall(dest, filter="data")
            except TypeError:  # Python without extraction filters: drop anything unsafe
                safe = [m for m in t.getmembers() if (m.isfile() or m.isdir()) and not m.name.startswith("/")
                        and ".." not in Path(m.name).parts]
                t.extractall(dest, members=safe)


def _read_package(label: str, root: Path, rep: Report, only_high: bool = False) -> None:
    s = Scan(root).run()
    for f in s.findings:
        if f.severity == LOW or (only_high and f.severity != HIGH):
            continue
        # common in published bundles; don't bury the real signals
        if f.what in ("Talks to a bare IP address", "Large encoded blob", "Scrambled JavaScript in a bundled file",
                      "Ready-made program in the repo: Linux program (ELF)", "Look-alike letters in names"):
            continue
        rep.findings.append((label, f))


def _check_integrity(data: bytes, integrity: str | None) -> bool:
    if not integrity:
        return True
    algo, _, b64 = integrity.partition("-")
    try:
        return hashlib.new(algo, data).digest() == base64.b64decode(b64)
    except (ValueError, TypeError):
        return True


def _osv(rep: Report, pkgs: list[tuple[str, str, str]]) -> None:
    try:
        hits = osv.query(pkgs)
    except Exception as e:
        rep.notes.append(f"couldn't reach the OSV known-malware database ({e.__class__.__name__}); only the file checks ran")
        return
    for h in hits:
        if h.malicious:
            s = next((h.details[x]["summary"] for x in h.malicious if x in h.details), "")
            rep.malicious.append((f"{h.name}@{h.version}", h.malicious, s))
        rest = [x for x in h.ids if not x.startswith("MAL-")]
        if rest:
            h.ids = rest
            rep.vulns.append(h)


# ----------------------------------------------------------------- npm

def _npm_tree(lock: dict) -> list[dict]:
    out = []
    for key, info in (lock.get("packages") or {}).items():
        if not key or not isinstance(info, dict) or info.get("link"):
            continue
        name = info.get("name") or key.rsplit("node_modules/", 1)[-1]
        if info.get("version"):
            out.append({"name": name, "version": info["version"], "resolved": info.get("resolved"),
                        "integrity": info.get("integrity"), "scripts": bool(info.get("hasInstallScript"))})
    return out


def npm_before(project: Path | None, args: list[str], tool: str = "npm") -> Report:
    rep = Report(tool)
    if not shutil.which("npm"):
        rep.skipped = "npm isn't installed"
        return rep
    pkgs = [a for a in args[1:] if not a.startswith("-")]
    global_ = "-g" in args or "--global" in args
    tmp = Path(tempfile.mkdtemp(prefix="guardpost-npm-"))
    try:
        if project and not global_ and (project / "package.json").exists():
            for f in ("package.json", "package-lock.json", "npm-shrinkwrap.json", ".npmrc"):
                if (project / f).exists():
                    shutil.copy(project / f, tmp / f)
        else:
            (tmp / "package.json").write_text('{"name":"guardpost-check","version":"0.0.0"}')
        # local file: deps can't be resolved from the copy; resolve the rest
        try:
            pj = json.loads((tmp / "package.json").read_text())
            for sec in ("dependencies", "devDependencies", "optionalDependencies"):
                for k, v in list((pj.get(sec) or {}).items()):
                    if isinstance(v, str) and v.startswith(("file:", "link:", "workspace:")):
                        del pj[sec][k]
            pj.pop("workspaces", None)
            (tmp / "package.json").write_text(json.dumps(pj))
        except (ValueError, OSError):
            pass
        print(ui.dim(f"guardpost: working out every package this install pulls in (nothing runs) ..."))
        r = subprocess.run(["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund",
                            "--loglevel=error", *pkgs], cwd=tmp, capture_output=True, text=True, timeout=600)
        if r.returncode != 0 or not (tmp / "package-lock.json").exists():
            rep.skipped = "npm couldn't work out the package list: " + (r.stderr.strip().splitlines() or ["?"])[-1][:160]
            return rep
        tree = _npm_tree(json.loads((tmp / "package-lock.json").read_text()))
        rep.packages = len(tree)
        print(ui.dim(f"guardpost: looking up {len(tree)} packages in the known-malware database (OSV) ..."))
        _osv(rep, [("npm", p["name"], p["version"]) for p in tree])
        bad = {m[0] for m in rep.malicious}
        wanted = {re.sub(r"(?<=.)@[^/@]*$", "", p) for p in pkgs}
        to_read = [p for p in tree if (p["scripts"] or p["name"] in wanted) and f"{p['name']}@{p['version']}" not in bad]
        rep.install_scripts = [f"{p['name']}@{p['version']}" for p in tree if p["scripts"]]
        if to_read:
            print(ui.dim(f"guardpost: downloading and reading {min(len(to_read), MAX_PACKAGES_READ)} package(s) "
                         "that run code on install or that you asked for ..."))
        for p in to_read[:MAX_PACKAGES_READ]:
            label = f"{p['name']}@{p['version']}"
            if not p["resolved"] or not p["resolved"].startswith("https://"):
                rep.notes.append(f"{label}: comes from {p['resolved'] or 'an unknown place'}, not downloaded")
                continue
            try:
                data = _fetch(p["resolved"])
            except Exception as e:
                rep.notes.append(f"{label}: download failed ({e.__class__.__name__})")
                continue
            if data is None:
                rep.notes.append(f"{label}: over 40 MB, not read")
                continue
            if not _check_integrity(data, p["integrity"]):
                rep.findings.append((label, Finding(HIGH, "Download doesn't match the lockfile's checksum",
                                                    "Someone may have swapped the package on the way.", label)))
                continue
            d = tmp / "read" / re.sub(r"[^\w.-]", "_", label)
            try:
                _safe_extract(data, "tar", d)
            except Exception:
                continue
            _read_package(label, d, rep)
        if len(to_read) > MAX_PACKAGES_READ:
            rep.notes.append(f"{len(to_read) - MAX_PACKAGES_READ} more packages with install scripts weren't read (limit)")
    except subprocess.TimeoutExpired:
        rep.skipped = "npm took too long to work out the package list"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return rep


def npm_after(project: Path, since: float) -> Report:
    rep = Report("npm")
    nm = project / "node_modules"
    lock = nm / ".package-lock.json"
    if not lock.exists():
        return rep
    try:
        tree = _npm_tree(json.loads(lock.read_text()))
    except (OSError, ValueError):
        return rep
    rep.packages = len(tree)
    new_dirs = []
    for p in tree:
        d = nm / p["name"]
        try:
            if d.is_dir() and d.stat().st_mtime >= since - 2:
                new_dirs.append((f"{p['name']}@{p['version']}", d))
        except OSError:
            pass
    _osv(rep, [("npm", p["name"], p["version"]) for p in tree])
    deadline = time.time() + AFTER_BUDGET
    read = 0
    for label, d in new_dirs:
        if time.time() > deadline:
            rep.notes.append(f"time limit: {len(new_dirs) - read} package folder(s) not read; run guardpost scan node_modules")
            break
        _read_package(label, d, rep, only_high=True)
        read += 1
    rep.notes.append(f"{read} new or updated package folder(s) read")
    return rep


# ----------------------------------------------------------------- pip

def _pip_python(tool: str) -> str | None:
    exe = shutil.which(tool)
    if not exe:
        return None
    try:
        first = open(exe, "rb").readline().decode(errors="replace")
    except OSError:
        return None
    m = re.match(r"#!\s*(\S+)", first)
    return m.group(1) if m else None


def _scan_wheel_pth(root: Path, label: str, rep: Report) -> None:
    for pth in root.glob("*.pth"):
        for line in pth.read_text(errors="replace").splitlines():
            if line.strip().startswith(("import ", "import\t")):
                rep.findings.append((label, Finding(HIGH, "Runs code every time Python starts (.pth file)",
                                                    "A .pth file with an import line runs on every Python start, "
                                                    "even when you never use this package.", pth.name, 0, line[:140])))
                break


def _sdist_read(name: str, version: str | None, tmp: Path, rep: Report) -> None:
    """Package without a wheel: pip would run its setup code. Read it first."""
    try:
        meta = json.loads(_fetch(f"https://pypi.org/pypi/{name}/{version + '/' if version else ''}json", 5_000_000) or b"{}")
    except Exception:
        rep.notes.append(f"{name}: couldn't read it from PyPI")
        return
    ver = meta.get("info", {}).get("version", version or "?")
    label = f"{name}@{ver}"
    for u in meta.get("urls", []):
        if u.get("packagetype") == "sdist":
            try:
                data = _fetch(u["url"])
            except Exception:
                data = None
            if not data or hashlib.sha256(data).hexdigest() != u.get("digests", {}).get("sha256"):
                rep.notes.append(f"{label}: source download failed or didn't match PyPI's checksum")
                return
            d = tmp / "sdist" / label
            try:
                _safe_extract(data, "zip" if u["filename"].endswith(".zip") else "tar", d)
            except Exception:
                return
            rep.install_scripts.append(label)
            rep.packages += 1
            _read_package(label, d, rep)
            _osv(rep, [("pypi", name, ver)])
            return
    rep.notes.append(f"{label}: no wheel and no source on PyPI")


def pip_before(tool: str, args: list[str]) -> Report:
    rep = Report(tool)
    py = _pip_python(tool)
    if not py:
        rep.skipped = f"couldn't find the Python behind {tool}"
        return rep
    tmp = Path(tempfile.mkdtemp(prefix="guardpost-pip-"))
    try:
        print(ui.dim("guardpost: working out every package this install pulls in (wheels only, nothing runs) ..."))
        cmd = [py, "-m", "pip", "install", "--dry-run", "--quiet", "--ignore-installed", "--only-binary=:all:",
               "--report", str(tmp / "r.json"), *args[1:]]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        err = r.stderr
        if "externally-managed-environment" in err:
            rep.skipped = "this Python is managed by Ubuntu (pip will refuse anyway); use a venv"
            return rep
        if r.returncode != 0 or not (tmp / "r.json").exists():
            # some package only comes as source: read the ones named on the command line
            names = [re.split(r"[<>=!~\[;@ ]", a, maxsplit=1)[0] for a in args[1:]
                     if not a.startswith("-") and not os.path.exists(a) and "://" not in a]
            versions = {re.split(r"[<>=!~\[;@ ]", a, maxsplit=1)[0]: (a.split("==", 1)[1] if "==" in a else None)
                        for a in args[1:] if not a.startswith("-")}
            if not names:
                rep.skipped = "pip couldn't work out the packages without building from source: " + \
                              (err.strip().splitlines() or ["?"])[-1][:160]
                return rep
            rep.notes.append("some packages only come as source code, so pip will run their setup code; "
                             "the named packages' source was read first, their dependencies weren't")
            for n in names[:10]:
                _sdist_read(n, versions.get(n), tmp, rep)
            return rep
        report = json.loads((tmp / "r.json").read_text())
        items = report.get("install", [])
        rep.packages = len(items)
        pk = [("pypi", it["metadata"]["name"], it["metadata"]["version"]) for it in items]
        print(ui.dim(f"guardpost: looking up {len(pk)} packages in the known-malware database (OSV) ..."))
        _osv(rep, pk)
        print(ui.dim(f"guardpost: downloading and reading the wheels (up to 40 MB each) ..."))
        for it in items[:MAX_PACKAGES_READ]:
            label = f"{it['metadata']['name']}@{it['metadata']['version']}"
            info = it.get("download_info") or {}
            url = info.get("url", "")
            if not url.startswith("https://"):
                continue
            try:
                data = _fetch(url)
            except Exception:
                rep.notes.append(f"{label}: download failed")
                continue
            if data is None:
                rep.notes.append(f"{label}: over 40 MB, checked in OSV only")
                continue
            want = ((info.get("archive_info") or {}).get("hashes") or {}).get("sha256")
            if want and hashlib.sha256(data).hexdigest() != want:
                rep.findings.append((label, Finding(HIGH, "Download doesn't match the index's checksum",
                                                    "Someone may have swapped the package on the way.", label)))
                continue
            d = tmp / "read" / re.sub(r"[^\w.-]", "_", label)
            try:
                _safe_extract(data, "zip", d)
            except Exception:
                continue
            _scan_wheel_pth(d, label, rep)
            _read_package(label, d, rep)
    except subprocess.TimeoutExpired:
        rep.skipped = "pip took too long to work out the packages"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return rep


def _site_dirs(py: str) -> list[Path]:
    try:
        out = subprocess.run([py, "-I", "-c", "import site,sys,json;print(json.dumps(site.getsitepackages()+[site.getusersitepackages()]))"],
                             capture_output=True, text=True, timeout=20).stdout
        return [Path(p) for p in json.loads(out) if os.path.isdir(p)]
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return []


def pip_after(tool: str, since: float) -> Report:
    rep = Report(tool)
    py = _pip_python(tool)
    if not py:
        return rep
    tmp_pk = []
    deadline = time.time() + AFTER_BUDGET
    for site in _site_dirs(py):
        for di in site.glob("*.dist-info"):
            try:
                if di.stat().st_mtime < since - 2:
                    continue
                meta = (di / "METADATA").read_text(errors="replace")
            except OSError:
                continue
            name = re.search(r"^Name:\s*(.+)$", meta, re.M)
            ver = re.search(r"^Version:\s*(.+)$", meta, re.M)
            if not name or not ver:
                continue
            label = f"{name.group(1).strip()}@{ver.group(1).strip()}"
            tmp_pk.append(("pypi", name.group(1).strip(), ver.group(1).strip()))
            tops = set()
            try:
                for line in (di / "RECORD").read_text(errors="replace").splitlines():
                    first = line.split(",")[0].split("/")[0]
                    if first and not first.endswith((".dist-info", ".data")) and first != "..":
                        tops.add(first)
            except OSError:
                pass
            if time.time() > deadline:
                rep.notes.append("time limit reached; some packages weren't read")
                break
            for t in sorted(tops):
                p = site / t
                if p.is_dir():
                    _read_package(label, p, rep, only_high=True)
                elif p.suffix == ".pth":
                    for l in p.read_text(errors="replace").splitlines():
                        if l.strip().startswith("import "):
                            rep.findings.append((label, Finding(HIGH, "Runs code every time Python starts (.pth file)",
                                                                "Installed a .pth file with an import line.", str(p), 0, l[:140])))
                            break
    rep.packages = len(tmp_pk)
    if tmp_pk:
        _osv(rep, tmp_pk)
    rep.notes.append(f"{len(tmp_pk)} new or updated package(s) read")
    return rep


# --------------------------------------------------------------- output

SEV_ORDER = {"critical": 0, "high": 1, "moderate": 2, "medium": 2, "low": 3, "unknown": 4}


def render(rep: Report, when: str) -> str:
    L = []
    if rep.skipped:
        return ui.dim(f"guardpost ({when}): dependency check skipped: {rep.skipped}")
    for label, ids, summary in rep.malicious:
        L.append(ui.red(f" HIGH  KNOWN MALWARE: {label}") + ui.dim(f"  ({', '.join(ids[:3])})"))
        if summary:
            L.append(f"        {summary}")
    shown: dict = {}
    for label, f in rep.findings:
        key = (label, f.what)
        if key in shown:
            continue
        shown[key] = 1
        tag = ui.red(" HIGH ") if f.severity == HIGH else ui.yellow(" WARN ")
        L.append(f"{tag} {label}: {ui.bold(f.what)}")
        loc = f"{f.file}:{f.line}" if f.line else f.file
        L.append(ui.dim(f"        {loc}" + (f"  > {f.snippet}" if f.snippet else "")))
    if rep.vulns:
        rows = []
        for h in rep.vulns:
            sevs = [h.details.get(i, {}).get("severity", "unknown") for i in h.ids]
            worst = min(sevs, key=lambda s: SEV_ORDER.get(s, 4)) if sevs else "unknown"
            fixed = next((h.details[i]["fixed"] for i in h.ids if h.details.get(i, {}).get("fixed")), "")
            rows.append((SEV_ORDER.get(worst, 4), h, worst, fixed))
        rows.sort(key=lambda r: r[0])
        L.append(ui.yellow(f" WARN  {len(rows)} package(s) with known vulnerabilities") +
                 ui.dim(" (bugs attackers can use, not malware)"))
        for _, h, worst, fixed in rows[:8]:
            L.append(f"        {h.name}@{h.version}: {len(h.ids)} ({worst})" + (f", fixed in {fixed}" if fixed else ""))
        if len(rows) > 8:
            L.append(ui.dim(f"        ... and {len(rows) - 8} more"))
    if rep.install_scripts:
        L.append(ui.dim(f"        runs code on install: {', '.join(rep.install_scripts[:8])}"
                        + (f" and {len(rep.install_scripts) - 8} more" if len(rep.install_scripts) > 8 else "")))
    for n in rep.notes:
        L.append(ui.dim(f"        note: {n}"))
    head = (ui.red("DANGER") if rep.danger() else ui.yellow("REVIEW") if rep.vulns or rep.findings else ui.green("CLEAN"))
    title = f"guardpost ({when}): {rep.packages} package(s) checked: {head}"
    return "\n".join([title] + L)
