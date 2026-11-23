"""System sweep: look through what is already on the laptop, the way MVT
looks through a phone, against threat data refreshed every week.

1. Ubuntu packages with security fixes waiting, marked when the bug is on
   CISA's list of ones attackers are using right now.
2. Every pip, npm and cargo package already installed (your venvs, project
   node_modules, global installs) looked up in OSV: known malware and
   known vulnerabilities.
3. Live connections to known malware command servers (abuse.ch feeds),
   and /etc/hosts redirecting well-known sites.
4. Running programs started from /tmp or /dev/shm, deleted after starting,
   or pretending to be kernel threads; LD_PRELOAD and /etc/ld.so.preload.
5. Start-up places (autostart, services, cron, shell start-up files) that
   run from temp folders or contain download-and-run / reverse-shell code.
6. System files changed since their package installed them (dpkg --verify),
   and kernel modules that no package or DKMS put there.
7. Programs sitting in temp folders; YARA and ClamAV when installed.
"""
from __future__ import annotations

import datetime as dt
import glob
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

from . import feeds, osv, ui
from .bootaudit import STATE
from .scanner import LINE_RULES, HIGH, MEDIUM

REPORTS = STATE / "sweep"
HOME = Path.home()


def _run(cmd: list[str], timeout: int = 120) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


class Sweep:
    def __init__(self):
        self.alerts: list[str] = []   # things to act on now
        self.warns: list[str] = []    # worth a look
        self.L: list[str] = []
        self.kev = feeds.kev()

    def section(self, title: str):
        self.L.append("")
        self.L.append(ui.h2(title))

    def line(self, s: str):
        self.L.append("   " + s)

    # ------------------------------------------------------------ 1 apt
    def os_packages(self):
        self.section("System packages with security fixes waiting")
        if not shutil.which("apt"):
            self.line(ui.dim("skipped: this check needs apt (Debian, Ubuntu, Mint, Pop!_OS)"))
            return
        out = _run(["apt", "list", "--upgradable"], 60)
        sec = []
        for l in out.splitlines():
            m = re.match(r"(\S+?)/(\S+)\s+(\S+)\s+\S+\s+\[upgradable from: (\S+)\]", l)
            if m and "security" in m.group(2):
                sec.append((m.group(1), m.group(4), m.group(3)))
        try:
            lists_age = (time.time() - max(p.stat().st_mtime for p in Path("/var/lib/apt/lists").glob("*Packages"))) / 86400
        except (ValueError, OSError):
            lists_age = None
        if not sec:
            self.line(ui.green("none") + (ui.dim(f" (package lists {lists_age:.0f} day(s) old)") if lists_age is not None else ""))
        else:
            rel = _run(["lsb_release", "-rs"]).strip()
            eco = f"Ubuntu:{rel}:LTS" if rel else "Ubuntu"
            exploited = {}
            try:
                for h in osv.query([(eco, n, cur) for n, cur, _ in sec], details=True, detail_limit=400):
                    cves = {c for i in h.ids for c in h.details.get(i, {}).get("aliases", [])}
                    cves |= {i.replace("UBUNTU-", "") for i in h.ids if i.startswith("UBUNTU-CVE-")}
                    hot = sorted(c for c in cves if c in self.kev)
                    if hot:
                        exploited[h.name] = hot
            except Exception:
                pass
            for n, cur, new in sec:
                tag = ui.red(f"  ACTIVELY EXPLOITED: {', '.join(exploited[n][:3])}") if n in exploited else ""
                self.line(f"{n} {cur} -> {new}{tag}")
            self.warns.append(f"{len(sec)} Ubuntu package(s) have security fixes waiting: run sudo apt upgrade")
            if exploited:
                self.alerts.append(f"{len(exploited)} installed package(s) have bugs attackers are exploiting now "
                                   f"({', '.join(list(exploited)[:4])}). Update today: sudo apt upgrade")
        snaps = [l.split()[0] for l in _run(["snap", "refresh", "--list"], 60).splitlines()[1:] if l.strip()]
        if snaps:
            self.line(f"snaps with updates: {', '.join(snaps[:10])}")
        if Path("/var/run/reboot-required").exists():
            self.line(ui.yellow("a restart is needed to finish security updates (kernel or core libraries)"))
            self.warns.append("Restart to finish installing security updates.")

    # ------------------------------------------------ 2 language packages
    def _pip_envs(self) -> list[Path]:
        sites = set(glob.glob(str(HOME / ".local/lib/python3*/site-packages")))
        for cfg in _run(["find", str(HOME), "-maxdepth", "5", "-name", "pyvenv.cfg", "-not", "-path", "*/node_modules/*",
                         "-not", "-path", "*/.cache/*", "-not", "-path", "*/snap/*"], 120).splitlines():
            sites |= set(glob.glob(str(Path(cfg).parent / "lib/python3*/site-packages")))
        return sorted(Path(s) for s in sites)

    def _npm_trees(self) -> list[Path]:
        locks = _run(["find", str(HOME), "-maxdepth", "6", "-path", "*/node_modules/.package-lock.json",
                      "-not", "-path", "*/node_modules/*/node_modules/*", "-not", "-path", "*/.cache/*",
                      "-not", "-path", "*/snap/*", "-not", "-path", "*/.vscode*/*"], 120).splitlines()
        g = _run(["npm", "root", "-g"], 30).strip()
        roots = [Path(l) for l in locks]
        if g and Path(g).is_dir():
            roots.append(Path(g))
        return roots

    def language_packages(self):
        self.section("Installed pip / npm / cargo packages (OSV: malware and known bugs)")
        pk: dict[tuple, set] = {}
        for site in self._pip_envs():
            for di in site.glob("*.dist-info"):
                try:
                    meta = (di / "METADATA").read_text(errors="replace")
                except OSError:
                    continue
                n = re.search(r"^Name:\s*(.+)$", meta, re.M)
                v = re.search(r"^Version:\s*(.+)$", meta, re.M)
                if n and v:
                    pk.setdefault(("pypi", n.group(1).strip(), v.group(1).strip()), set()).add(str(site).replace(str(HOME), "~"))
        for root in self._npm_trees():
            if root.name == ".package-lock.json":
                try:
                    data = json.loads(root.read_text())
                except (OSError, ValueError):
                    continue
                where = str(root.parent.parent).replace(str(HOME), "~")
                for key, info in (data.get("packages") or {}).items():
                    if isinstance(info, dict) and info.get("version") and key:
                        name = info.get("name") or key.rsplit("node_modules/", 1)[-1]
                        pk.setdefault(("npm", name, info["version"]), set()).add(where)
            else:
                for pj in list(root.glob("*/package.json")) + list(root.glob("@*/*/package.json")):
                    try:
                        d = json.loads(pj.read_text())
                        pk.setdefault(("npm", d["name"], d["version"]), set()).add("npm global")
                    except (OSError, ValueError, KeyError):
                        pass
        try:
            crates = json.loads((HOME / ".cargo/.crates2.json").read_text()).get("installs", {})
            for k in crates:
                parts = k.split()
                if len(parts) >= 2:
                    pk.setdefault(("cargo", parts[0], parts[1]), set()).add("cargo install")
        except (OSError, ValueError):
            pass
        eco_count = {}
        for e, _, _ in pk:
            eco_count[e] = eco_count.get(e, 0) + 1
        self.line(f"{len(pk)} package versions: " + ", ".join(f"{n} {e}" for e, n in sorted(eco_count.items())))
        if not pk:
            return
        try:
            hits = osv.query(list(pk), details=True, detail_limit=400)
        except Exception as e:
            self.line(ui.yellow(f"couldn't reach OSV ({e.__class__.__name__}); try again online"))
            self.warns.append("The installed-package check couldn't reach OSV.")
            return
        mal = [h for h in hits if h.malicious]
        for h in mal:
            where = ", ".join(sorted(pk[(next(k for k in osv.ECOSYSTEM if osv.ECOSYSTEM[k] == h.ecosystem), h.name, h.version)])[:3])
            self.line(ui.red(f"KNOWN MALWARE: {h.name}@{h.version} in {where} ({', '.join(h.malicious[:2])})"))
            self.alerts.append(f"Known malicious package installed: {h.name}@{h.version} ({where}). Remove it and change "
                               "passwords/tokens that were on this laptop.")
        vul = [h for h in hits if not h.malicious]
        sev_rank = {"critical": 0, "high": 1, "moderate": 2, "medium": 2, "low": 3}
        rows = []
        for h in vul:
            sevs = [h.details.get(i, {}).get("severity", "unknown") for i in h.ids]
            worst = min(sevs, key=lambda s: sev_rank.get(s, 4))
            cves = {c for i in h.ids for c in h.details.get(i, {}).get("aliases", [])}
            hot = sorted(c for c in cves if c in self.kev)
            fixed = next((h.details[i]["fixed"] for i in h.ids if h.details.get(i, {}).get("fixed")), "")
            key = (next(k for k in osv.ECOSYSTEM if osv.ECOSYSTEM[k] == h.ecosystem), h.name, h.version)
            rows.append((0 if hot else 1, sev_rank.get(worst, 4), h, worst, fixed, hot, sorted(pk.get(key, []))))
        rows.sort(key=lambda r: (r[0], r[1]))
        if rows:
            self.line(f"{len(rows)} with known vulnerabilities:")
        for _, _, h, worst, fixed, hot, where in rows[:20]:
            tag = ui.red(f" ACTIVELY EXPLOITED {', '.join(hot[:2])}") if hot else ""
            self.line(f"  {h.name}@{h.version} ({worst}, {len(h.ids)})" + (f" fixed in {fixed}" if fixed else "") +
                      ui.dim(f"  {', '.join(where[:2])}") + tag)
        if len(rows) > 20:
            self.line(ui.dim(f"  ... and {len(rows) - 20} more (full list in the saved report)"))
        crit = [r for r in rows if r[0] == 0 or r[1] == 0]
        if crit:
            self.warns.append(f"{len(crit)} installed package(s) have critical or actively exploited bugs.")

    # --------------------------------------------------------- 3 network
    def network(self):
        self.section("Connections to known malware servers")
        bad = feeds.bad_ips()
        peers = []
        for l in _run(["ss", "-tnpH", "state", "established"]).splitlines():
            parts = l.split()
            if len(parts) >= 4:
                ip = parts[3].rsplit(":", 1)[0].strip("[]")
                peers.append((ip, " ".join(parts[4:])))
        hits = [(ip, proc) for ip, proc in peers if ip in bad]
        weak_n = len(feeds.suspicious_ips())
        self.line(f"{len(peers)} open connection(s) compared with {len(bad)} known malware servers and "
                  f"{weak_n} IPs on several blocklists" if bad or weak_n else
                  ui.yellow("no feed yet: run guardpost update"))
        weak = feeds.suspicious_ips()
        for ip, proc in peers:
            if ip in weak and ip not in bad:
                self.line(ui.yellow(f"connected to {ip}, which is on several blocklists  {proc}"))
                self.warns.append(f"A program is connected to {ip}, an IP on several blocklists.")
        for ip, proc in hits:
            self.line(ui.red(f"CONNECTED TO {ip}: {bad[ip]}  {proc}"))
            self.alerts.append(f"A program is connected to {ip}, a known {bad[ip]}.")
        try:
            for line in open("/etc/hosts"):
                s = line.split("#")[0].split()
                if len(s) >= 2 and not s[0].startswith(("127.", "::1", "fe00", "ff0", "0.0.0.0")) and any(
                        re.search(r"(google|microsoft|windowsupdate|github|apple|ubuntu|canonical|bank|paypal|"
                                  r"npmjs|pypi|python|mozilla|chrome)", h) for h in s[1:]):
                    self.line(ui.red(f"/etc/hosts sends {' '.join(s[1:])} to {s[0]}"))
                    self.alerts.append(f"/etc/hosts redirects {s[1]} to {s[0]}.")
        except OSError:
            pass

    # ------------------------------------------------------- 4 processes
    def processes(self):
        self.section("Running programs")
        odd = 0
        if Path("/etc/ld.so.preload").exists() and Path("/etc/ld.so.preload").read_text().strip():
            self.line(ui.red("/etc/ld.so.preload is set: every program loads " + Path("/etc/ld.so.preload").read_text().strip()))
            self.alerts.append("/etc/ld.so.preload forces a library into every program (a rootkit trick).")
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                exe = os.readlink(f"/proc/{pid}/exe")
            except OSError:
                continue
            try:
                cmd = open(f"/proc/{pid}/cmdline", "rb").read().replace(b"\0", b" ").decode(errors="replace").strip()
                env = open(f"/proc/{pid}/environ", "rb").read()
            except OSError:
                cmd, env = "", b""
            name = cmd.split()[0] if cmd else exe
            if re.match(r"^/(tmp|var/tmp|dev/shm)/", exe):
                odd += 1
                self.line(ui.red(f"pid {pid} runs from a temp folder: {exe}"))
                self.alerts.append(f"A program is running from a temp folder: {exe}")
            elif exe.endswith(" (deleted)") and re.match(r"^/(tmp|var/tmp|dev/shm|home)/", exe):
                odd += 1
                self.line(ui.red(f"pid {pid} deleted its own program file after starting: {exe}"))
                self.alerts.append(f"A program deleted its own file after starting (malware hides like this): {exe}")
            if re.match(r"^\[[\w/:.-]+\]$", name):
                odd += 1
                self.line(ui.red(f"pid {pid} calls itself {name} like a kernel thread, but is {exe}"))
                self.alerts.append(f"A program pretends to be the kernel thread {name}: {exe}")
            if b"LD_PRELOAD=" in env:
                v = re.search(rb"LD_PRELOAD=([^\0]*)", env).group(1).decode(errors="replace")
                # snaps preload from their own read-only, signed image
                libs = [x for x in re.split(r"[: ]", v) if x and not x.startswith("/snap/")]
                if libs and not re.search(r"libgtk3-nocsd|libmozsandbox|libsandbox|vgpreload|libfakeroot", v):
                    v = ":".join(libs)
                    odd += 1
                    self.line(ui.yellow(f"pid {pid} ({name[:40]}) loads LD_PRELOAD={v}"))
                    self.warns.append(f"A program runs with LD_PRELOAD={v}.")
        if not odd:
            self.line(ui.green("nothing odd") + ui.dim(" (only your own programs are visible without root)"))

    # ------------------------------------------------------ 5 start-up
    def startup(self):
        self.section("Start-up places")
        files = []
        for pat in ["~/.config/autostart/*.desktop", "/etc/xdg/autostart/*.desktop", "~/.config/systemd/user/*.service",
                    "~/.config/systemd/user/*.timer", "/etc/systemd/system/*.service", "/etc/cron.d/*", "/etc/crontab",
                    "~/.bashrc", "~/.profile", "~/.bash_profile", "~/.zshrc", "~/.config/fish/config.fish",
                    "~/.config/fish/conf.d/*", "/etc/profile.d/*", "/etc/rc.local"]:
            files += [Path(p) for p in glob.glob(os.path.expanduser(pat))]
        cron = _run(["crontab", "-l"])
        found = 0
        sources = [(f, f.read_text(errors="replace")) for f in files if f.is_file() and f.stat().st_size < 500_000] + \
                  ([(Path("crontab -l"), cron)] if cron else [])
        for f, text in sources:
            for i, line in enumerate(text.splitlines(), 1):
                if line.lstrip().startswith("#"):
                    continue
                hit = None
                if re.search(r"(Exec(Start)?=|^\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+)[^\n]*(/tmp/|/dev/shm/|/var/tmp/)", line):
                    hit = (HIGH, "starts a program from a temp folder")
                else:
                    for sev, title, _, rx in LINE_RULES:
                        if sev in (HIGH, MEDIUM) and title != "Makes itself start automatically" and rx.search(line):
                            hit = (sev, title.lower())
                            break
                if hit:
                    found += 1
                    where = str(f).replace(str(HOME), "~")
                    self.line((ui.red if hit[0] == HIGH else ui.yellow)(f"{where}:{i}: {hit[1]}") + ui.dim(f"  > {line.strip()[:110]}"))
                    (self.alerts if hit[0] == HIGH else self.warns).append(f"{where}:{i} {hit[1]}")
        if not found:
            self.line(ui.green(f"nothing odd in {len(sources)} start-up file(s)"))

    # ----------------------------------------------- 6 integrity, modules
    def integrity(self):
        self.section("System files changed since install (dpkg --verify)")
        if not shutil.which("dpkg"):
            self.line(ui.dim("skipped: needs dpkg (Debian-based systems)"))
            return
        out = _run(["dpkg", "--verify"], 900)
        changed = []
        for l in out.splitlines():
            m = re.match(r"^(\S{9})\s+(c?)\s*(/\S.*)$", l)
            if not m or m.group(2) == "c" or m.group(1)[2] != "5":
                continue
            path = m.group(3)
            if re.match(r"^/(usr/)?(s?bin|lib|lib64|libexec)/|^/usr/lib/|^/boot/", path) and not re.search(
                    r"\.pyc$|/__pycache__/|\.cache$|/locale/|/fonts/|/icons/|\.mo$", path):
                changed.append(path)
        if changed:
            for p in changed[:20]:
                self.line(ui.red(f"changed: {p}"))
            self.alerts.append(f"{len(changed)} system program/library file(s) differ from what their package installed "
                               f"(e.g. {changed[0]}). Rootkits replace system files like this.")
        else:
            self.line(ui.green("no system programs or libraries changed") + ui.dim(" (files only root can read are skipped)"))

        self.section("Kernel modules")
        owned = set()
        for lst in glob.glob("/var/lib/dpkg/info/*.list"):
            try:
                for p in open(lst, errors="replace"):
                    if "/modules/" in p:
                        owned.add(p.strip())
            except OSError:
                pass
        stray = []
        mods = [l.split()[0] for l in open("/proc/modules")] if os.path.exists("/proc/modules") else []
        for m in mods:
            fn = _run(["modinfo", "-n", m], 10).strip()
            if not fn or fn.startswith("(builtin)"):
                continue
            real = os.path.realpath(fn)
            if fn in owned or real in owned or "/updates/dkms/" in fn or "/kernel/" in fn and fn.replace("/usr/lib/", "/lib/") in owned \
                    or fn.replace("/lib/", "/usr/lib/", 1) in owned:
                continue
            stray.append(f"{m} ({fn})")
        if stray:
            for s in stray[:10]:
                self.line(ui.yellow(f"not from any package or DKMS: {s}"))
            self.warns.append(f"{len(stray)} kernel module(s) loaded that no package installed.")
        else:
            self.line(ui.green(f"all {len(mods)} loaded modules come from packages or DKMS"))

    # --------------------------------------------- 7 files, YARA, ClamAV
    def files(self):
        self.section("Programs in temp folders, YARA and ClamAV")
        elves = []
        for d in ("/tmp", "/var/tmp", "/dev/shm"):
            for p in _run(["find", d, "-maxdepth", "3", "-type", "f", "-size", "+1k", "-size", "-200M"], 60).splitlines():
                try:
                    with open(p, "rb") as f:
                        if f.read(4) == b"\x7fELF":
                            elves.append(p)
                except OSError:
                    pass
        elves = [e for e in elves if not re.search(r"/(\.mount_|snap-private-tmp|systemd-private|claude-\d+|\.org\.chromium|"
                                                   r"go-build|pip-|cargo-install|\.X11-unix)", e)]
        for e in elves[:10]:
            self.line(ui.yellow(f"program in a temp folder: {e}"))
        if elves:
            self.warns.append(f"{len(elves)} program file(s) in temp folders.")
        targets = [str(HOME / "Downloads"), "/tmp", "/var/tmp", "/dev/shm", str(HOME / ".local/bin"),
                   str(HOME / ".config/autostart")]
        targets = [t for t in targets if os.path.isdir(t)]
        ydir = feeds.yara_dir()
        if shutil.which("yara") and ydir:
            rules = sorted(str(p) for p in ydir.glob("*.yar"))
            hits = set()
            for chunk in range(0, len(rules), 200):
                out = _run(["yara", "-r", "-w", "-f", "-N", *rules[chunk:chunk + 200], *targets], 900)
                hits |= {l.strip() for l in out.splitlines() if l.strip()}
            for h in sorted(hits)[:20]:
                self.line(ui.red(f"YARA: {h}"))
            if hits:
                self.alerts.append(f"YARA malware rules matched {len(hits)} file(s).")
            else:
                self.line(ui.green(f"YARA: {len(rules)} rule files, no matches") + ui.dim(f" in {', '.join(targets)}"))
        else:
            self.line(ui.dim("YARA: not installed (sudo apt install yara, then guardpost update)"))
        cs = shutil.which("clamdscan") or shutil.which("clamscan")
        if cs:
            out = _run([cs, "--infected", "--no-summary", *(["-r"] if cs.endswith("clamscan") else ["--fdpass", "-m"]), *targets], 3600)
            found = [l for l in out.splitlines() if l.endswith("FOUND")]
            for f in found[:20]:
                self.line(ui.red(f"ClamAV: {f}"))
            if found:
                self.alerts.append(f"ClamAV found {len(found)} infected file(s).")
            else:
                self.line(ui.green("ClamAV: nothing found") + ui.dim(f" in {', '.join(targets)}"))
        else:
            self.line(ui.dim("ClamAV: not installed (sudo apt install clamav)"))

    # ------------------------------------------------------------- run
    def run(self, parts: list[str] | None = None) -> tuple[str, list[str], str]:
        t0 = time.time()
        age = feeds.age_days()
        steps = [("updates", self.os_packages), ("packages", self.language_packages), ("network", self.network),
                 ("processes", self.processes), ("startup", self.startup), ("integrity", self.integrity),
                 ("files", self.files)]
        for name, fn in steps:
            if parts and name not in parts:
                continue
            try:
                fn()
            except Exception as e:
                self.line(ui.yellow(f"{name} check failed: {e}"))
        head = [ui.h1(f"System sweep  {dt.datetime.now():%a %d %b %H:%M}"),
                ui.dim(f"Threat feeds updated {age:.0f} day(s) ago." if age is not None else
                       "Threat feeds never updated: run guardpost update") + ui.dim(f"  Took {time.time() - t0:.0f} s.")]
        verdict = [ "", ui.h2("Verdict")]
        verdict += [ui.red(f"   ! {a}") for a in self.alerts]
        verdict += [ui.yellow(f"   - {w}") for w in dict.fromkeys(self.warns)]
        if not self.alerts:
            verdict.append(ui.green("   No malware or intrusion found."))
        text = "\n".join(head + self.L + verdict)
        summary = (f"{len(self.alerts)} problem(s): {self.alerts[0]}" if self.alerts else
                   f"No malware found. {len(self.warns)} thing(s) to update or look at." if self.warns else
                   "No malware found, nothing to update.")
        return text, self.alerts, summary


def sweep(parts=None, save=True):
    text, alerts, summary = Sweep().run(parts)
    if save:
        REPORTS.mkdir(parents=True, exist_ok=True)
        p = REPORTS / dt.datetime.now().strftime("%Y-%m-%d_%H%M%S.txt")
        p.write_text(ui.strip(text) + "\n")
        for old in sorted(REPORTS.glob("*.txt"))[:-30]:
            old.unlink()
    return text, alerts, summary


def latest() -> Path | None:
    r = sorted(REPORTS.glob("*.txt"))
    return r[-1] if r else None
