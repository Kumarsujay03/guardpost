"""Morning boot audit: what happened to this laptop since the last check.

Reads the systemd journal (the user must be in the adm group, as on Ubuntu)
and compares a snapshot of the places malware uses to stay on a machine
with the snapshot from the last check. Nothing here needs root.
"""
from __future__ import annotations

import datetime as dt
import glob
import hashlib
import json
import os
import pwd
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import ui

STATE = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state")) / "guardpost"
REPORTS = STATE / "boot"
SNAPSHOT = STATE / "snapshot.json"
LAST_RUN = STATE / "last-run"
CONFIG = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "guardpost" / "config.json"

DEFAULT_CONFIG = {
    # boots or wake-ups in these hours (24 h clock, start..end) are pointed out
    "quiet_hours": [3, 8],
    # users allowed to log in; empty means just the user running guardpost
    "owners": [],
    # GitHub owners whose repos install without a check (your own account)
    "trusted_owners": [],
}

# one journal search for every event the report uses
EVENT_RE = (
    r"session opened for user|authentication failure|incorrect password attempt|"
    r"^auth \S+: |unlock for \S+:|stands down|Kernel command line:|"
    r"Lid opened|Suspending system|System returned from sleep|"
    r"Accepted (password|publickey|keyboard)|COMMAND=|"
    r"USB Mass Storage device detected|Attached SCSI removable disk|New USB device found"
)
RECOVERY_RE = re.compile(r"(^|\s)(single|emergency|rescue|init=|systemd\.unit=(rescue|emergency)|rd\.break|systemd\.debug-shell)", re.I)
LOGIN_SERVICES = {
    "gdm-face": "face", "gdm-fingerprint": "fingerprint", "gdm-password": "password",
    "gdm-autologin": "AUTOMATIC LOGIN", "gdm-smartcard": "smartcard", "sshd": "SSH (remote)",
    "login": "text console", "su": "su", "su-l": "su", "systemd-user": None, "cron": None,
    "gdm-launch-environment": None, "sudo": None, "sudo-i": None, "polkit-1": None,
    "runuser": None, "runuser-l": None, "pkexec": None,
}


@dataclass
class Boot:
    boot_id: str
    start: float
    end: float
    cmdline: str = ""
    clean: bool | None = None
    logins: list = field(default_factory=list)      # (time, user, method)
    failures: list = field(default_factory=list)    # (time, text)
    unlocks: list = field(default_factory=list)     # (time, method, user)
    wakes: list = field(default_factory=list)       # time
    usb: list = field(default_factory=list)         # (time, text)
    sudo: list = field(default_factory=list)        # (time, text)
    notes: list = field(default_factory=list)


def load_config() -> dict:
    cfg = dict(DEFAULT_CONFIG)
    try:
        cfg.update(json.loads(CONFIG.read_text()))
    except (OSError, ValueError):
        pass
    if not cfg["owners"]:
        cfg["owners"] = [pwd.getpwuid(os.getuid()).pw_name]
    return cfg


def journal(*args: str, timeout: int = 60) -> str:
    try:
        return subprocess.run(["journalctl", "--no-pager", "-q", *args], capture_output=True,
                              text=True, timeout=timeout).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def list_boots(since: float) -> list[Boot]:
    try:
        rows = json.loads(journal("--list-boots", "-o", "json") or "[]")
    except ValueError:
        rows = []
    boots = []
    for r in rows:
        start, end = r["first_entry"] / 1e6, r["last_entry"] / 1e6
        if end >= since:
            boots.append(Boot(r["boot_id"], start, end))
    return boots


def read_events(boots: list[Boot], since: float) -> None:
    by_id = {b.boot_id: b for b in boots}
    out = journal("--since", f"@{int(since)}", "-o", "json", "-g", EVENT_RE,
                  "--output-fields=MESSAGE,SYSLOG_IDENTIFIER,_BOOT_ID,_COMM", timeout=120)
    for line in out.splitlines():
        try:
            e = json.loads(line)
        except ValueError:
            continue
        b = by_id.get(e.get("_BOOT_ID"))
        msg = e.get("MESSAGE")
        if b is None or not isinstance(msg, str):
            continue
        t = int(e["__REALTIME_TIMESTAMP"]) / 1e6
        ident = e.get("SYSLOG_IDENTIFIER") or e.get("_COMM") or ""
        classify(b, t, ident, msg)


SESSION_RE = re.compile(r"pam_unix\(([^:]+):session\): session opened for user (\S+?)\(")
AUTHFAIL_RE = re.compile(r"pam_unix\(([^:]+):auth\): authentication failure.*\suser=(\S*)")
FACE_RE = re.compile(r"^auth (\S+): (\w+)")
UNLOCK_RE = re.compile(r"^(fingerprint|password|face) unlock for (\S+):")


def classify(b: Boot, t: float, ident: str, msg: str) -> None:
    if msg.startswith("Kernel command line:"):
        b.cmdline = msg.split(":", 1)[1].strip()
    elif m := SESSION_RE.search(msg):
        service, user = m.groups()
        method = LOGIN_SERVICES.get(service, service)
        if method:
            b.logins.append((t, user, method))
    elif m := AUTHFAIL_RE.search(msg):
        service, user = m.groups()
        what = LOGIN_SERVICES.get(service) or service
        b.failures.append((t, f"wrong password ({what}) for {user or '?'}"))
    elif "incorrect password attempt" in msg:
        b.failures.append((t, "sudo: " + msg.strip()))
    elif ident == "facelockd" and (m := FACE_RE.match(msg)):
        user, result = m.groups()
        if "other=True" in msg:
            b.failures.append((t, f"face unlock: a face you marked as someone else tried to unlock {user}"))
        elif "spoof=True" in msg and result != "matched":
            b.failures.append((t, f"face unlock: a photo or screen was held up for {user}"))
        if result == "matched":
            b.unlocks.append((t, "face", user))
    elif ident == "facelockd" and (m := UNLOCK_RE.match(msg)):
        method, user = m.groups()
        if method != "face":
            b.unlocks.append((t, method, user))
    elif "stands down" in msg:
        b.notes.append((t, "face and fingerprint matched together; only one login was opened"))
    elif msg.startswith("Lid opened") or "returned from sleep" in msg:
        if not b.wakes or t - b.wakes[-1] > 30:
            b.wakes.append(t)
    elif "Accepted " in msg:
        b.logins.append((t, msg.split(" for ")[1].split()[0] if " for " in msg else "?", "SSH (remote)"))
    elif "COMMAND=" in msg and ident == "sudo":
        b.sudo.append((t, msg.strip()))
    elif "USB Mass Storage" in msg or "removable disk" in msg:
        b.usb.append((t, "USB storage (pen drive or disk) plugged in"))


def check_shutdowns(boots: list[Boot], current: str) -> None:
    for b in boots:
        if b.boot_id == current:
            continue
        tail = journal("-b", b.boot_id, "-n", "40", "-o", "cat")
        b.clean = bool(re.search(r"systemd-shutdown|Reached target (System Shutdown|Power-Off|System Reboot)|"
                                 r"Journal stopped|Shutting down", tail))


def current_boot_id() -> str:
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip().replace("-", "")
    except OSError:
        return ""


# ---------------------------------------------------------------- snapshot

def _hash(path: str) -> str | None:
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()[:16]
    except OSError:
        return None


def _files(patterns: list[str]) -> dict:
    out = {}
    for pat in patterns:
        for p in sorted(glob.glob(os.path.expanduser(pat))):
            if os.path.isfile(p):
                h = _hash(p)
                if h:
                    out[p.replace(str(Path.home()), "~")] = h
    return out


def _lines(cmd: list[str]) -> list[str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return sorted({l.strip() for l in r.stdout.splitlines() if l.strip()})
    except (OSError, subprocess.TimeoutExpired):
        return []


def snapshot() -> dict:
    home_units = ["~/.config/systemd/user/*", "~/.config/systemd/user/*/*"]
    ports = []
    for l in _lines(["ss", "-tulnH"]):
        parts = l.split()
        if len(parts) >= 5:
            local = parts[4]
            scope = "this laptop only" if re.match(r"(127\.|\[::1\]|::1|localhost)", local) or "%lo" in local else "OPEN TO THE NETWORK"
            ports.append(f"{parts[0]} {local} ({scope})")
    users = []
    try:
        for p in pwd.getpwall():
            if p.pw_uid == 0 or 1000 <= p.pw_uid < 60000:
                users.append(f"{p.pw_name} (uid {p.pw_uid}, shell {p.pw_shell})")
    except OSError:
        pass
    admins = []
    try:
        for line in open("/etc/group"):
            name, _, _, members = line.strip().split(":", 3)
            if name in ("sudo", "wheel", "adm", "root") and members:
                admins.append(f"{name}: {members}")
    except (OSError, ValueError):
        pass
    return {
        "Services that start at boot": _lines(["systemctl", "list-unit-files", "--state=enabled", "--no-legend", "--plain"]),
        "Your services that start at login": _lines(["systemctl", "--user", "list-unit-files", "--state=enabled", "--no-legend", "--plain"]),
        "Scheduled timers": [l.split()[-2] if len(l.split()) > 2 else l for l in
                             _lines(["systemctl", "list-timers", "--all", "--no-legend", "--plain"])],
        "Your crontab": _lines(["crontab", "-l"]),
        "System cron files": _files(["/etc/crontab", "/etc/cron.d/*", "/etc/cron.hourly/*", "/etc/cron.daily/*"]),
        "Autostart programs": _files(["~/.config/autostart/*.desktop", "/etc/xdg/autostart/*.desktop"]),
        "Your service files": _files(home_units),
        "System service files": _files(["/etc/systemd/system/*.service", "/etc/systemd/system/*.timer",
                                        "/etc/systemd/system/*/*.service"]),
        "Shell start-up files": _files(["~/.bashrc", "~/.profile", "~/.bash_profile", "~/.bash_login", "~/.zshrc",
                                        "~/.config/fish/config.fish", "~/.config/fish/conf.d/*",
                                        "~/.config/environment.d/*", "/etc/environment", "/etc/profile",
                                        "/etc/profile.d/*", "/etc/bash.bashrc"]),
        "Login and password rules (PAM)": _files(["/etc/pam.d/*"]),
        "SSH keys allowed to log in": _files(["~/.ssh/authorized_keys", "~/.ssh/authorized_keys2", "/etc/ssh/sshd_config"]),
        "Library preload (a classic rootkit trick)": _files(["/etc/ld.so.preload"]),
        "Programs that run as root (setuid)": _lines(["find", "/usr/bin", "/usr/sbin", "/usr/local", "/usr/lib",
                                                       "/usr/libexec", "/opt", "/bin", "/sbin", "-xdev", "-type", "f",
                                                       "-perm", "/6000"]),
        "Listening ports": sorted(set(ports)),
        "User accounts": sorted(users),
        "Admin groups": admins,
        "GNOME Shell extensions": sorted(os.path.basename(p) for p in
                                         glob.glob(os.path.expanduser("~/.local/share/gnome-shell/extensions/*")) +
                                         glob.glob("/usr/share/gnome-shell/extensions/*")),
        "Browser extensions": sorted(set(os.path.basename(p) for p in
                                         glob.glob(os.path.expanduser("~/.config/*/Default/Extensions/*")) +
                                         glob.glob(os.path.expanduser("~/snap/*/common/*/Default/Extensions/*")) +
                                         glob.glob(os.path.expanduser("~/snap/*/*/.config/*/Default/Extensions/*")))),
    }


def diff_snapshots(old: dict, new: dict) -> list[tuple[str, list[str]]]:
    changes = []
    for key, now in new.items():
        before = old.get(key)
        if before is None:
            continue
        lines = []
        if isinstance(now, dict):
            for p in sorted(set(now) | set(before)):
                if p not in before:
                    lines.append(f"+ new      {p}")
                elif p not in now:
                    lines.append(f"- removed  {p}")
                elif before[p] != now[p]:
                    lines.append(f"~ changed  {p}")
        else:
            lines += [f"+ new      {x}" for x in now if x not in before]
            lines += [f"- removed  {x}" for x in before if x not in now]
        if lines:
            changes.append((key, lines))
    return changes


def packages_since(since: float) -> list[str]:
    out = []
    for log in sorted(glob.glob("/var/log/dpkg.log*")):
        if log.endswith(".gz"):
            continue
        try:
            for line in open(log, errors="replace"):
                parts = line.split()
                if len(parts) >= 5 and parts[2] in ("install", "remove", "purge"):
                    try:
                        t = dt.datetime.strptime(f"{parts[0]} {parts[1]}", "%Y-%m-%d %H:%M:%S").timestamp()
                    except ValueError:
                        continue
                    if t >= since:
                        out.append(f"{parts[0]} {parts[1][:5]}  {parts[2]:8} {parts[3]}")
        except OSError:
            pass
    return sorted(set(out))


def snap_flatpak_changes(since: float) -> list[str]:
    out = []
    for line in _lines(["snap", "changes"]):
        m = re.match(r"\d+\s+Done\s+(\S+T\S+)\s+\S+\s+(.*)", line)
        if m:
            try:
                t = dt.datetime.fromisoformat(m.group(1).replace("Z", "+00:00")).timestamp()
            except ValueError:
                continue
            if t >= since and re.match(r"(Install|Remove)", m.group(2)):
                out.append(f"snap: {m.group(2)}")
    return out


# ------------------------------------------------------------------ report

def fmt(t: float, date: bool = True) -> str:
    d = dt.datetime.fromtimestamp(t)
    return d.strftime("%a %d %b %H:%M") if date else d.strftime("%H:%M")


def span(seconds: float) -> str:
    h, m = divmod(int(seconds // 60), 60)
    return f"{h}h {m:02d}m" if h else f"{m}m"


def in_quiet(t: float, quiet: list[int]) -> bool:
    h = dt.datetime.fromtimestamp(t).hour
    a, b = quiet
    return a <= h < b if a <= b else (h >= a or h < b)


def audit(days: float | None = None, save: bool = True) -> tuple[str, list[str], str]:
    """Returns (report text, alerts, one-line summary)."""
    cfg = load_config()
    owners = set(cfg["owners"])
    now = time.time()
    try:
        since = float(LAST_RUN.read_text().strip())
    except (OSError, ValueError):
        since = now - 7 * 86400
    if days is not None:
        since = now - days * 86400
    # start from the boot that was running at the last check, so its
    # shutdown and the time the laptop was off are covered too
    boots = list_boots(since)
    if boots:
        since = min(since, boots[0].start)
    current = current_boot_id()
    read_events(boots, since)
    check_shutdowns(boots, current)

    alerts: list[str] = []
    notes: list[str] = []
    L: list[str] = []
    L.append(ui.h1(f"Boot audit  {fmt(now)}"))
    L.append(ui.dim(f"Covering {fmt(since)} to now ({span(now - since)}); {len(boots)} boot(s)."))
    L.append("")

    L.append(ui.h2("Power on and off"))
    prev = None
    for b in boots:
        if prev is not None:
            gap = b.start - prev.end
            if gap < 120:
                L.append(f"   restart at {fmt(b.start)}")
            else:
                L.append(f"   off   {fmt(prev.end)} -> {fmt(b.start)}   ({span(gap)}, nothing ran on Linux in between)")
        tag = " (this boot)" if b.boot_id == current else ""
        end = "now" if b.boot_id == current else fmt(b.end, date=False)
        L.append(f"   on    {fmt(b.start)} -> {end}{tag}")
        if b.clean is False:
            notes.append(f"The boot at {fmt(b.start)} didn't shut down cleanly (battery ran out, a hard power-off or a crash).")
        if b.cmdline and RECOVERY_RE.search(b.cmdline):
            alerts.append(f"The boot at {fmt(b.start)} used a recovery/rescue start-up ({RECOVERY_RE.search(b.cmdline).group(0).strip()}). "
                          "That gives a root shell without your password.")
        if in_quiet(b.start, cfg["quiet_hours"]):
            alerts.append(f"The laptop was switched on at {fmt(b.start)}, inside your quiet hours "
                          f"({cfg['quiet_hours'][0]:02d}:00-{cfg['quiet_hours'][1]:02d}:00).")
        owned = [l for l in b.logins if l[1] in owners]
        if not b.logins and not b.unlocks and b.boot_id != current and b.end - b.start > 20:
            alerts.append(f"The laptop was switched on at {fmt(b.start)} for {span(b.end - b.start)} and nobody logged in. "
                          "Someone may have tried the login screen or started another system from the boot menu.")
        elif not owned and b.logins:
            alerts.append(f"The boot at {fmt(b.start)} had logins, but none by you.")
        prev = b
    L.append("")

    L.append(ui.h2("Logins and unlocks"))
    any_login = False
    for b in boots:
        for t, user, method in b.logins:
            any_login = True
            mark = "" if user in owners else ui.red("  <- not you")
            L.append(f"   {fmt(t)}  login   {user} by {method}{mark}")
            if user not in owners:
                alerts.append(f"{user} logged in at {fmt(t)} by {method}.")
            if method in ("SSH (remote)", "AUTOMATIC LOGIN", "text console"):
                alerts.append(f"Login at {fmt(t)} by {method} ({user}); you normally log in at the screen.")
        gdm = [l for l in b.logins if l[2] in ("face", "fingerprint", "password")]
        for a, c in zip(gdm, gdm[1:]):
            if c[0] - a[0] < 3 and a[1] == c[1]:
                notes.append(f"{fmt(c[0])}: {a[2]} and {c[2]} logged you in at the same moment, "
                             "so GDM opened two sessions (the facelock claim fix stops this).")
        counts: dict[str, int] = {}
        for _, method, user in b.unlocks:
            counts[method] = counts.get(method, 0) + 1
        if counts:
            any_login = True
            L.append(f"   {fmt(b.start, date=True)[:10]} boot: unlocks by " +
                     ", ".join(f"{m} x{n}" for m, n in sorted(counts.items())))
        for t, text in b.notes:
            L.append(ui.dim(f"   {fmt(t)}  {text}"))
    if not any_login:
        L.append("   none")
    L.append("")

    failures = [(t, x) for b in boots for t, x in b.failures]
    L.append(ui.h2("Failed attempts"))
    if failures:
        for t, text in failures:
            L.append(f"   {fmt(t)}  {text}")
        others = [x for _, x in failures if "someone else" in x or "photo" in x]
        if others:
            alerts.append(f"{len(others)} face unlock attempt(s) by someone else or with a photo.")
        if len(failures) - len(others) >= 3:
            alerts.append(f"{len(failures) - len(others)} wrong password attempts.")
        elif len(failures) > len(others):
            notes.append(f"{len(failures) - len(others)} wrong password attempt(s), probably typos.")
    else:
        L.append("   none")
    L.append("")

    wakes = [t for b in boots for t in b.wakes]
    quiet_wakes = [t for t in wakes if in_quiet(t, cfg["quiet_hours"])]
    L.append(ui.h2("Wake-ups from sleep"))
    L.append(f"   {len(wakes)} wake-up(s)" + (": " + ", ".join(fmt(t) for t in quiet_wakes) + " in quiet hours" if quiet_wakes else ""))
    for t in quiet_wakes:
        alerts.append(f"The laptop woke from sleep at {fmt(t)}, inside your quiet hours.")
    L.append("")

    usb = [(t, x) for b in boots for t, x in b.usb]
    sudo = [(t, x) for b in boots for t, x in b.sudo]
    L.append(ui.h2("USB storage and admin commands"))
    L.append(f"   USB storage plugged in: {len(usb)} time(s)" + (" (" + ", ".join(fmt(t) for t, _ in usb[:6]) + ")" if usb else ""))
    L.append(f"   sudo commands run: {len(sudo)}")
    for t, x in sudo[-5:]:
        cmd = x.split("COMMAND=", 1)[1] if "COMMAND=" in x else x
        who = x.split(":", 1)[0].strip()
        L.append(ui.dim(f"      {fmt(t)}  {who}: {cmd[:110]}"))
    L.append("")

    L.append(ui.h2("Changes since the last check"))
    new_snap = snapshot()
    try:
        old_snap = json.loads(SNAPSHOT.read_text())
    except (OSError, ValueError):
        old_snap = None
    pkgs = packages_since(since) + snap_flatpak_changes(since)
    if old_snap is None:
        L.append("   first run: saved what's on the laptop now; the next check shows what changed")
    else:
        changes = diff_snapshots(old_snap, new_snap)
        risky = {"Library preload (a classic rootkit trick)", "SSH keys allowed to log in", "User accounts",
                 "Admin groups", "Programs that run as root (setuid)", "Login and password rules (PAM)"}
        for key, lines in changes:
            L.append(f"   {key}:")
            L += [f"      {l}" for l in lines[:25]]
            if len(lines) > 25:
                L.append(f"      ... and {len(lines) - 25} more")
            added = [l for l in lines if l.startswith(("+", "~"))]
            if key in risky and added:
                alerts.append(f"{key}: {len(added)} new or changed. Check you did this.")
            elif key == "Listening ports" and any("OPEN TO THE NETWORK" in l for l in added):
                alerts.append("A program started listening on the network.")
            elif added and not pkgs:
                notes.append(f"{key}: {len(added)} new or changed, with no package installs to explain it.")
        if not changes:
            L.append("   nothing changed")
    if pkgs:
        L.append(f"   Packages ({len(pkgs)}):")
        L += [f"      {p}" for p in pkgs[:30]]
        if len(pkgs) > 30:
            L.append(f"      ... and {len(pkgs) - 30} more")
    L.append("")

    L.append(ui.h2("Verdict"))
    if alerts:
        for a in alerts:
            L.append(ui.red(f"   ! {a}"))
    for n in notes:
        L.append(ui.yellow(f"   - {n}"))
    if not alerts:
        L.append(ui.green("   All clear: nothing points to anyone else using the laptop."))
    L.append("")
    L.append(ui.dim("Only Linux is visible here: if someone starts Windows or a USB system, Linux keeps no record of it. "
                    "A firmware (BIOS/UEFI) password and disk encryption cover that."))

    logins_total = sum(len(b.logins) for b in boots)
    summary = (f"{len(alerts)} thing(s) to check: {alerts[0]}" if alerts else
               f"All clear. {len(boots)} boot(s), {logins_total} login(s), {len(failures)} failed attempt(s).")
    text = "\n".join(L)
    if save:
        REPORTS.mkdir(parents=True, exist_ok=True)
        path = REPORTS / dt.datetime.fromtimestamp(now).strftime("%Y-%m-%d_%H%M%S.txt")
        path.write_text(ui.strip(text) + "\n")
        SNAPSHOT.write_text(json.dumps(new_snap, indent=1))
        LAST_RUN.write_text(str(now))
        for old in sorted(REPORTS.glob("*.txt"))[:-60]:
            old.unlink()
    return text, alerts, summary


def latest_report() -> Path | None:
    reports = sorted(REPORTS.glob("*.txt"))
    return reports[-1] if reports else None


def notify(summary: str, alerts: list[str], report: Path | None) -> None:
    title = "Guardpost: check your laptop" if alerts else "Guardpost: all clear"
    cmd = ["notify-send", "-a", "Guardpost", "-i", "security-high" if not alerts else "security-low",
           "-u", "critical" if alerts else "normal"]
    if report:
        cmd += ["-A", "open=Open report", "-w"]
    try:
        r = subprocess.run(cmd + [title, summary], capture_output=True, text=True, timeout=600)
        if report and r.stdout.strip() == "open":
            subprocess.Popen(["xdg-open", str(report)], start_new_session=True)
    except (OSError, subprocess.TimeoutExpired):
        pass
