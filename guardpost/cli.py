"""guardpost: a morning boot audit and a malware check for code you download."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from . import __version__, bootaudit, deps, feeds, osv, popular, sweep, ui
from .scanner import HIGH, LOW, MEDIUM, Finding, Scan, clamav

CACHE = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "guardpost"
SCANS = CACHE / "scans"
SEV_LABEL = {HIGH: ui.red(" HIGH "), MEDIUM: ui.yellow(" WARN "), LOW: ui.dim(" note ")}
VERDICT_TEXT = {
    "danger": "DANGER: don't install, build or open this in VS Code until you've read the HIGH items.",
    "review": "REVIEW: nothing clearly malicious, but read the WARN items before installing.",
    "clean": "LOOKS CLEAN: no signs of malware found.",
}


def _git(root: Path, *args: str) -> str:
    try:
        return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, timeout=20).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _cache_path(root: Path) -> Path:
    return SCANS / (hashlib.sha1(str(root.resolve()).encode()).hexdigest()[:16] + ".json")


def do_scan(root: Path, label: str | None = None, slow_ok: bool = False) -> tuple[Scan, float, Path]:
    t0 = time.time()
    s = Scan(root).run()
    s.findings = clamav(root, slow_ok) + s.findings
    took = time.time() - t0
    data = s.to_json()
    data.update(label=label or root.name, head=_git(root, "rev-parse", "HEAD"),
                remote=_git(root, "remote", "get-url", "origin"), time=time.time())
    SCANS.mkdir(parents=True, exist_ok=True)
    cp = _cache_path(root)
    cp.write_text(json.dumps(data, indent=1))
    report = cp.with_suffix(".txt")
    report.write_text(ui.strip(render(s, label or root.name, took, full=True)) + "\n")
    return s, took, report


def render(s: Scan, label: str, took: float, full: bool, limit: int = 15) -> str:
    L = [ui.h1(f"guardpost scan: {label}") + ui.dim(f"  {s.files} files, {took:.1f} s" +
                                                    (" (stopped at the file limit)" if s.truncated else ""))]
    if s.hooks:
        L.append(ui.h2("Runs automatically when you install or build"))
        L += [f"   {h[:150]}" for h in s.hooks[:10]]
    shown = [f for f in s.findings if full or f.severity != LOW]
    if shown:
        L.append(ui.h2("Findings"))
        # group identical titles so one noisy rule doesn't bury the rest
        seen: dict[tuple, int] = {}
        printed = 0
        for f in shown:
            key = (f.severity, f.what)
            seen[key] = seen.get(key, 0) + 1
            if seen[key] > (6 if full else 2) or (printed >= limit and not full):
                continue
            printed += 1
            loc = f"{f.file}:{f.line}" if f.line else f.file
            L.append(f"{SEV_LABEL[f.severity]} {ui.bold(f.what)}")
            L.append(f"        {loc}")
            if f.snippet:
                L.append(ui.dim(f"        > {f.snippet}"))
            L.append(f"        {f.why}")
        hidden = len(shown) - printed
        if hidden > 0:
            L.append(ui.dim(f"   ... {hidden} more of the same kinds"))
    c = s.counts()
    v = s.verdict()
    colour = {"danger": ui.red, "review": ui.yellow, "clean": ui.green}[v]
    L.append(colour(f"\n{VERDICT_TEXT[v]}") + ui.dim(f"  ({c[HIGH]} high, {c[MEDIUM]} warn, {c[LOW]} notes)"))
    return "\n".join(L)


def ask(question: str) -> bool:
    try:
        with open("/dev/tty", "r+") as tty:
            tty.write(question)
            tty.flush()
            return tty.readline().strip().lower() in ("y", "yes")
    except OSError:
        return False


# --------------------------------------------------------------- commands

def cmd_boot(a) -> int:
    if a.last:
        r = bootaudit.latest_report()
        if not r:
            print("No report yet. Run: guardpost boot")
            return 1
        print(r.read_text())
        return 0
    if a.notify:
        time.sleep(a.delay)
    text, alerts, summary = bootaudit.audit(days=a.days, save=not a.no_save)
    if a.notify:
        bootaudit.notify(summary, alerts, bootaudit.latest_report())
    else:
        print(text)
    return 1 if alerts else 0


def _clone(url: str, dest: Path) -> bool:
    empty = dest.parent / "template"
    empty.mkdir(exist_ok=True)
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    r = subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never",
                        "clone", "--quiet", "--depth", "1", "--no-recurse-submodules", f"--template={empty}",
                        url, str(dest)], env=env, timeout=600)
    return r.returncode == 0


def scan_url(url: str, quiet: bool = False) -> Scan | None:
    tmp = Path(tempfile.mkdtemp(prefix="guardpost-"))
    try:
        if not quiet:
            print(ui.dim(f"guardpost: fetching {url} into a temporary folder to check it (nothing is run)"))
        if not _clone(url, tmp / "repo"):
            print(ui.red(f"guardpost: couldn't fetch {url}"))
            return None
        s, took, report = do_scan(tmp / "repo", label=url)
        print(render(s, url, took, full=False))
        return s
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def cmd_scan(a) -> int:
    target = a.target or "."
    if re.match(r"(https?://|git@|ssh://|git://)", target) or re.match(r"^[\w.-]+/[\w.-]+$", target) and not os.path.exists(target):
        url = target if not re.match(r"^[\w.-]+/[\w.-]+$", target) else f"https://github.com/{target}"
        s = scan_url(url)
        return 2 if s is None else (1 if s.verdict() == "danger" else 0)
    root = Path(target).resolve()
    if not root.is_dir():
        print(f"guardpost: {target} is not a folder")
        return 2
    if os.environ.get("GUARDPOST_OFF"):
        return 0
    s, took, report = do_scan(root, slow_ok=not a.after_clone)
    if a.json:
        print(json.dumps(s.to_json(), indent=1))
    elif a.after_clone:
        v = s.verdict()
        if v == "clean" and not s.hooks:
            print(ui.green(f"guardpost: {root.name} looks clean") + ui.dim(f" ({s.files} files checked, nothing runs on install)"))
        elif v == "clean":
            print(ui.green(f"guardpost: {root.name} looks clean") + ui.dim(f" ({s.files} files checked)"))
            for h in s.hooks[:5]:
                print(ui.dim(f"   on install: {h[:140]}"))
        else:
            print(render(s, root.name, took, full=False))
            print(ui.dim(f"Full report: {report}"))
    else:
        print(render(s, root.name, took, full=a.all))
        if not a.all and any(f.severity == LOW for f in s.findings):
            print(ui.dim("Notes hidden; see all with --all. Full report: ") + ui.dim(str(report)))
    return 1 if s.verdict() == "danger" else 0


def _project_root(start: Path, marker: str | None) -> Path:
    top = _git(start, "rev-parse", "--show-toplevel")
    if top:
        return Path(top)
    if marker:
        p = start
        while p != p.parent:
            if (p / marker).exists():
                return p
            p = p.parent
    return start


def _guard_local(root: Path) -> bool:
    """Scan (or reuse a scan at the same commit) and decide whether to go on."""
    if _trusted(root):
        return True
    head = _git(root, "rev-parse", "HEAD")
    dirty = ""  # your own edits don't need a rescan; a new commit (pull) does
    cp = _cache_path(root)
    s = None
    try:
        old = json.loads(cp.read_text())
        if head and old.get("head") == head and not dirty and time.time() - old.get("time", 0) < 30 * 86400:
            verdict = old["verdict"]
            if verdict == "clean":
                return True
            if verdict == "review":
                print(ui.yellow(f"guardpost: {root.name} had {old['counts']['medium']} warning(s) when checked; "
                                f"see {cp.with_suffix('.txt')}"))
                return True
    except (OSError, ValueError, KeyError):
        pass
    print(ui.dim(f"guardpost: checking {root} before installing ..."))
    s, took, report = do_scan(root)
    v = s.verdict()
    if v == "clean":
        print(ui.green(f"guardpost: {root.name} looks clean") + ui.dim(f" ({s.files} files)"))
        return True
    print(render(s, root.name, took, full=False))
    print(ui.dim(f"Full report: {report}"))
    if v == "review":
        return True
    return ask(ui.red("Install anyway? [y/N] "))


def _trusted(root: Path) -> bool:
    """Your own work: a git repo with no remote, or one under a GitHub owner you trust."""
    if not (root / ".git").exists() and not _git(root, "rev-parse", "--git-dir"):
        return False
    remotes = _git(root, "remote", "-v")
    if not remotes:
        return True
    owners = bootaudit.load_config().get("trusted_owners", [])
    urls = {l.split()[1] for l in remotes.splitlines() if len(l.split()) > 1}
    return bool(owners) and all(any(re.search(rf"[:/]{re.escape(o)}/", u, re.I) for o in owners) for u in urls)


def _guard_names(names: list[str], eco: str) -> bool:
    bad = [(n, popular.lookalike(n, eco)) for n in names]
    bad = [(n, k) for n, k in bad if k and not popular.is_popular(n, eco)]
    if not bad:
        return True
    for n, k in bad:
        print(ui.red(f"guardpost: '{n}' is one letter away from the popular package '{k}'. "
                     "Look-alike names are a common way to slip in malware."))
    return ask(ui.red("Install anyway? [y/N] "))


DEPS_CACHE = CACHE / "deps"


def _deps_key(root: Path, args: list[str]) -> str:
    h = hashlib.sha1(" ".join(args).encode() + str(root).encode())
    for f in ("package.json", "package-lock.json", "requirements.txt", "pyproject.toml"):
        try:
            h.update((root / f).read_bytes())
        except OSError:
            pass
    return h.hexdigest()[:20]


def _layer2(run, key: str) -> bool:
    """Run a dependency check (reusing a clean result from the last day) and decide."""
    DEPS_CACHE.mkdir(parents=True, exist_ok=True)
    marker = DEPS_CACHE / key
    try:
        if time.time() - marker.stat().st_mtime < 86400:
            return True
    except OSError:
        pass
    rep = run()
    print(deps.render(rep, "before install"))
    if rep.danger():
        return ask(ui.red("Install anyway? [y/N] "))
    if not rep.skipped and not rep.vulns:
        marker.touch()
    return True


def cmd_after(a) -> int:
    """After an install finished: read what actually landed."""
    if os.environ.get("GUARDPOST_OFF"):
        return 0
    tool, args = a.tool, a.args
    try:
        if tool in ("npm", "pnpm", "yarn", "bun"):
            rep = deps.npm_after(_project_root(Path.cwd(), "package.json"), a.since)
        elif tool in ("pip", "pip3"):
            rep = deps.pip_after(tool, a.since)
        else:
            return 0
        if rep.packages == 0:
            return 0
        if rep.danger() or rep.findings:
            print(deps.render(rep, "after install"))
            if rep.danger():
                print(ui.red("guardpost: something harmful was installed. Remove it now "
                             f"({'npm uninstall' if tool != 'pip' else 'pip uninstall'} <package>) and run: guardpost sweep"))
        else:
            print(ui.dim(f"guardpost (after install): {rep.packages} package(s) checked, no malware found"
                         + (f", {len(rep.vulns)} with known vulnerabilities" if rep.vulns else "")))
    except Exception as e:
        print(ui.dim(f"guardpost: after-install check skipped ({e})"), file=sys.stderr)
    return 0


def _notify(title: str, body: str) -> None:
    try:
        subprocess.run(["notify-send", "-a", "Guardpost", title, body], timeout=10, capture_output=True)
    except (OSError, subprocess.TimeoutExpired):
        pass


def cmd_update(a) -> int:
    """Threat feeds, then guardpost itself (auto_update in the config)."""
    from . import updater
    quiet = a.quiet or a.timer
    msgs = feeds.update(verbose=not quiet)
    feeds_failed = all(m.startswith("FAIL") for m in msgs if not m.startswith("skip"))
    if a.feeds_only:
        return 1 if feeds_failed else 0
    try:
        version, tar_url, sum_url, page = updater.latest()
    except Exception as e:
        if not quiet:
            print(f"couldn't check for a new guardpost release: {e}")
        return 1 if feeds_failed else 0
    if not updater.newer(version):
        if not quiet:
            print(f"guardpost {__version__} is the latest version.")
        return 0
    auto = bootaudit.load_config().get("auto_update", True)
    if a.check or (a.timer and not auto):
        print(f"guardpost {version} is available (you have {__version__}): {page}")
        if a.timer:
            _notify(f"Guardpost {version} is available", "Install it with: guardpost update")
        else:
            print("Install it with: guardpost update")
        return 0
    if not quiet:
        print(f"updating guardpost {__version__} -> {version} ...")
    try:
        updater.install(version, tar_url, sum_url)
    except Exception as e:
        print(f"update failed, still on {__version__}: {e}")
        if a.timer:
            _notify("Guardpost update failed", str(e)[:200])
        return 1
    print(f"guardpost {version} installed. Release notes: {page}")
    if a.timer:
        _notify(f"Guardpost updated to {version}", "Open a new terminal to use it. Notes: " + page)
    return 0


def cmd_uninstall(a) -> int:
    script = Path(__file__).resolve().parent.parent / "uninstall.sh"
    if not ask("Remove guardpost (hooks, timers, command)? Reports and settings are kept. [y/N] "):
        return 1
    return subprocess.run(["bash", str(script)]).returncode


def cmd_sweep(a) -> int:
    if a.last:
        r = sweep.latest()
        print(r.read_text() if r else "No sweep yet. Run: guardpost sweep")
        return 0
    if a.update or (feeds.age_days() or 99) > 2:
        feeds.update(verbose=not a.notify)
    if not a.notify:
        print(ui.dim("guardpost: sweeping the system (a few minutes; nothing is changed) ..."))
    text, alerts, summary = sweep.sweep(a.only.split(",") if a.only else None)
    if a.notify:
        title = "Guardpost sweep: problems found" if alerts else "Guardpost sweep: no malware"
        r = sweep.latest()
        try:
            out = subprocess.run(["notify-send", "-a", "Guardpost", "-u", "critical" if alerts else "normal",
                                  "-A", "open=Open report", "-w", title, summary],
                                 capture_output=True, text=True, timeout=3600).stdout
            if out.strip() == "open" and r:
                subprocess.Popen(["xdg-open", str(r)], start_new_session=True)
        except (OSError, subprocess.TimeoutExpired):
            pass
    else:
        print(text)
    return 1 if alerts else 0


def cmd_guard(a) -> int:
    """Called by the shell wrappers: exit 0 to go on, 1 to stop."""
    if os.environ.get("GUARDPOST_OFF"):
        return 0
    tool, args = a.tool, a.args
    try:
        if tool in ("npm", "pnpm", "yarn", "bun"):
            sub = args[0] if args else ("install" if tool == "yarn" else "")
            if sub not in ("install", "i", "add", "ci", "isntall", "in"):
                return 0
            pkgs = [x for x in args[1:] if not x.startswith("-")]
            urls = [x for x in pkgs if re.match(r"(https?://|git(\+\w+)?://|github:|git@)", x) or re.match(r"^[\w.-]+/[\w.-]+(#.*)?$", x)]
            for u in urls:
                u2 = re.sub(r"^github:", "https://github.com/", re.sub(r"^git\+", "", u)).split("#")[0]
                if re.match(r"^[\w.-]+/[\w.-]+$", u2):
                    u2 = f"https://github.com/{u2}"
                s = scan_url(u2)
                if s and s.verdict() == "danger" and not ask(ui.red("Install anyway? [y/N] ")):
                    return 1
            names = [re.sub(r"(?<=.)@[^/]*$", "", x) for x in pkgs if x not in urls and not x.startswith((".", "/", "file:"))]
            if names and not _guard_names(names, "npm"):
                return 1
            project = _project_root(Path.cwd(), "package.json")
            if not pkgs or any(x.startswith((".", "/", "file:")) for x in pkgs):
                if not _guard_local(project):
                    return 1
            # layer 2: every package the install pulls in
            dep_args = ["install"] + [x for x in pkgs if x not in urls] + [x for x in args[1:] if x in ("-g", "--global")]
            return 0 if _layer2(lambda: deps.npm_before(project, dep_args, tool), _deps_key(project, dep_args)) else 1
        if tool in ("pip", "pip3", "uv", "pipx"):
            original = list(args)
            if tool == "uv":
                if args[:2] != ["pip", "install"] and (not args or args[0] != "add"):
                    return 0
                args = args[2:] if args[:1] == ["pip"] else args[1:]
            else:
                if not args or args[0] != "install":
                    return 0
                args = args[1:]
            i = 0
            local: list[Path] = []
            names: list[str] = []
            while i < len(args):
                x = args[i]
                if x in ("-r", "--requirement", "-c", "--constraint") and i + 1 < len(args):
                    sc = Scan(Path.cwd())
                    sc._requirements(Path(args[i + 1]))
                    bad = [f for f in sc.findings if f.severity != LOW]
                    for f in bad:
                        print(ui.yellow(f"guardpost: {args[i + 1]}:{f.line}: {f.what}: {f.snippet}"))
                    if any(f.severity == HIGH for f in bad) and not ask(ui.red("Install anyway? [y/N] ")):
                        return 1
                    i += 2
                    continue
                if x in ("-e", "--editable") and i + 1 < len(args):
                    x = args[i + 1]
                    i += 1
                if x.startswith("-"):
                    i += 1
                    continue
                if re.match(r"git\+|https?://.*\.git|https?://github\.com/", x):
                    u = re.sub(r"^git\+", "", x).split("@")[0] if x.startswith("git+") else x
                    u = re.sub(r"#.*$", "", u)
                    if "github.com" in u or u.endswith(".git"):
                        s = scan_url(u)
                        if s and s.verdict() == "danger" and not ask(ui.red("Install anyway? [y/N] ")):
                            return 1
                elif os.path.isdir(x):
                    local.append(Path(x).resolve())
                elif not os.path.exists(x):
                    names.append(re.split(r"[<>=!~\[;@ ]", x, maxsplit=1)[0])
                i += 1
            if names and not _guard_names(names, "pypi"):
                return 1
            for p in local:
                if not _guard_local(_project_root(p, None) if (p / ".git").exists() else p):
                    return 1
            if tool in ("pip", "pip3") and original[:1] == ["install"]:
                return 0 if _layer2(lambda: deps.pip_before(tool, original), _deps_key(Path.cwd(), original)) else 1
            if names:  # uv/pipx: no dry-run report, so check the names
                try:
                    mal = osv.malicious_by_name([("pypi", n) for n in names])
                except Exception:
                    mal = {}
                for n, ids in mal.items():
                    print(ui.yellow(f"guardpost: {n} has had a malicious release ({', '.join(ids[:2])}); "
                                    "check the version you get"))
            return 0
        if tool == "make":
            if "install" in args:
                return 0 if _guard_local(_project_root(Path.cwd(), "Makefile")) else 1
            return 0
        if tool == "cargo":
            if args[:1] == ["install"] and "--path" in args:
                i = args.index("--path") + 1
                return 0 if i < len(args) and _guard_local(Path(args[i]).resolve()) or i >= len(args) else 1
            if args[:1] == ["install"] and "--git" in args:
                u = args[args.index("--git") + 1] if args.index("--git") + 1 < len(args) else ""
                s = scan_url(u) if u else None
                if s and s.verdict() == "danger" and not ask(ui.red("Install anyway? [y/N] ")):
                    return 1
            return 0
    except KeyboardInterrupt:
        return 1
    except Exception as e:  # never break the user's real command because of a guardpost bug
        print(ui.dim(f"guardpost: check skipped ({e})"), file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="guardpost", description=__doc__)
    p.add_argument("--version", action="version", version=f"guardpost {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("boot", help="what happened to this laptop since the last check")
    b.add_argument("--days", type=float, help="look back this many days instead of since the last check")
    b.add_argument("--last", action="store_true", help="show the last report again")
    b.add_argument("--notify", action="store_true", help="send a desktop notification instead of printing")
    b.add_argument("--delay", type=float, default=0, help=argparse.SUPPRESS)
    b.add_argument("--no-save", action="store_true", help="don't save this as the new baseline")
    b.set_defaults(fn=cmd_boot)

    s = sub.add_parser("scan", help="check a folder, a git URL or a GitHub owner/repo for malware")
    s.add_argument("target", nargs="?", help="folder (default: current), URL, or owner/repo")
    s.add_argument("--all", action="store_true", help="also show low-level notes")
    s.add_argument("--json", action="store_true")
    s.add_argument("--after-clone", action="store_true", help=argparse.SUPPRESS)
    s.set_defaults(fn=cmd_scan)

    g = sub.add_parser("guard", help=argparse.SUPPRESS)
    g.add_argument("tool")
    g.add_argument("args", nargs=argparse.REMAINDER)
    g.set_defaults(fn=cmd_guard)

    u = sub.add_parser("update", help="refresh threat feeds and update guardpost (runs daily by itself)")
    u.add_argument("--check", action="store_true", help="only say whether a new release exists")
    u.add_argument("--feeds-only", action="store_true", help="refresh the threat feeds, not guardpost itself")
    u.add_argument("--quiet", action="store_true")
    u.add_argument("--timer", action="store_true", help=argparse.SUPPRESS)
    u.set_defaults(fn=cmd_update)

    un = sub.add_parser("uninstall", help="remove guardpost (keeps reports and settings)")
    un.set_defaults(fn=cmd_uninstall)

    w = sub.add_parser("sweep", help="check everything already installed for malware and known bugs")
    w.add_argument("--last", action="store_true", help="show the last sweep report")
    w.add_argument("--update", action="store_true", help="refresh the threat feeds first")
    w.add_argument("--only", help="comma list: updates,packages,network,processes,startup,integrity,files")
    w.add_argument("--notify", action="store_true", help=argparse.SUPPRESS)
    w.set_defaults(fn=cmd_sweep)

    af = sub.add_parser("after", help=argparse.SUPPRESS)
    af.add_argument("tool")
    af.add_argument("--since", type=float, required=True)
    af.add_argument("args", nargs=argparse.REMAINDER)
    af.set_defaults(fn=cmd_after)

    a = p.parse_args(argv)
    if a.cmd in ("guard", "after") and a.args[:1] == ["--"]:
        a.args = a.args[1:]
    try:
        return a.fn(a)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
