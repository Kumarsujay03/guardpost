"""Static scan of a source tree for signs of malware, before anything in it runs.

Nothing in the scanned tree is executed or imported: files are only read as
bytes and text. The checks follow what real supply-chain attacks did:
install hooks that download and run code, code hidden off the right edge of
the screen or behind base64/eval, stealers that read browser passwords,
wallets and SSH keys and post them to a Discord/Telegram webhook, look-alike
package names, programs shipped inside the source, and invisible Unicode
that makes code read differently from what runs.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import zipfile
from dataclasses import dataclass, asdict
from pathlib import Path

from . import popular

HIGH, MEDIUM, LOW = "high", "medium", "low"
RANK = {HIGH: 0, MEDIUM: 1, LOW: 2}

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache",
             ".next", ".cache", "target", ".gradle", ".idea"}
CODE_EXT = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".py", ".pyw", ".sh", ".bash", ".zsh", ".fish",
            ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".wsf", ".rb", ".pl", ".php", ".go", ".rs", ".c",
            ".cc", ".cpp", ".h", ".java", ".kt", ".lua", ".mk", ".cs", ".swift", ".scala", ".r", ".jl",
            ".gradle", ".cmake", ".nix", ".hta", ".applescript", ".scpt"}
CODE_NAMES = {"makefile", "gnumakefile", "dockerfile", "containerfile", "build.rs", "setup.py", "conftest.py",
              "rakefile", "gemfile", "justfile", "pkgbuild", "install", "configure", "vagrantfile"}
DATA_EXT = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp", ".txt", ".md", ".json", ".csv",
            ".woff", ".woff2", ".ttf", ".otf", ".mp3", ".mp4", ".wav", ".pdf", ".xml", ".yml", ".yaml", ".html",
            ".css", ".lock", ".toml", ".ini", ".cfg", ".log", ".dat"}
PROGRAM_EXT = {".exe", ".dll", ".scr", ".msi", ".com", ".cpl", ".sys", ".jar", ".apk", ".dmg", ".pkg",
               ".deb", ".rpm", ".appimage", ".elf", ".bin", ".so", ".dylib", ".pyc", ".pyo", ".node", ".class"}
ARCHIVE_EXT = {".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".xz", ".bz2", ".zst"}
SOFT_PATH = re.compile(r"(^|/)(tests?|spec|__tests__|fixtures?|examples?|samples?|docs?|documentation)/", re.I)
MAX_TEXT = 2_000_000
MAX_FILES = 40_000


@dataclass
class Finding:
    severity: str
    what: str          # short title
    why: str           # what it means for you
    file: str
    line: int = 0
    snippet: str = ""


# The detection patterns live in rules.json: as data they don't make the
# scanner's own source look like the malware it describes.
_RULES = json.loads((Path(__file__).with_name("rules.json")).read_text())
LINE_RULES = [(r["severity"], r["title"], r["why"], re.compile(r["pattern"])) for r in _RULES["line_rules"]]
SECRET_RE = re.compile(_RULES["secret"])
NETWORK_RE = re.compile(_RULES["network"])
BIDI_RE = re.compile(_RULES["bidi"])
ZW_RE = re.compile(_RULES["zero_width"])
HOMOGLYPH_RE = re.compile(_RULES["homoglyph"])
GAP_RE = re.compile(r"[ \t]{150,}")  # linear; the hidden-code check is done around it in code
OBF_JS_RE = re.compile(_RULES["obfuscated_js"])
BASE64_RE = re.compile(_RULES["base64_blob"])
EXEC_NEAR_RE = re.compile(_RULES["exec_near"])
CHUNK = 2000
OBF_JS_RE = re.compile(r"\b_0x[0-9a-f]{4,6}\b")
BASE64_RE = re.compile(r"['\"`]([A-Za-z0-9+/]{400,}={0,2})['\"`]")
EXEC_NEAR_RE = re.compile(r"\b(eval|exec|Function|child_process|subprocess|os\.system|spawn|execSync|Popen|"
                          r"\$\(|base64\s+-d|b64decode|atob|Buffer\.from)\b")


def _rel(root: Path, p: Path) -> str:
    try:
        return str(p.relative_to(root))
    except ValueError:
        return str(p)


def _is_code(p: Path, head: bytes) -> bool:
    name = p.name.lower()
    return (p.suffix.lower() in CODE_EXT or name in CODE_NAMES or name.startswith("makefile")
            or head.startswith(b"#!"))


def _program_kind(head: bytes) -> str | None:
    if head.startswith(b"\x7fELF"):
        return "Linux program (ELF)"
    if head.startswith(b"MZ"):
        return "Windows program (EXE/DLL)"
    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "macOS program (Mach-O)"
    return None


def _snip(s: str, n: int = 140) -> str:
    s = s.strip().replace("\t", " ")
    return s if len(s) <= n else s[:n] + " ..."


class Scan:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.findings: list[Finding] = []
        self.files = 0
        self.truncated = False
        self.hooks: list[str] = []   # what runs automatically on install

    def add(self, sev, what, why, path: Path | str, line=0, snippet=""):
        rel = path if isinstance(path, str) else _rel(self.root, path)
        self.findings.append(Finding(sev, what, why, rel, line, _snip(snippet)))

    # ---------------------------------------------------------------- walk
    def run(self) -> "Scan":
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                if self.files >= MAX_FILES:
                    self.truncated = True
                    return self._finish()
                p = Path(dirpath) / fn
                try:
                    st = p.lstat()
                except OSError:
                    continue
                if stat.S_ISLNK(st.st_mode):
                    self._symlink(p)
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue
                self.files += 1
                self._file(p, st)
        self._manifests()
        return self._finish()

    def _finish(self) -> "Scan":
        self.findings.sort(key=lambda f: (RANK[f.severity], f.file, f.line))
        return self

    def _symlink(self, p: Path):
        try:
            target = os.readlink(p)
        except OSError:
            return
        resolved = (p.parent / target).resolve()
        if not str(resolved).startswith(str(self.root)):
            self.add(MEDIUM, "Link pointing outside the repo",
                     "A file in the repo is a shortcut to somewhere else on your laptop; a build step could "
                     "read or overwrite that file through it.", p, 0, f"-> {target}")

    def _file(self, p: Path, st):
        try:
            with open(p, "rb") as f:
                head = f.read(4096)
        except OSError:
            return
        ext = p.suffix.lower()
        kind = _program_kind(head)
        rel = _rel(self.root, p)
        if kind:
            if ext in DATA_EXT or ext == "":
                if ext:
                    self.add(HIGH, "Program disguised as a data file",
                             f"{p.name} looks like a {ext} file but is really a {kind}. Malware hides like this.", p)
                else:
                    self.add(MEDIUM, f"Ready-made program in the repo: {kind}",
                             "You can't see its source; it does whatever it was built to do.", p)
            else:
                sev = LOW if SOFT_PATH.search(rel) or ext in (".so", ".node", ".dylib") else MEDIUM
                self.add(sev, f"Ready-made program in the repo: {kind}",
                         "You can't see its source. Check the project explains why it ships one.", p)
            return
        if ext in (".pyc", ".pyo", ".class", ".jar", ".apk", ".msi", ".scr", ".bat", ".vbs", ".hta", ".lnk"):
            if ext in (".pyc", ".pyo", ".class", ".jar"):
                self.add(MEDIUM, f"Compiled code without source ({ext})",
                         "Compiled files can hold code that isn't in the readable source.", p)
            elif ext in (".scr", ".hta", ".lnk", ".vbs"):
                self.add(MEDIUM, f"Windows script/shortcut ({ext})",
                         "These file types are a favourite way to deliver Windows malware.", p)
        if ext == ".zip" or head.startswith(b"PK\x03\x04"):
            self._zip(p)
        elif ext in ARCHIVE_EXT and st.st_size > 0:
            self.add(LOW, "Archive in the repo", "Packed files can't be checked without unpacking them.", p)
        if st.st_size > MAX_TEXT or b"\x00" in head[:1024]:
            return
        try:
            text = p.read_bytes().decode("utf-8", errors="replace")
        except OSError:
            return
        if ext == ".pth":
            for i, line in enumerate(text.splitlines(), 1):
                if line.strip().startswith(("import ", "import\t")):
                    self.add(HIGH, "Runs code every time Python starts (.pth file)",
                             "If this gets installed, the import line runs on every Python start.", p, i, line)
                    break
        code = _is_code(p, head)
        self._unicode(p, text, code)
        if code or p.name in ("package.json",) or rel.startswith(".vscode/") or ext in (".yml", ".yaml"):
            self._code(p, text, rel)

    def _zip(self, p: Path):
        try:
            with zipfile.ZipFile(p) as z:
                infos = z.infolist()
                if any(i.flag_bits & 0x1 for i in infos):
                    self.add(HIGH, "Password-protected archive",
                             "Malware is often shipped in locked zips so scanners can't look inside.", p)
                bad = [i.filename for i in infos if Path(i.filename).suffix.lower() in PROGRAM_EXT | {".bat", ".ps1", ".vbs", ".lnk", ".hta", ".scr"}]
                if bad:
                    self.add(MEDIUM, "Archive with programs inside",
                             f"It contains {len(bad)} program file(s), e.g. {', '.join(bad[:3])}.", p)
        except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError):
            pass

    def _unicode(self, p: Path, text: str, code: bool):
        if not code and p.suffix.lower() not in (".json", ".yml", ".yaml", ".toml"):
            return
        for i, line in enumerate(text.splitlines(), 1):
            if BIDI_RE.search(line):
                self.add(HIGH, "Invisible text-direction characters (Trojan Source)",
                         "The code shown in your editor is not the code that runs.", p, i,
                         line.encode("unicode_escape").decode()[:140])
                break
        for i, line in enumerate(text.splitlines(), 1):
            outside = re.sub(r"(['\"`]).*?\1|#.*$|//.*$", "", line)  # literals and comments are fine
            if ZW_RE.search(outside) and not line.lstrip().startswith(("#", "//", "*")):
                self.add(MEDIUM, "Invisible zero-width characters in code",
                         "Two names that look the same can be different, hiding a swapped function.", p, i,
                         line.encode("unicode_escape").decode()[:140])
                break
        if code:
            for i, line in enumerate(text.splitlines(), 1):
                stripped = re.sub(r"(['\"`]).*?\1|#.*$|//.*$", "", line)
                if HOMOGLYPH_RE.search(stripped):
                    self.add(MEDIUM, "Look-alike letters in names",
                             "Cyrillic or Greek letters mixed into names make a fake function look like the real one.",
                             p, i, line)
                    break

    def _code(self, p: Path, text: str, rel: str):
        soft = bool(SOFT_PATH.search(rel))
        ci_only = rel.startswith((".github/", ".gitlab-ci", ".circleci/", ".travis", "azure-pipelines"))
        lines = text.splitlines()
        minified = p.name.endswith((".min.js", ".bundle.js")) or "/dist/" in f"/{rel}" or (
            len(lines) < 20 and len(text) > 20000)
        hits: dict[str, int] = {}
        for i, line in enumerate(lines, 1):
            if len(line) > 5000 and minified:
                continue
            gap = GAP_RE.search(line) if len(line) > 160 else None
            if gap and line[:gap.start()].strip() and not minified:
                hid = line[gap.end():].strip()
                if len(hid) > 10 and re.match(r"[A-Za-z_$]", hid) and re.search(r"(?i)[A-Za-z_$][\w$.]*\s*\(|\b(import|require|eval|exec)\b", hid[:500]):
                    self.add(HIGH, "Code hidden off the right edge of the screen",
                             "Hundreds of spaces push this code out of view in editors and on GitHub. "
                             "Fake 'interview task' repos hide stealers exactly like this.", p, i, hid)
            # long lines (tables, bundles) are read in overlapping pieces so no
            # pattern can take quadratic time on them
            pieces = [line] if len(line) <= CHUNK else [line[k:k + CHUNK + 200] for k in range(0, min(len(line), 200_000), CHUNK)]
            for sev, title, why, rx in LINE_RULES:
                if title in hits and hits[title] >= 3:
                    continue
                mm = next((x for x in map(rx.search, pieces) if x), None)
                if mm:
                    if soft and sev != HIGH and title in ("Downloads a script and runs it", "Talks to a bare IP address",
                                                          "Makes itself start automatically"):
                        sev = LOW
                    if title == "Downloads a script and runs it" and line.lstrip().startswith(("#", "//")):
                        sev = LOW
                    if ci_only:
                        sev = LOW  # runs on the CI server, not on your laptop
                    hits[title] = hits.get(title, 0) + 1
                    src = mm.string
                    self.add(sev, title, why, p, i, src if mm.start() < 60 else "... " + src[mm.start() - 20:].lstrip())
        # whole-file checks
        secrets = sorted({m.group(0) for m in SECRET_RE.finditer(text)})
        if secrets:
            net = NETWORK_RE.search(text)
            if len(secrets) >= 2 and net:
                self.add(HIGH, "Reads passwords/keys/wallets and sends data out",
                         "Looks like a stealer: it touches " + ", ".join(secrets[:5]) +
                         f" and also uses the network ({net.group(0)}).", p)
            elif len(secrets) >= 3:
                self.add(MEDIUM, "Reads saved passwords, keys or wallets",
                         "It refers to " + ", ".join(secrets[:5]) + ". Fine for a password manager, odd for anything else.", p)
        n_obf = len(OBF_JS_RE.findall(text))
        if n_obf >= 25 and not minified:
            self.add(HIGH, "Scrambled JavaScript (obfuscator output)",
                     f"{n_obf} names like _0x1a2b: the tell-tale of javascript-obfuscator, used to hide what code does.", p)
        elif n_obf >= 25:
            self.add(MEDIUM, "Scrambled JavaScript in a bundled file",
                     f"{n_obf} names like _0x1a2b. Some bundles do this, so does malware.", p)
        for m in BASE64_RE.finditer(text):
            blob_line = text.count("\n", 0, m.start()) + 1
            window = text[max(0, m.start() - 400): m.end() + 400]
            if m.group(1).startswith("AGFzbQ"):  # "\0asm": compiled WebAssembly, common in bundles
                break
            if EXEC_NEAR_RE.search(window.replace(m.group(1), "")):
                self.add(HIGH, "Large encoded blob next to code that runs it",
                         f"A {len(m.group(1))}-character base64 string sits next to eval/exec/decode.", p, blob_line,
                         m.group(1)[:60])
            elif not minified and p.suffix.lower() not in (".json", ".yml", ".yaml"):
                self.add(LOW, "Large encoded blob", f"A {len(m.group(1))}-character base64 string (often an image or font).",
                         p, blob_line, m.group(1)[:60])
            break

    # ------------------------------------------------------- manifests
    def _manifests(self):
        for pj in self._find("package.json"):
            self._package_json(pj)
        for name in ("setup.py",):
            for f in self._find(name):
                self._setup_py(f)
        for f in self._find("pyproject.toml"):
            t = f.read_text(errors="replace")
            if re.search(r"backend-path\s*=", t):
                self.add(MEDIUM, "Custom build code runs on pip install",
                         "pyproject.toml uses a build backend from inside the repo, which pip runs when installing.",
                         f, 0, "backend-path")
            self.hooks.append(f"pip install: builds with {(re.search(r'build-backend\s*=\s*[\"\']([^\"\']+)', t) or [None, 'default'])[1]}")
        for f in self._find_glob("requirements*.txt"):
            self._requirements(f)
        for f in self._find("build.rs"):
            t = f.read_text(errors="replace")
            self.hooks.append(f"cargo build: runs {_rel(self.root, f)}")
            if re.search(r"Command::new|reqwest|TcpStream|ureq::|std::net", t):
                self.add(MEDIUM, "Rust build script runs programs or uses the network",
                         "build.rs runs on every cargo build, before you run anything yourself.", f)
        for f in self._find("tasks.json"):
            if f.parent.name == ".vscode":
                t = f.read_text(errors="replace")
                if re.search(r"\"runOn\"\s*:\s*\"folderOpen\"", t):
                    self.add(HIGH, "Runs a command as soon as you open the folder in VS Code",
                             "A .vscode/tasks.json task set to runOn: folderOpen. This is how fake job-interview "
                             "repos infect people. Open it in Restricted Mode or delete the file first.", f, 0,
                             re.search(r"\"command\"\s*:\s*\"[^\"]*\"", t).group(0) if re.search(r"\"command\"\s*:\s*\"[^\"]*\"", t) else "")
        for f in self._find("devcontainer.json"):
            t = f.read_text(errors="replace")
            for key in ("initializeCommand", "postCreateCommand", "postStartCommand", "onCreateCommand"):
                if key in t:
                    sev = MEDIUM if key == "initializeCommand" else LOW
                    self.add(sev, f"Dev container runs {key}",
                             "initializeCommand runs on your laptop itself, not inside the container." if sev == MEDIUM
                             else "Runs inside the dev container when it's created.", f, 0, key)
        for name in (".npmrc", ".yarnrc", ".yarnrc.yml", "pip.conf", ".pypirc"):
            for f in self._find(name):
                t = f.read_text(errors="replace")
                if re.search(r"registry|index-url|npmRegistryServer", t) and not re.search(r"registry\.npmjs\.org|pypi\.org/simple\s*$", t):
                    self.add(MEDIUM, "Changes where packages are downloaded from",
                             f"{name} points installs at another registry, so the packages may not be the real ones.", f, 0,
                             (re.search(r".*(registry|index-url|npmRegistryServer).*", t) or [""])[0])
        for f in self._find("package-lock.json"):
            self._lockfile(f)
        for f in self._find(".gitmodules"):
            for url in re.findall(r"url\s*=\s*(\S+)", f.read_text(errors="replace")):
                if not re.search(r"github\.com|gitlab\.com|bitbucket\.org|codeberg\.org|sr\.ht|^\.\./|^\./", url):
                    self.add(LOW, "Submodule from an unusual host", "Pulls more code from another server.", f, 0, url)

    def _find(self, name: str):
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            if name in filenames:
                yield Path(dirpath) / name

    def _find_glob(self, pattern: str):
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                if Path(fn).match(pattern):
                    yield Path(dirpath) / fn

    def _package_json(self, f: Path):
        try:
            data = json.loads(f.read_text(errors="replace"))
        except ValueError:
            return
        if not isinstance(data, dict):
            return
        scripts = data.get("scripts") or {}
        benign = re.compile(r"^\s*(husky( install)?|node-gyp rebuild|patch-package|tsc\b[^;&|]*|npm run build|"
                            r"ngcc|lerna bootstrap|is-ci \|\| husky install|prebuild-install( \|\| node-gyp rebuild)?|"
                            r"opencollective(-postinstall)?|echo [^;&|]*|svelte-kit sync|nuxt prepare|"
                            r"electron-builder install-app-deps|playwright install)\s*$")
        for hook in ("preinstall", "install", "postinstall", "prepare", "prepublish", "preuninstall", "postuninstall"):
            cmd = scripts.get(hook)
            if not isinstance(cmd, str):
                continue
            self.hooks.append(f"npm install: runs \"{hook}\": {cmd}")
            if re.search(r"curl|wget|https?://|eval|base64|Buffer\.from|child_process|\bsh\s+-c|powershell|"
                         r"\|\s*(ba)?sh\b|>\s*/dev/null\s*2>&1\s*&", cmd):
                self.add(HIGH, f"npm '{hook}' downloads or runs hidden code",
                         "This runs automatically the moment you type npm install.", f, 0, cmd)
            elif benign.match(cmd):
                continue
            else:
                target = re.search(r"(?:node|python3?|sh|bash)\s+(\S+\.(?:c?js|mjs|py|sh))", cmd)
                extra = ""
                if target:
                    tp = (f.parent / target.group(1)).resolve()
                    flagged = [x for x in self.findings if x.severity == HIGH and (self.root / x.file).resolve() == tp]
                    if flagged:
                        self.add(HIGH, f"npm '{hook}' runs a file that was flagged",
                                 f"{target.group(1)} runs on npm install and has: {flagged[0].what}.", f, 0, cmd)
                        continue
                    extra = f" Read {target.group(1)} before installing."
                self.add(MEDIUM if hook != "prepare" else LOW, f"npm '{hook}' script runs on install",
                         "It runs automatically with npm install." + extra, f, 0, cmd)
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            deps = data.get(section) or {}
            if not isinstance(deps, dict):
                continue
            for name, ver in deps.items():
                look = popular.lookalike(name, "npm")
                if look and not popular.is_popular(name, "npm"):
                    since = popular.first_published(name, "npm")
                    self.add(MEDIUM if since and since < popular.YEARS_AGO_2 else HIGH, "Look-alike package name",
                             f"'{name}' is one letter away from the popular '{look}'. Typosquatted packages steal data."
                             + (f" This one has existed since {since[:4]}, so it may be genuine." if since else ""),
                             f, 0, f"\"{name}\": \"{ver}\"")
                if isinstance(ver, str) and re.match(r"(https?://|git(\+\w+)?://|github:|gitlab:|bitbucket:|file:|[\w-]+/[\w.-]+(#|$))", ver):
                    if not ver.startswith("file:"):
                        self.add(LOW, "Dependency fetched from a URL or repo, not the npm registry",
                                 "It skips the registry's malware checks.", f, 0, f"\"{name}\": \"{ver}\"")

    def _setup_py(self, f: Path):
        t = f.read_text(errors="replace")
        if not re.search(r"^\s*(from|import)\s+(setuptools|distutils)", t, re.M):
            return  # a script that happens to be called setup.py, not a pip install script
        self.hooks.append(f"pip install: runs {_rel(self.root, f)}")
        risky = re.findall(r"\b(subprocess|os\.system|os\.popen|urllib|urlopen|requests\.|socket\.|exec\(|eval\(|"
                           r"b64decode|__import__|Popen|ctypes)", t)
        if risky:
            self.add(HIGH if any(r in risky for r in ("urllib", "urlopen", "requests.", "socket.", "b64decode", "exec(", "eval(")) else MEDIUM,
                     "setup.py does more than describe the package",
                     "pip runs setup.py while installing. This one uses " + ", ".join(sorted(set(risky))) + ".", f)
        if re.search(r"cmdclass\s*=", t):
            self.add(LOW, "setup.py replaces an install step (cmdclass)", "Custom code runs during pip install.", f)

    def _requirements(self, f: Path):
        for i, line in enumerate(f.read_text(errors="replace").splitlines(), 1):
            s = line.split("#")[0].strip()
            if not s:
                continue
            if re.match(r"--(extra-)?index-url|-i\s|--trusted-host|--find-links|-f\s", s):
                self.add(MEDIUM, "Installs from another package index",
                         "Packages may come from a server that isn't PyPI.", f, i, s)
                continue
            if re.match(r"(git\+|https?://|\S+ @ (https?|git))", s):
                self.add(LOW, "Dependency fetched from a URL or repo, not PyPI", "It skips PyPI's checks.", f, i, s)
                continue
            name = re.split(r"[<>=!~\[;@ ]", s, maxsplit=1)[0]
            look = popular.lookalike(name, "pypi") if name and not name.startswith("-") else None
            if look and not popular.is_popular(name, "pypi"):
                since = popular.first_published(name, "pypi")
                self.add(MEDIUM if since and since < popular.YEARS_AGO_2 else HIGH, "Look-alike package name",
                         f"'{name}' is one letter away from the popular '{look}'. Typosquatted packages steal data."
                         + (f" This one has existed since {since[:4]}, so it may be genuine." if since else ""), f, i, s)

    def _lockfile(self, f: Path):
        try:
            data = json.loads(f.read_text(errors="replace"))
        except ValueError:
            return
        odd = set()
        for name, info in (data.get("packages") or {}).items():
            r = info.get("resolved") if isinstance(info, dict) else None
            if isinstance(r, str) and r.startswith("http") and not re.match(r"https://registry\.(npmjs\.org|yarnpkg\.com)/", r):
                odd.add(r.split("/")[2])
        if odd:
            self.add(MEDIUM, "Lockfile downloads packages from other servers",
                     "package-lock.json fetches from " + ", ".join(sorted(odd)[:4]) + ".", f)

    # ------------------------------------------------------------ result
    def counts(self) -> dict:
        c = {HIGH: 0, MEDIUM: 0, LOW: 0}
        for x in self.findings:
            c[x.severity] += 1
        return c

    def verdict(self) -> str:
        c = self.counts()
        if c[HIGH]:
            return "danger"
        if c[MEDIUM]:
            return "review"
        return "clean"

    def to_json(self) -> dict:
        return {"root": str(self.root), "files": self.files, "truncated": self.truncated, "verdict": self.verdict(),
                "counts": self.counts(), "hooks": self.hooks, "findings": [asdict(f) for f in self.findings]}


def _clamd_running() -> bool:
    return any(os.path.exists(p) for p in ("/run/clamav/clamd.ctl", "/var/run/clamav/clamd.ctl",
                                           "/run/clamd.scan/clamd.sock"))


def clamav(root: Path, slow_ok: bool = False) -> list[Finding]:
    """Optional ClamAV signatures. clamscan spends ~15 s loading its database
    on every run, so quick checks (clone, install) only use the clamd service,
    which keeps it loaded; the weekly sweep may use clamscan."""
    exe = shutil.which("clamdscan") if _clamd_running() else None
    if not exe and slow_ok:
        exe = shutil.which("clamscan")
    if not exe:
        return []
    args = [exe, "--infected", "--no-summary"]
    if exe.endswith("clamscan"):
        args += ["-r", "--exclude-dir=^" + re.escape(str(root / ".git"))]
    else:
        args += ["--fdpass", "-m"]
    try:
        out = subprocess.run(args + [str(root)], capture_output=True, text=True, timeout=600).stdout
    except (OSError, subprocess.TimeoutExpired):
        return []
    res = []
    for line in out.splitlines():
        if line.endswith(" FOUND"):
            path, sig = line[:-6].rsplit(": ", 1)
            res.append(Finding(HIGH, f"Known malware (ClamAV: {sig})", "Matches an antivirus signature.",
                               _rel(root, Path(path))))
    return res
