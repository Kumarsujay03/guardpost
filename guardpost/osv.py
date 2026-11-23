"""Known-bad lookups in OSV (osv.dev): malicious packages (MAL-* ids) and
known vulnerabilities for npm, PyPI, crates.io, Go and Ubuntu packages.

OSV is updated continuously, so every check uses the latest data. Only
package names and versions are sent. Details are cached for a day.
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

API = "https://api.osv.dev/v1"
CACHE = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "guardpost" / "osv"
ECOSYSTEM = {"npm": "npm", "pypi": "PyPI", "cargo": "crates.io", "go": "Go"}


@dataclass
class Hit:
    ecosystem: str
    name: str
    version: str
    ids: list = field(default_factory=list)
    malicious: list = field(default_factory=list)   # MAL-* ids
    details: dict = field(default_factory=dict)     # id -> {summary, severity, fixed, aliases}


def _post(path: str, body: dict, timeout: int = 30) -> dict:
    req = urllib.request.Request(f"{API}/{path}", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json", "User-Agent": "guardpost"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def _get_vuln(vid: str) -> dict:
    CACHE.mkdir(parents=True, exist_ok=True)
    cp = CACHE / (re.sub(r"[^\w.-]", "_", vid) + ".json")
    try:
        if time.time() - cp.stat().st_mtime < 86400:
            return json.loads(cp.read_text())
    except (OSError, ValueError):
        pass
    try:
        req = urllib.request.Request(f"{API}/vulns/{vid}", headers={"User-Agent": "guardpost"})
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.load(r)
        cp.write_text(json.dumps(data))
        return data
    except Exception:
        return {}


def _severity(v: dict) -> str:
    sev = (v.get("database_specific") or {}).get("severity")
    if isinstance(sev, str):
        return sev.lower()
    for a in v.get("affected", []):
        s = (a.get("ecosystem_specific") or {}).get("severity") or (a.get("database_specific") or {}).get("severity")
        if isinstance(s, str):
            return s.lower()
    for s in v.get("severity", []):
        m = re.search(r"/AV:(\w)", s.get("score", ""))
        if s.get("type", "").startswith("CVSS") and m:
            return "unknown"
    return "unknown"


def _fixed(v: dict, name: str) -> str:
    fixes = []
    for a in v.get("affected", []):
        if (a.get("package") or {}).get("name", "").lower() != name.lower():
            continue
        for r in a.get("ranges", []):
            for e in r.get("events", []):
                if "fixed" in e:
                    fixes.append(e["fixed"])
    return ", ".join(sorted(set(fixes))[-2:])


def query(packages: list[tuple[str, str, str]], details: bool = True, detail_limit: int = 300) -> list[Hit]:
    """packages: (ecosystem key or OSV ecosystem, name, version). Returns only packages with hits.
    Raises OSError-like exceptions when offline; callers decide what to do."""
    pk = []
    for eco, name, ver in packages:
        e = ECOSYSTEM.get(eco, eco)
        q = {"package": {"name": name, "ecosystem": e}}
        if ver:
            q["version"] = ver
        pk.append(((e, name, ver), q))
    hits: list[Hit] = []
    for i in range(0, len(pk), 1000):
        chunk = pk[i:i + 1000]
        res = _post("querybatch", {"queries": [q for _, q in chunk]}, timeout=60)
        for (key, _), r in zip(chunk, res.get("results", [])):
            ids = [v["id"] for v in r.get("vulns", []) or []]
            if ids:
                hits.append(Hit(key[0], key[1], key[2], ids, [x for x in ids if x.startswith("MAL-")]))
    if details:
        wanted = []
        for h in hits:
            wanted += h.ids
        wanted = list(dict.fromkeys(wanted))[:detail_limit]
        with ThreadPoolExecutor(8) as ex:
            got = dict(zip(wanted, ex.map(_get_vuln, wanted)))
        for h in hits:
            for vid in h.ids:
                v = got.get(vid)
                if not v:
                    continue
                if v.get("withdrawn"):
                    continue
                summary = (v.get("summary") or v.get("details") or "")
                cwes = (v.get("database_specific") or {}).get("cwe_ids") or []
                # hijacked packages are published as normal advisories, not MAL-*
                if vid not in h.malicious and ("CWE-506" in cwes or re.search(
                        r"(?i)\b(embedded malicious code|embedded malware|malicious code in|contains malware|"
                        r"compromised (package|version|release))", summary)):
                    h.malicious.append(vid)
                h.details[vid] = {"summary": summary[:160].replace("\n", " "),
                                  "severity": _severity(v), "fixed": _fixed(v, h.name),
                                  "aliases": [a for a in v.get("aliases", []) + v.get("upstream", []) if a.startswith("CVE-")]}
            # an OSV id that turned into "withdrawn" isn't a hit any more
            if h.details:
                h.ids = [x for x in h.ids if x in h.details or x not in got]
                h.malicious = [x for x in h.malicious if x in h.ids]
    return [h for h in hits if h.ids]


def malicious_by_name(packages: list[tuple[str, str]]) -> dict:
    """Name-only check (version not known yet): {name: [MAL ids]}."""
    hits = query([(e, n, "") for e, n in packages], details=False)
    return {h.name: h.malicious for h in hits if h.malicious}
