"""Threat feeds kept on disk and refreshed weekly by `guardpost update`.

- CISA KEV: vulnerabilities attackers are exploiting right now.
- abuse.ch Feodo Tracker and SSLBL: IPs of live botnet/malware command servers.
- Elastic protections-artifacts YARA rules for Linux malware (only when the
  `yara` command is installed).
ClamAV keeps its own signatures fresh through the clamav-freshclam service.
"""
from __future__ import annotations

import io
import json
import os
import shutil
import tarfile
import time
import urllib.request
from pathlib import Path

DIR = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")) / "guardpost" / "feeds"
FEEDS = {
    "kev.json": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "feodo-ips.json": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
    "sslbl-ips.txt": "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
    # IPs reported by at least 4 public blocklists (stamparm/ipsum, updated daily)
    "ipsum4.txt": "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/4.txt",
}
YARA_URL = "https://github.com/elastic/protections-artifacts/archive/refs/heads/main.tar.gz"


def _fetch(url: str, timeout: int = 120) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "guardpost"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def update(verbose: bool = True) -> list[str]:
    DIR.mkdir(parents=True, exist_ok=True)
    msgs = []
    for name, url in FEEDS.items():
        try:
            data = _fetch(url)
            if name.endswith(".json"):
                json.loads(data)
            (DIR / (name + ".new")).write_bytes(data)
            os.replace(DIR / (name + ".new"), DIR / name)
            msgs.append(f"ok    {name} ({len(data) // 1024} KB)")
        except Exception as e:
            msgs.append(f"FAIL  {name}: {e} (keeping the old copy)")
    if shutil.which("yara"):
        try:
            data = _fetch(YARA_URL, timeout=300)
            out = DIR / "yara.new"
            shutil.rmtree(out, ignore_errors=True)
            out.mkdir()
            n = 0
            with tarfile.open(fileobj=io.BytesIO(data)) as t:
                for m in t.getmembers():
                    base = os.path.basename(m.name)
                    if m.isfile() and "/yara/rules/" in m.name and base.startswith(("Linux_", "Multi_")) and base.endswith(".yar"):
                        f = t.extractfile(m)
                        if f:
                            (out / base).write_bytes(f.read())
                            n += 1
            shutil.rmtree(DIR / "yara", ignore_errors=True)
            out.rename(DIR / "yara")
            msgs.append(f"ok    YARA rules for Linux ({n} files, Elastic)")
        except Exception as e:
            msgs.append(f"FAIL  YARA rules: {e} (keeping the old copy)")
    else:
        msgs.append("skip  YARA rules (install the 'yara' package to use them)")
    if shutil.which("freshclam"):
        msgs.append("ok    ClamAV updates itself (clamav-freshclam service)")
    else:
        msgs.append("skip  ClamAV (install 'clamav' for antivirus signatures)")
    (DIR / "updated").write_text(str(time.time()))
    if verbose:
        print("\n".join(msgs))
    return msgs


def age_days() -> float | None:
    try:
        return (time.time() - float((DIR / "updated").read_text())) / 86400
    except (OSError, ValueError):
        return None


def kev() -> dict:
    """CVE id -> {name, date, ransomware}"""
    try:
        data = json.loads((DIR / "kev.json").read_text())
    except (OSError, ValueError):
        return {}
    return {v["cveID"]: {"name": f"{v.get('vendorProject', '')} {v.get('product', '')}".strip(),
                         "date": v.get("dateAdded", ""),
                         "ransomware": v.get("knownRansomwareCampaignUse") == "Known"}
            for v in data.get("vulnerabilities", [])}


def bad_ips() -> dict:
    """IP -> what it is"""
    ips = {}
    try:
        for e in json.loads((DIR / "feodo-ips.json").read_text()):
            ips[e["ip_address"]] = f"botnet command server ({e.get('malware', '?')}, Feodo Tracker)"
    except (OSError, ValueError, TypeError, KeyError):
        pass
    try:
        for line in (DIR / "sslbl-ips.txt").read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                ips.setdefault(line.split(",")[0], "malware command server (abuse.ch SSLBL)")
    except OSError:
        pass
    return ips


def suspicious_ips() -> set:
    """IPs on several blocklists: attackers and scanners, a weaker signal."""
    try:
        return {l.strip() for l in (DIR / "ipsum4.txt").read_text().splitlines() if l.strip() and not l.startswith("#")}
    except OSError:
        return set()


def yara_dir() -> Path | None:
    d = DIR / "yara"
    return d if d.is_dir() and any(d.glob("*.yar")) else None
