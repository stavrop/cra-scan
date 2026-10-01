"""Vulnerability data sources, all public and free:

  * OSV.dev            — advisories matched to SwiftURL packages (GitHub advisory database)
  * CISA KEV           — known exploited vulnerabilities (CVE ids)
  * ENISA EUVD         — EU vulnerability database, exploited flag (CVE/GHSA aliases)
  * FIRST EPSS         — probability of exploitation in the next 30 days

KEV and EUVD lists are cached on disk (default 12 h) so CI runs stay fast.
"""
from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.request
from typing import Dict, Iterable, List, Optional, Set

from . import __version__

UA = f"cra-scan/{__version__} (+https://github.com/stavrop/cra-scan)"
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EUVD_SEARCH = "https://euvdservices.enisa.europa.eu/api/search"
EPSS_URL = "https://api.first.org/data/v1/epss"


def cache_dir() -> str:
    d = os.environ.get("CRA_SCAN_CACHE") or os.path.join(os.path.expanduser("~"), ".cache", "cra-scan")
    os.makedirs(d, exist_ok=True)
    return d


def _http(url: str, data: Optional[dict] = None, timeout: int = 30):
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, headers={"User-Agent": UA, "Accept": "application/json",
                                                          **({"Content-Type": "application/json"} if body else {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def _cached(name: str, max_age_h: float, loader):
    path = os.path.join(cache_dir(), name)
    if os.path.exists(path) and time.time() - os.path.getmtime(path) < max_age_h * 3600:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    data = loader()
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f)
    os.replace(tmp, path)
    return data


# --------------------------------------------------------------------------- OSV
def osv_query(components: List[Dict]) -> Dict[str, List[str]]:
    """Return {purl: [vuln ids]} for components OSV can match (SwiftURL today)."""
    queries, purls = [], []
    for c in components:
        if c["ecosystem"] != "SwiftURL" or not c.get("source_url"):
            continue
        if c.get("version"):
            q = {"package": {"ecosystem": "SwiftURL", "name": c["source_url"]}, "version": c["version"]}
        elif c.get("revision"):
            q = {"commit": c["revision"]}
        else:
            continue
        queries.append(q)
        purls.append(c["purl"])
    result: Dict[str, List[str]] = {}
    for i in range(0, len(queries), 500):
        resp = _http(OSV_BATCH, {"queries": queries[i:i + 500]})
        for purl, r in zip(purls[i:i + 500], resp.get("results", [])):
            ids = [v["id"] for v in r.get("vulns", [])]
            if ids:
                result[purl] = ids
    return result


def osv_details(vuln_id: str) -> Dict:
    def load():
        return _http(OSV_VULN + urllib.parse.quote(vuln_id))
    return _cached(f"osv-{vuln_id}.json", 24, load)


# --------------------------------------------------------------------------- KEV / EUVD
def kev_cves(max_age_h: float = 12) -> Set[str]:
    data = _cached("kev.json", max_age_h, lambda: _http(KEV_URL, timeout=60))
    return {v["cveID"] for v in data.get("vulnerabilities", [])}


def euvd_exploited(max_age_h: float = 12) -> Dict[str, str]:
    """{alias (CVE/GHSA) -> EUVD id} for vulnerabilities ENISA marks as exploited."""
    def load():
        out, page = {}, 0
        while True:
            q = urllib.parse.urlencode({"exploited": "true", "size": 100, "page": page})
            d = _http(f"{EUVD_SEARCH}?{q}", timeout=60)
            items = d.get("items", [])
            for it in items:
                for a in (it.get("aliases") or "").split():
                    out[a.strip()] = it.get("id")
            page += 1
            if not items or page * 100 >= int(d.get("total", 0)) or page > 200:
                break
        return out
    return _cached("euvd-exploited.json", max_age_h, load)


def epss(cves: Iterable[str]) -> Dict[str, float]:
    cves = sorted(set(c for c in cves if c.startswith("CVE-")))
    out: Dict[str, float] = {}
    for i in range(0, len(cves), 100):
        q = urllib.parse.urlencode({"cve": ",".join(cves[i:i + 100])})
        d = _http(f"{EPSS_URL}?{q}")
        for row in d.get("data", []):
            out[row["cve"]] = float(row["epss"])
    return out
