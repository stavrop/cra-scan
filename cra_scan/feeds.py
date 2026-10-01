"""Vulnerability data sources, all public and free:

  * OSV.dev            — advisories matched to SwiftURL packages (GitHub advisory database)
  * CISA KEV           — known exploited vulnerabilities (CVE ids)
  * ENISA EUVD         — EU vulnerability database, exploited flag (CVE/GHSA aliases)
  * FIRST EPSS         — probability of exploitation in the next 30 days
  * CocoaPods CDN      — podspecs, to map each pod to its source repository
  * NVD (CPE match)    — CVEs for CocoaPods pods, matched by product name and version

KEV and EUVD lists are cached on disk (default 12 h) so CI runs stay fast. Podspecs are cached
for 30 days and NVD answers for 24 h. Set NVD_API_KEY to raise NVD's rate limit (5 → 50 requests / 30 s).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
import urllib.error
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
POD_CDN = "https://cdn.cocoapods.org/Specs/"
NVD_CVES = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def cache_dir() -> str:
    d = os.environ.get("CRA_SCAN_CACHE") or os.path.join(os.path.expanduser("~"), ".cache", "cra-scan")
    os.makedirs(d, exist_ok=True)
    return d


def _http(url: str, data: Optional[dict] = None, timeout: int = 30, headers: Optional[dict] = None):
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, headers={"User-Agent": UA, "Accept": "application/json",
                                                          **({"Content-Type": "application/json"} if body else {}),
                                                          **(headers or {})})
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
    """Return {purl: [vuln ids]} for components OSV can match: Swift packages, and pods whose
    source repository is known (a pod and a Swift package often share a GitHub repo and tags)."""
    queries, purls = [], []
    for c in components:
        if c["ecosystem"] not in ("SwiftURL", "CocoaPods") or not c.get("source_url"):
            continue
        if c.get("version"):
            q = {"package": {"ecosystem": "SwiftURL", "name": c["source_url"]}, "version": c["version"]}
        elif c.get("revision") and c["ecosystem"] == "SwiftURL":
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


# --------------------------------------------------------------------------- CocoaPods
def pod_spec(name: str, version: str) -> Dict:
    """Podspec JSON from the CocoaPods CDN ({} if unavailable). Sharded by md5 of the pod name."""
    h = hashlib.md5(name.encode("utf-8")).hexdigest()
    url = f"{POD_CDN}{h[0]}/{h[1]}/{h[2]}/{urllib.parse.quote(name)}/{urllib.parse.quote(version)}/{urllib.parse.quote(name)}.podspec.json"

    def load():
        try:
            return _http(url, timeout=20)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {}
            raise
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", f"{name}@{version}")
    return _cached(f"pod-{safe}.json", 24 * 30, load)


# --------------------------------------------------------------------------- NVD
_last_nvd = [0.0]


def nvd_by_cpe(product: str, version: str) -> List[Dict]:
    """CVEs whose NVD configuration matches cpe:2.3:a:*:<product>:<version> (range-aware)."""
    key = os.environ.get("NVD_API_KEY") or os.environ.get("CRA_SCAN_NVD_API_KEY")

    def load():
        gap = 0.7 if key else 6.5          # NVD public limits: 5 req/30 s without a key, 50 with one
        wait = _last_nvd[0] + gap - time.time()
        if wait > 0:
            time.sleep(wait)
        cpe = f"cpe:2.3:a:*:{product}:{version}"
        q = urllib.parse.urlencode({"virtualMatchString": cpe, "resultsPerPage": 200})
        try:
            d = _http(f"{NVD_CVES}?{q}", timeout=60, headers={"apiKey": key} if key else None)
        finally:
            _last_nvd[0] = time.time()
        out = []
        for v in d.get("vulnerabilities", []):
            c = v.get("cve", {})
            out.append({
                "id": c.get("id"),
                "summary": next((x["value"] for x in c.get("descriptions", []) if x.get("lang") == "en"), ""),
                "cvss": _nvd_score(c.get("metrics", {})),
                "matches": [m for conf in c.get("configurations", []) for n in conf.get("nodes", [])
                            for m in n.get("cpeMatch", []) if m.get("vulnerable")
                            and m.get("criteria", "").split(":")[4:5] == [product]],
            })
        return out
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", f"{product}@{version}")
    return _cached(f"nvd-{safe}.json", 24, load)


def _nvd_score(metrics: Dict):
    for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        for m in metrics.get(k, []):
            s = m.get("cvssData", {}).get("baseScore")
            if s is not None:
                return float(s)
    return None


def progress(msg: str):
    if sys.stderr.isatty() or os.environ.get("CRA_SCAN_VERBOSE"):
        print(msg, file=sys.stderr, flush=True)
