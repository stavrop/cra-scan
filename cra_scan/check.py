"""Match components against vulnerability feeds and classify the findings.

Levels (highest first):
  exploited  — listed as actively exploited by CISA KEV or ENISA EUVD.
               If your product is actually affected, this is what triggers the CRA
               Art. 14 reporting clock (24h early warning / 72h notification).
  high       — EPSS >= 0.10 (10% chance of exploitation in 30 days) or CVSS >= 9.0
  known      — any other published advisory for the pinned version

CocoaPods pods have no advisory feed of their own. cra-scan maps each pod to its source repo via its
podspec (then checks OSV as for Swift packages) and asks NVD for CVEs whose CPE names the pod. A CVE
matched only by product name (the CPE vendor is not the pod's GitHub owner) is reported with
"verify": true and capped at "known", so a name collision never fails a build.
"""
from __future__ import annotations

import re
from typing import Dict, List

from . import feeds, lockfiles

LEVELS = ["none", "known", "high", "exploited"]


def _cvss_score(vector: str):
    """Rough CVSS v3 base score from a vector (enough to flag criticals)."""
    m = dict(p.split(":", 1) for p in vector.split("/")[1:] if ":" in p)
    try:
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
        ac = {"L": 0.77, "H": 0.44}[m["AC"]]
        scope_changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[m["PR"]]
        ui = {"N": 0.85, "R": 0.62}[m["UI"]]
        cia = [{"H": 0.56, "L": 0.22, "N": 0.0}[m[k]] for k in ("C", "I", "A")]
    except KeyError:
        return None
    iss = 1 - (1 - cia[0]) * (1 - cia[1]) * (1 - cia[2])
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
    if impact <= 0:
        return 0.0
    expl = 8.22 * av * ac * pr * ui
    base = min(1.08 * (impact + expl), 10) if scope_changed else min(impact + expl, 10)
    return round(-(-base * 10 // 1) / 10, 1)  # round up to one decimal


def _fixed_versions(osv: Dict) -> List[str]:
    out = []
    for aff in osv.get("affected", []):
        for rng in aff.get("ranges", []):
            for ev in rng.get("events", []):
                if "fixed" in ev and ev["fixed"] not in out:
                    out.append(ev["fixed"])
    return out


def _vkey(v: str):
    return [int(x) if x.isdigit() else 0 for x in re.split(r"[.+-]", v or "0")[:4]]


def _next_fix(current, fixed: List[str]):
    """Lowest fixed version above the pinned one (fix lists span several release branches)."""
    if not current:
        return fixed[:1]
    above = [f for f in fixed if _vkey(f) > _vkey(current)]
    return [min(above, key=_vkey)] if above else []


_REPO_HOSTS = ("github.com/", "gitlab.com/", "bitbucket.org/")


def resolve_pods(components: List[Dict]) -> int:
    """Fill source_url for CocoaPods components from their podspecs. Returns how many were resolved."""
    n = 0
    for c in components:
        if c["ecosystem"] != "CocoaPods" or c.get("source_url") or not c.get("version"):
            continue
        spec = feeds.pod_spec(c["name"], c["version"])
        src = spec.get("source") or {}
        for cand in (src.get("git"), spec.get("homepage")):
            u = lockfiles.normalise_git_url(cand) if cand else ""
            if u.count("/") < 2:
                continue
            c.setdefault("repo", u)                     # any host: used to recognise the CPE vendor
            if u.startswith(_REPO_HOSTS) and u.count("/") == 2:
                c["source_url"] = u                     # GitHub-style: also queried in OSV
                n += 1
                break
    return n


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def _pod_products(c: Dict) -> List[str]:
    names = {c["name"].lower()}
    for u in (c.get("source_url"), c.get("repo")):
        if u:
            names.add(u.rstrip("/").rsplit("/", 1)[-1].lower())
    out = set()
    for n in names:
        out.add(n)
        out.add(n.replace("-", "_"))
    return sorted(x for x in out if re.fullmatch(r"[a-z0-9._-]+", x))


def _nvd_findings(c: Dict, known_cves: set) -> List[Dict]:
    trusted = set()
    for base in {c["name"]} | {u.rstrip("/").rsplit("/", 1)[-1] for u in (c.get("source_url"), c.get("repo")) if u}:
        trusted |= {_norm(base), _norm(base) + "project"}
    for u in (c.get("source_url"), c.get("repo")):
        parts = (u or "").split("/")
        if len(parts) >= 3:          # owner / organisation in the repo path, e.g. webm in .../webm/libwebp
            trusted |= {_norm(parts[-2]), _norm(parts[-2]) + "project"}
    trusted -= {"", "project"}
    out, seen = [], set()
    for product in _pod_products(c):
        for cve in feeds.nvd_by_cpe(product, c["version"]):
            if not cve["id"] or cve["id"] in seen or cve["id"] in known_cves:
                continue
            seen.add(cve["id"])
            vendors = {m["criteria"].split(":")[3] for m in cve["matches"] if m.get("criteria")}
            fixed = sorted({m["versionEndExcluding"] for m in cve["matches"] if m.get("versionEndExcluding")}, key=_vkey)
            out.append({
                "purl": c["purl"], "component": c["name"], "version": c["version"],
                "id": cve["id"], "aliases": [], "cves": [cve["id"]],
                "summary": (cve["summary"] or "")[:160], "cvss": cve["cvss"],
                "fixed": _next_fix(c["version"], fixed),
                "source": "nvd-cpe", "cpe_vendor": ", ".join(sorted(vendors)),
                "verify": not any(_norm(v) in trusted for v in vendors),
                "url": f"https://nvd.nist.gov/vuln/detail/{cve['id']}",
            })
    return out


def check(components: List[Dict], use_epss: bool = True, use_nvd: bool = True) -> Dict:
    pods = [c for c in components if c["ecosystem"] == "CocoaPods" and c.get("version")]
    if pods:
        feeds.progress(f"cra-scan: resolving {len(pods)} pod(s) to their source repositories…")
        resolve_pods(pods)
    matches = feeds.osv_query(components)
    by_purl = {c["purl"]: c for c in components}

    findings = []
    all_cves = set()
    for purl, ids in matches.items():
        for vid in ids:
            d = feeds.osv_details(vid)
            aliases = [vid] + list(d.get("aliases", []))
            cves = [a for a in aliases if a.startswith("CVE-")]
            all_cves.update(cves)
            score = None
            for s in d.get("severity", []):
                if s.get("type", "").startswith("CVSS_V3"):
                    score = _cvss_score(s.get("score", ""))
            findings.append({
                "purl": purl,
                "component": by_purl[purl]["name"],
                "version": by_purl[purl].get("version") or (by_purl[purl].get("revision") or "")[:12],
                "id": vid,
                "aliases": aliases[1:],
                "cves": cves,
                "summary": d.get("summary") or (d.get("details") or "")[:160],
                "cvss": score,
                "fixed": _next_fix(by_purl[purl].get("version"), _fixed_versions(d)),
                "source": "osv", "verify": False,
                "url": f"https://osv.dev/vulnerability/{vid}",
            })

    if use_nvd and pods:
        feeds.progress(f"cra-scan: checking {len(pods)} pod(s) against NVD (cached for 24 h; set NVD_API_KEY to go faster)…")
        for c in pods:
            known = {cve for f in findings if f["purl"] == c["purl"] for cve in f["cves"]}
            for f in _nvd_findings(c, known):
                findings.append(f)
                all_cves.update(f["cves"])

    kev = feeds.kev_cves() if findings else set()
    euvd = feeds.euvd_exploited() if findings else {}
    for f in findings:
        f["kev"] = any(c in kev for c in f["cves"])
        f["euvd"] = next((euvd[a] for a in [f["id"]] + f["aliases"] if a in euvd), None)

    scores = feeds.epss(all_cves) if (use_epss and all_cves) else {}
    for f in findings:
        f["epss"] = max((scores.get(c, 0.0) for c in f["cves"]), default=None) if f["cves"] else None
        if f["verify"]:
            f["level"] = "known"          # name-only CPE match: report, never fail the build on it
        elif f["kev"] or f["euvd"]:
            f["level"] = "exploited"
        elif (f["epss"] or 0) >= 0.10 or (f["cvss"] or 0) >= 9.0:
            f["level"] = "high"
        else:
            f["level"] = "known"
    findings.sort(key=lambda f: (-LEVELS.index(f["level"]), -(f["epss"] or 0), f["component"]))

    def checked(c):
        if c["ecosystem"] == "SwiftURL":
            return bool(c.get("version") or c.get("revision"))
        if c["ecosystem"] == "CocoaPods":
            return bool(c.get("version")) and (use_nvd or bool(c.get("source_url")))
        return False
    return {
        "components": len(components),
        "checked": sum(1 for c in components if checked(c)),
        "not_checked": [c["purl"] for c in components if not checked(c)],
        "findings": findings,
        "worst": findings[0]["level"] if findings else "none",
    }


def to_markdown(report: Dict, product: str) -> str:
    lines = [f"# cra-scan report — {product}", "",
             f"{report['components']} components, {report['checked']} checked; worst level: **{report['worst']}**.", ""]
    if report["findings"]:
        lines += ["| Level | Component | Version | Advisory | CVE | EPSS | Fixed in |", "|---|---|---|---|---|---|---|"]
        for f in report["findings"]:
            ep = f"{f['epss']:.3f}" if f["epss"] is not None else ""
            lvl = f["level"] + (" (verify)" if f.get("verify") else "")
            lines.append(f"| {lvl} | {f['component']} | {f['version']} | [{f['id']}]({f['url']}) | {', '.join(f['cves'])} | {ep} | {', '.join(f['fixed'])} |")
        lines.append("")
        if any(f.get("verify") for f in report["findings"]):
            lines += ["(verify) = matched in NVD by product name only; check the CVE really concerns this pod.", ""]
    if report["worst"] == "exploited":
        lines += ["> **Actively exploited vulnerability in a dependency.** If it is exploitable in your product, the CRA",
                  "> Art. 14 clock is running: early warning to ENISA's Single Reporting Platform within 24 hours of awareness,",
                  "> notification within 72 hours, final report within 14 days of a fix. Record the time you became aware.", ""]
    if report["not_checked"]:
        lines += [f"Not checked (no version or no advisory source): {len(report['not_checked'])} component(s).", ""]
    return "\n".join(lines)
