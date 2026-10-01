"""Match components against vulnerability feeds and classify the findings.

Levels (highest first):
  exploited  — listed as actively exploited by CISA KEV or ENISA EUVD.
               If your product is actually affected, this is what triggers the CRA
               Art. 14 reporting clock (24h early warning / 72h notification).
  high       — EPSS >= 0.10 (10% chance of exploitation in 30 days) or CVSS >= 9.0
  known      — any other published advisory for the pinned version
"""
from __future__ import annotations

import re
from typing import Dict, List

from . import feeds

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


def check(components: List[Dict], use_epss: bool = True) -> Dict:
    matches = feeds.osv_query(components)
    kev = feeds.kev_cves() if matches else set()
    euvd = feeds.euvd_exploited() if matches else {}
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
                "kev": any(c in kev for c in cves),
                "euvd": next((euvd[a] for a in aliases if a in euvd), None),
                "url": f"https://osv.dev/vulnerability/{vid}",
            })

    scores = feeds.epss(all_cves) if (use_epss and all_cves) else {}
    for f in findings:
        f["epss"] = max((scores.get(c, 0.0) for c in f["cves"]), default=None) if f["cves"] else None
        if f["kev"] or f["euvd"]:
            f["level"] = "exploited"
        elif (f["epss"] or 0) >= 0.10 or (f["cvss"] or 0) >= 9.0:
            f["level"] = "high"
        else:
            f["level"] = "known"
    findings.sort(key=lambda f: (-LEVELS.index(f["level"]), -(f["epss"] or 0), f["component"]))

    covered = sum(1 for c in components if c["ecosystem"] == "SwiftURL" and (c.get("version") or c.get("revision")))
    return {
        "components": len(components),
        "checked": covered,
        "not_checked": [c["purl"] for c in components if c["ecosystem"] != "SwiftURL"],
        "findings": findings,
        "worst": findings[0]["level"] if findings else "none",
    }


def to_markdown(report: Dict, product: str) -> str:
    lines = [f"# cra-scan report — {product}", "",
             f"{report['components']} components, {report['checked']} checked against OSV; worst level: **{report['worst']}**.", ""]
    if report["findings"]:
        lines += ["| Level | Component | Version | Advisory | CVE | EPSS | Fixed in |", "|---|---|---|---|---|---|---|"]
        for f in report["findings"]:
            ep = f"{f['epss']:.3f}" if f["epss"] is not None else ""
            lines.append(f"| {f['level']} | {f['component']} | {f['version']} | [{f['id']}]({f['url']}) | {', '.join(f['cves'])} | {ep} | {', '.join(f['fixed'])} |")
        lines.append("")
    if report["worst"] == "exploited":
        lines += ["> **Actively exploited vulnerability in a dependency.** If it is exploitable in your product, the CRA",
                  "> Art. 14 clock is running: early warning to ENISA's Single Reporting Platform within 24 hours of awareness,",
                  "> notification within 72 hours, final report within 14 days of a fix. Record the time you became aware.", ""]
    if report["not_checked"]:
        lines += [f"Not checked (no public advisory feed for this ecosystem yet): {len(report['not_checked'])} component(s).", ""]
    return "\n".join(lines)
