"""CycloneDX 1.6 JSON SBOM writer and reader."""
from __future__ import annotations

import datetime as dt
import json
import uuid
from typing import Dict, List, Optional

from . import __version__


def build_sbom(components: List[Dict], product: str, product_version: Optional[str] = None,
               supplier: Optional[str] = None) -> Dict:
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    meta_comp = {"type": "application", "name": product, "bom-ref": "product"}
    if product_version:
        meta_comp["version"] = product_version
    if supplier:
        meta_comp["supplier"] = {"name": supplier}
    comps = []
    for c in components:
        item = {
            "type": "library",
            "bom-ref": c["purl"],
            "name": c["name"],
            "purl": c["purl"],
        }
        if c.get("version"):
            item["version"] = c["version"]
        props = [{"name": "cra-scan:ecosystem", "value": c["ecosystem"]},
                 {"name": "cra-scan:lockfile", "value": c["lockfile"]}]
        if c.get("revision"):
            props.append({"name": "cra-scan:revision", "value": c["revision"]})
        if c.get("branch"):
            props.append({"name": "cra-scan:branch", "value": c["branch"]})
        if c.get("source_url"):
            item["externalReferences"] = [{"type": "vcs", "url": "https://" + c["source_url"]}]
        item["properties"] = props
        comps.append(item)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": {"components": [{"type": "application", "name": "cra-scan", "version": __version__}]},
            "component": meta_comp,
        },
        "components": comps,
        "dependencies": [{"ref": "product", "dependsOn": [c["bom-ref"] for c in comps]}],
    }


def components_from_sbom(path: str) -> List[Dict]:
    """Read a CycloneDX SBOM (ours or another tool's) back into component dicts."""
    with open(path, encoding="utf-8") as f:
        bom = json.load(f)
    out = []
    for c in bom.get("components", []):
        purl = c.get("purl") or ""
        props = {p.get("name"): p.get("value") for p in c.get("properties", [])}
        eco, src = None, None
        if purl.startswith("pkg:swift/"):
            eco = "SwiftURL"
            src = purl[len("pkg:swift/"):].split("@")[0]
        elif purl.startswith("pkg:cocoapods/"):
            eco = "CocoaPods"
        out.append({
            "name": c.get("name"), "version": c.get("version"),
            "revision": props.get("cra-scan:revision"), "branch": props.get("cra-scan:branch"),
            "ecosystem": eco or props.get("cra-scan:ecosystem") or "unknown",
            "source_url": src, "purl": purl, "lockfile": props.get("cra-scan:lockfile", path),
        })
    return out
