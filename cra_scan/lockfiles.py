"""Parse Apple-ecosystem dependency lockfiles into a flat component list.

Supported:
  * Swift Package Manager ``Package.resolved`` — format versions 1, 2 and 3
  * CocoaPods ``Podfile.lock``

Each component is a dict:
  {name, version, revision, ecosystem, source_url, purl, lockfile}
"""
from __future__ import annotations

import json
import os
import re
from typing import Dict, Iterable, List, Optional

SKIP_DIRS = {".build", "build", "DerivedData", "Pods", "SourcePackages", "checkouts", ".git", "node_modules", "Carthage"}


def normalise_git_url(url: str) -> str:
    """https://github.com/Apple/swift-nio.git -> github.com/apple/swift-nio (OSV SwiftURL form)."""
    u = (url or "").strip()
    u = re.sub(r"^git@([^:]+):", r"https://\1/", u)          # scp-style ssh
    u = re.sub(r"^[a-z+]+://", "", u)                         # scheme
    u = re.sub(r"^[^@/]+@", "", u)                            # user@
    u = u.rstrip("/")
    if u.endswith(".git"):
        u = u[:-4]
    host, _, path = u.partition("/")
    return f"{host.lower()}/{path}".rstrip("/") if path else host.lower()


def swift_purl(source: str, version: Optional[str], revision: Optional[str]) -> str:
    ns, _, name = source.rpartition("/")
    v = version or revision or ""
    return f"pkg:swift/{ns}/{name}" + (f"@{v}" if v else "")


def parse_package_resolved(path: str) -> List[Dict]:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    fmt = data.get("version", 1)
    pins = data.get("object", {}).get("pins", []) if fmt == 1 else data.get("pins", [])
    out = []
    for p in pins:
        url = p.get("repositoryURL") if fmt == 1 else p.get("location")
        name = p.get("package") if fmt == 1 else p.get("identity")
        if fmt != 1 and p.get("kind") not in (None, "remoteSourceControl"):
            continue  # local packages / registry entries are skipped in v0.1
        state = p.get("state", {})
        src = normalise_git_url(url)
        out.append({
            "name": name or src.rsplit("/", 1)[-1],
            "version": state.get("version"),
            "revision": state.get("revision"),
            "branch": state.get("branch"),
            "ecosystem": "SwiftURL",
            "source_url": src,
            "purl": swift_purl(src, state.get("version"), state.get("revision")),
            "lockfile": path,
        })
    return out


_POD_LINE = re.compile(r"^  - \"?([^\s\"(]+)(?: \(([^)]+)\))?\"?:?$")


def parse_podfile_lock(path: str) -> List[Dict]:
    """Read the PODS: section. Subspecs (Foo/Bar) collapse onto their root pod."""
    out, seen, in_pods = [], set(), False
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.rstrip("\n")
            if line.startswith("PODS:"):
                in_pods = True
                continue
            if in_pods and line and not line.startswith(" "):
                break
            if not in_pods:
                continue
            m = _POD_LINE.match(line)
            if not m:
                continue
            name, version = m.group(1).split("/")[0], m.group(2)
            if not version or name in seen:
                continue
            seen.add(name)
            out.append({
                "name": name, "version": version, "revision": None, "branch": None,
                "ecosystem": "CocoaPods", "source_url": None,
                "purl": f"pkg:cocoapods/{name}@{version}", "lockfile": path,
            })
    return out


def find_lockfiles(root: str) -> List[str]:
    if os.path.isfile(root):
        return [root]
    found = []
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS and not x.startswith(".") or x in (".swiftpm",)]
        for fn in files:
            if fn in ("Package.resolved", "Podfile.lock"):
                found.append(os.path.join(d, fn))
    return sorted(found)


def load_components(paths: Iterable[str]) -> List[Dict]:
    comps, keys = [], set()
    for p in paths:
        base = os.path.basename(p)
        items = parse_package_resolved(p) if base.startswith("Package.resolved") else parse_podfile_lock(p) if base.startswith("Podfile.lock") else []
        for c in items:
            k = c["purl"]
            if k not in keys:
                keys.add(k)
                comps.append(c)
    return comps
