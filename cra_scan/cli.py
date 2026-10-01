"""cra-scan — SBOM + exploited-vulnerability check for Swift / Apple-platform projects.

  cra-scan sbom  PATH [--product NAME] [--product-version V] [--supplier ORG] [-o sbom.json]
  cra-scan check PATH|SBOM.json [--format table|json|markdown] [--fail-on exploited|high|known|never]
  cra-scan scan  PATH  (= sbom + check; writes sbom.cdx.json and prints the report)

Exit codes: 0 ok · 1 findings at/above --fail-on · 2 usage or input error · 3 network/feed error
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error

from . import __version__, check as checker, lockfiles, sbom


def _components(path: str):
    if path.endswith(".json") and os.path.isfile(path):
        with open(path, encoding="utf-8") as f:
            head = f.read(4096)
        if '"bomFormat"' in head:
            return sbom.components_from_sbom(path), []
    files = lockfiles.find_lockfiles(path)
    return lockfiles.load_components(files), files


def _product_name(path: str, explicit: str = None) -> str:
    if explicit:
        return explicit
    p = os.path.abspath(path)
    return os.path.basename(p if os.path.isdir(p) else os.path.dirname(p)) or "product"


def _print_table(rep: dict, product: str):
    print(f"cra-scan {__version__} · {product}: {rep['components']} components, {rep['checked']} checked, worst: {rep['worst'].upper()}")
    for f in rep["findings"]:
        ep = f" epss={f['epss']:.3f}" if f["epss"] is not None else ""
        fix = f" fixed in {', '.join(f['fixed'])}" if f["fixed"] else ""
        tag = " (verify: name-only NVD match, vendor " + f["cpe_vendor"] + ")" if f.get("verify") else ""
        ids = " ".join(c for c in f["cves"] if c != f["id"])
        print(f"  [{f['level'].upper():9}] {f['component']} {f['version']}: {f['id']} {ids}{ep}{fix}{tag}")
        if f["summary"]:
            print(f"              {f['summary'][:110]}")
    if rep["worst"] == "exploited":
        print("\n  ! Actively exploited vulnerability found. If your product is affected, CRA Art. 14 reporting applies:")
        print("    24h early warning / 72h notification via ENISA's Single Reporting Platform. Record when you became aware.")
    if rep["not_checked"]:
        print(f"  ({len(rep['not_checked'])} component(s) listed in the SBOM but not checked: no pinned version or no advisory source)")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="cra-scan", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version=f"cra-scan {__version__}")
    sp = ap.add_subparsers(dest="cmd", required=True)
    for name in ("sbom", "check", "scan"):
        p = sp.add_parser(name)
        p.add_argument("path", nargs="?", default=".")
        p.add_argument("--product")
        if name in ("sbom", "scan"):
            p.add_argument("--product-version")
            p.add_argument("--supplier")
            p.add_argument("-o", "--output", default=None if name == "sbom" else "sbom.cdx.json")
        if name in ("check", "scan"):
            p.add_argument("--format", choices=["table", "json", "markdown"], default="table")
            p.add_argument("--fail-on", choices=["exploited", "high", "known", "never"], default="exploited")
            p.add_argument("--no-epss", action="store_true")
            p.add_argument("--no-nvd", action="store_true", help="skip NVD look-ups for CocoaPods pods")
    a = ap.parse_args(argv)

    if not os.path.exists(a.path):
        print(f"cra-scan: {a.path}: not found", file=sys.stderr)
        return 2
    comps, files = _components(a.path)
    if not comps:
        print("cra-scan: no Package.resolved or Podfile.lock found (resolve packages in Xcode first)", file=sys.stderr)
        return 2
    product = _product_name(a.path, a.product)

    if a.cmd == "scan":
        try:   # put each pod's source repo into the SBOM too
            checker.resolve_pods(comps)
        except (urllib.error.URLError, TimeoutError, OSError):
            pass
    if a.cmd in ("sbom", "scan"):
        bom = sbom.build_sbom(comps, product, a.product_version, a.supplier)
        text = json.dumps(bom, indent=2)
        if a.output:
            with open(a.output, "w", encoding="utf-8") as f:
                f.write(text + "\n")
            print(f"cra-scan: wrote {a.output} ({len(comps)} components from {len(files) or 1} file(s))", file=sys.stderr)
        else:
            print(text)
        if a.cmd == "sbom":
            return 0

    try:
        rep = checker.check(comps, use_epss=not a.no_epss, use_nvd=not a.no_nvd)
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        print(f"cra-scan: could not reach a vulnerability feed: {e}", file=sys.stderr)
        return 3
    if a.format == "json":
        print(json.dumps(rep, indent=2))
    elif a.format == "markdown":
        print(checker.to_markdown(rep, product))
    else:
        _print_table(rep, product)
    if a.fail_on != "never" and checker.LEVELS.index(rep["worst"]) >= checker.LEVELS.index(a.fail_on):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
