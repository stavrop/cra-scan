# cra-scan

SBOM + exploited-vulnerability check for Swift / Apple-platform projects, built for the EU Cyber Resilience Act (CRA).
The open-source core of [Pinwatch](https://pinwatch.dev).

- Reads Swift Package Manager `Package.resolved` (formats v1–v3) and CocoaPods `Podfile.lock`
- Writes a CycloneDX 1.6 SBOM
- Checks every pinned Swift package against [OSV](https://osv.dev) and flags vulnerabilities that
  [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) or ENISA's [EUVD](https://euvd.enisa.europa.eu) list as **exploited**,
  plus [EPSS](https://www.first.org/epss/) exploit probability
- Pure Python 3.9+, no dependencies, no account, no telemetry

## Install & run

```bash
pipx install cra-scan            # once published; until then: python3 -m cra_scan from this folder
cra-scan scan path/to/MyApp --product "My App" --product-version 1.4 --supplier "My Studio"
cra-scan check sbom.cdx.json --format markdown    # re-check an existing SBOM
```

Exit codes: `0` ok · `1` findings at/above `--fail-on` (default `exploited`) · `2` input error · `3` feed unreachable.

Levels: **exploited** (CISA KEV or ENISA EUVD lists it as exploited — if your product is affected, CRA Art. 14 reporting applies:
24 h early warning, 72 h notification, final report within 14 days of a fix) · **high** (EPSS ≥ 0.10 or CVSS ≥ 9.0) ·
**known** (any published advisory for the pinned version).

Coverage: Swift packages are matched through OSV's `SwiftURL` ecosystem (GitHub advisory database). CocoaPods pods are
listed in the SBOM but not yet matched — there is no public advisory feed for them; v0.2 will map pods to their source repos.
Feeds are cached in `~/.cache/cra-scan` for 12 h (`CRA_SCAN_CACHE` overrides).

## GitHub Action

```yaml
- uses: actions/checkout@v4
- uses: stavrop/cra-scan@v0
  with: {product: "My App", version: "1.4", fail-on: exploited}
```
The report is added to the job summary; output `worst` = none | known | high | exploited.

## Development

```bash
python3 -m unittest discover -s tests
```

Licence: Apache-2.0. Not legal advice — you remain the manufacturer responsible for your product's conformity.
