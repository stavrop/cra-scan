# cra-scan

SBOM + exploited-vulnerability check for Swift / Apple-platform projects, built for the EU Cyber Resilience Act (CRA).
The open-source core of [Pinwatch](https://pinwatch.dev).

- Reads Swift Package Manager `Package.resolved` (formats v1–v3) and CocoaPods `Podfile.lock`
- Writes a CycloneDX 1.6 SBOM
- Checks every pinned Swift package against [OSV](https://osv.dev), and every CocoaPods pod against OSV (via its source
  repo) and [NVD](https://nvd.nist.gov) (by CPE), and flags vulnerabilities that
  [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) or ENISA's [EUVD](https://euvd.enisa.europa.eu) list as **exploited**,
  plus [EPSS](https://www.first.org/epss/) exploit probability
- Pure Python 3.9+, no dependencies, no account, no telemetry

## Install & run

```bash
pipx install cra-scan            # or: pip install cra-scan
cra-scan scan path/to/MyApp --product "My App" --product-version 1.4 --supplier "My Studio"
cra-scan check sbom.cdx.json --format markdown    # re-check an existing SBOM
```

Exit codes: `0` ok · `1` findings at/above `--fail-on` (default `exploited`) · `2` input error · `3` feed unreachable.

Levels: **exploited** (CISA KEV or ENISA EUVD lists it as exploited — if your product is affected, CRA Art. 14 reporting applies:
24 h early warning, 72 h notification, final report within 14 days of a fix) · **high** (EPSS ≥ 0.10 or CVSS ≥ 9.0) ·
**known** (any published advisory for the pinned version).

Example (a demo project pinning `libwebp 1.2.0` and `SSZipArchive 2.1.0` through CocoaPods, and `swift-nio 2.41.0`):

```text
cra-scan 0.2.0 · Demo: 8 components, 8 checked, worst: EXPLOITED
  [EXPLOITED] libwebp 1.2.0: CVE-2023-4863  epss=1.000 fixed in 1.3.2
              Heap buffer overflow in libwebp in Google Chrome prior to 116.0.5845.187 and libwebp 1.3.2 allowed a remote at
  [KNOWN    ] SSZipArchive 2.1.0: CVE-2022-36943  epss=0.009
              SSZipArchive versions 2.5.3 and older contain an arbitrary file write vulnerability due to lack of sanitizatio
  [KNOWN    ] swift-nio 2.41.0: GHSA-7fj7-39wj-c64f CVE-2022-3215 epss=0.006 fixed in 2.42.0
  ...
  ! Actively exploited vulnerability found. If your product is affected, CRA Art. 14 reporting applies:
    24h early warning / 72h notification via ENISA's Single Reporting Platform. Record when you became aware.
```

### Coverage

- **Swift packages** — OSV's `SwiftURL` ecosystem (GitHub advisory database), by version or, for branch pins, by commit.
- **CocoaPods pods** — there is no advisory feed for pods, so cra-scan reads each pod's podspec from the CocoaPods CDN
  to find its source repo, then checks (1) OSV for that repo, which catches pods that are also Swift packages, and
  (2) NVD for CVEs whose CPE names the pod or its repo at the pinned version. When the CPE vendor matches the pod's
  repo owner (e.g. `webmproject` ↔ `webm/libwebp`) the finding counts normally. A match **by product name only** is
  shown as `verify` and capped at `known`, so a name collision never fails your build.
- NVD allows 5 requests per 30 s without a key, so the first CocoaPods scan takes ~10 s per pod. Results are cached for
  24 h; set `NVD_API_KEY` ([free](https://nvd.nist.gov/developers/request-an-api-key)) for ~10× faster first runs,
  or `--no-nvd` to skip it.
- Pods from a `:git` or `:path` source, Carthage and binary frameworks are listed in the SBOM only.

Feeds are cached in `~/.cache/cra-scan` (`CRA_SCAN_CACHE` overrides): KEV/EUVD 12 h, NVD 24 h, podspecs 30 days.

## GitHub Action

```yaml
- uses: actions/checkout@v4
- uses: stavrop/cra-scan@v0
  with: {product: "My App", version: "1.4", fail-on: exploited}
```
The report is added to the job summary; output `worst` = none | known | high | exploited. The cache is kept between
runs with `actions/cache`; pass `nvd-api-key: ${{ secrets.NVD_API_KEY }}` to speed up CocoaPods checks.

## Development

```bash
python3 -m unittest discover -s tests
```

Licence: Apache-2.0. Not legal advice — you remain the manufacturer responsible for your product's conformity.
