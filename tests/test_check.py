import unittest
from unittest import mock
from cra_scan import check, feeds

COMPS = [
    {"name": "swift-nio", "version": "2.41.0", "revision": None, "ecosystem": "SwiftURL",
     "source_url": "github.com/apple/swift-nio", "purl": "pkg:swift/github.com/apple/swift-nio@2.41.0", "lockfile": "x"},
    {"name": "AFNetworking", "version": "2.5.0", "revision": None, "ecosystem": "CocoaPods",
     "source_url": None, "purl": "pkg:cocoapods/AFNetworking@2.5.0", "lockfile": "y"},
]
OSV = {"id": "GHSA-7fj7-39wj-c64f", "aliases": ["CVE-2022-3215"], "summary": "CRLF injection",
       "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"}],
       "affected": [{"ranges": [{"events": [{"introduced": "2.41.0"}, {"fixed": "2.42.0"}]}]}]}


class CheckTests(unittest.TestCase):
    def run_check(self, kev=set(), euvd={}, epss=None):
        with mock.patch.object(feeds, "osv_query", return_value={COMPS[0]["purl"]: ["GHSA-7fj7-39wj-c64f"]}), \
             mock.patch.object(feeds, "osv_details", return_value=OSV), \
             mock.patch.object(feeds, "kev_cves", return_value=kev), \
             mock.patch.object(feeds, "euvd_exploited", return_value=euvd), \
             mock.patch.object(feeds, "epss", return_value=epss or {"CVE-2022-3215": 0.0065}):
            return check.check(COMPS)

    def test_known(self):
        r = self.run_check()
        self.assertEqual(r["worst"], "known")
        f = r["findings"][0]
        self.assertEqual(f["fixed"], ["2.42.0"])
        self.assertEqual(f["cvss"], 5.3)
        self.assertEqual(r["not_checked"], ["pkg:cocoapods/AFNetworking@2.5.0"])

    def test_exploited_via_kev(self):
        self.assertEqual(self.run_check(kev={"CVE-2022-3215"})["worst"], "exploited")

    def test_exploited_via_euvd_alias(self):
        r = self.run_check(euvd={"GHSA-7fj7-39wj-c64f": "EUVD-2022-1"})
        self.assertEqual(r["findings"][0]["euvd"], "EUVD-2022-1")
        self.assertEqual(r["worst"], "exploited")

    def test_high_via_epss(self):
        self.assertEqual(self.run_check(epss={"CVE-2022-3215": 0.4})["worst"], "high")

    def test_next_fix_picks_lowest_above_pin(self):
        self.assertEqual(check._next_fix("2.41.0", ["2.42.0", "2.39.1", "2.29.1"]), ["2.42.0"])
        self.assertEqual(check._next_fix("2.50.0", ["2.42.0"]), [])

    def test_cvss_calc(self):
        self.assertEqual(check._cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(check._cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10.0)


if __name__ == "__main__":
    unittest.main()
