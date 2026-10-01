import json, os, unittest
from cra_scan import lockfiles, sbom

FX = os.path.join(os.path.dirname(__file__), "fixtures")


class LockfileTests(unittest.TestCase):
    def test_url_normalisation(self):
        n = lockfiles.normalise_git_url
        self.assertEqual(n("https://github.com/Apple/swift-nio.git"), "github.com/Apple/swift-nio")
        self.assertEqual(n("git@github.com:Alamofire/Alamofire.git"), "github.com/Alamofire/Alamofire")
        self.assertEqual(n("ssh://git@gitlab.com/a/b/"), "gitlab.com/a/b")

    def test_v1(self):
        c = lockfiles.parse_package_resolved(os.path.join(FX, "Package.resolved.v1"))
        self.assertEqual([x["name"] for x in c], ["swift-nio", "Alamofire"])
        self.assertEqual(c[0]["purl"], "pkg:swift/github.com/apple/swift-nio@2.41.0")
        self.assertEqual(c[0]["source_url"], "github.com/apple/swift-nio")

    def test_v2_v3_skips_local_and_keeps_branch(self):
        c = lockfiles.parse_package_resolved(os.path.join(FX, "Package.resolved.v2"))
        self.assertEqual([x["name"] for x in c], ["purchases-ios", "swift-collections"])
        self.assertIsNone(c[1]["version"])
        self.assertEqual(c[1]["purl"], "pkg:swift/github.com/apple/swift-collections@3333")

    def test_podfile_lock_collapses_subspecs(self):
        c = lockfiles.parse_podfile_lock(os.path.join(FX, "Podfile.lock"))
        self.assertEqual([(x["name"], x["version"]) for x in c],
                         [("AFNetworking", "2.5.0"), ("Firebase", "10.0.0"), ("FirebaseCore", "10.0.0")])

    def test_sbom_roundtrip(self, tmp="/tmp/cra-scan-test.cdx.json"):
        comps = lockfiles.load_components([os.path.join(FX, "Package.resolved.v1"), os.path.join(FX, "Podfile.lock")])
        bom = sbom.build_sbom(comps, "Demo", "1.0", "Parhelia")
        self.assertEqual(bom["specVersion"], "1.6")
        self.assertEqual(len(bom["components"]), 5)
        with open(tmp, "w") as f:
            json.dump(bom, f)
        back = sbom.components_from_sbom(tmp)
        self.assertEqual({c["purl"] for c in back}, {c["purl"] for c in comps})
        self.assertEqual(back[0]["source_url"], "github.com/apple/swift-nio")


if __name__ == "__main__":
    unittest.main()
