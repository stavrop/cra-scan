import io
import json
import os
import tempfile
import time
import unittest
import urllib.error
from unittest import mock
from cra_scan import feeds

URL = "https://www.cisa.gov/feed.json"


def http_error(code, retry_after=None):
    headers = {"Retry-After": retry_after} if retry_after else {}
    return urllib.error.HTTPError(URL, code, "Forbidden" if code == 403 else "Error", headers, None)


def ok(payload):
    r = mock.MagicMock()
    r.__enter__.return_value.read.return_value = json.dumps(payload).encode()
    return r


class HttpTests(unittest.TestCase):
    def setUp(self):
        p = mock.patch.object(feeds, "_sleep")
        self.sleep = p.start()
        self.addCleanup(p.stop)

    def test_retries_403_then_succeeds(self):
        with mock.patch("urllib.request.urlopen", side_effect=[http_error(403), ok({"a": 1})]) as u:
            self.assertEqual(feeds._http(URL), {"a": 1})
        self.assertEqual(u.call_count, 2)
        self.sleep.assert_called_once_with(2)

    def test_honours_retry_after(self):
        with mock.patch("urllib.request.urlopen", side_effect=[http_error(429, "7"), ok({})]):
            feeds._http(URL)
        self.sleep.assert_called_once_with(7.0)

    def test_gives_up_naming_the_url(self):
        with mock.patch("urllib.request.urlopen", side_effect=[http_error(403)] * 3) as u:
            with self.assertRaises(feeds.FeedError) as cm:
                feeds._http(URL + "?page=2")
        self.assertEqual(u.call_count, feeds.ATTEMPTS)
        self.assertEqual(cm.exception.code, 403)
        self.assertIn(URL + ": HTTP 403 Forbidden", str(cm.exception))
        self.assertNotIn("page=2", str(cm.exception))

    def test_404_is_not_retried(self):
        with mock.patch("urllib.request.urlopen", side_effect=[http_error(404)]) as u:
            with self.assertRaises(feeds.FeedError) as cm:
                feeds._http(URL)
        self.assertEqual((u.call_count, cm.exception.code), (1, 404))
        self.sleep.assert_not_called()

    def test_network_error_is_retried(self):
        with mock.patch("urllib.request.urlopen", side_effect=[urllib.error.URLError("timed out"), ok({})]):
            self.assertEqual(feeds._http(URL), {})


class StaleCacheTests(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        p = mock.patch.dict(os.environ, {"CRA_SCAN_CACHE": d.name})
        p.start()
        self.addCleanup(p.stop)
        self.path = os.path.join(d.name, "kev.json")
        feeds.STALE.clear()

    def write_cache(self, age_h):
        with open(self.path, "w") as f:
            json.dump({"vulnerabilities": [{"cveID": "CVE-1"}]}, f)
        t = time.time() - age_h * 3600
        os.utime(self.path, (t, t))

    def failing(self):
        raise feeds.FeedError(URL, "HTTP 403 Forbidden", 403)

    def test_expired_cache_used_when_feed_fails(self):
        self.write_cache(30)
        with mock.patch("sys.stderr", new_callable=io.StringIO) as err:
            data = feeds._cached("kev.json", 12, self.failing)
        self.assertEqual(data["vulnerabilities"][0]["cveID"], "CVE-1")
        self.assertEqual(feeds.STALE, ["kev.json (30 h old)"])
        self.assertIn(URL, err.getvalue())

    def test_too_old_cache_raises(self):
        self.write_cache(feeds.STALE_MAX_H + 1)
        with self.assertRaises(feeds.FeedError):
            feeds._cached("kev.json", 12, self.failing)
        self.assertEqual(feeds.STALE, [])

    def test_no_cache_raises(self):
        with self.assertRaises(feeds.FeedError):
            feeds._cached("kev.json", 12, self.failing)


if __name__ == "__main__":
    unittest.main()
