import asyncio
import unittest

from phishdetect.engine import check_urls
from phishdetect.features import extract_features, split_host
from phishdetect.scorer import Scorer


class T(unittest.TestCase):
    def test_split_host(self):
        self.assertEqual(split_host("www.bbc.co.uk"), ("www", "bbc", "co.uk"))
        self.assertEqual(split_host("a.b.example.com"), ("a.b", "example", "com"))

    def test_features(self):
        f = extract_features("http://192.168.1.1/login")
        self.assertTrue(f["has_ip_host"])
        self.assertFalse(f["uses_https"])
        self.assertTrue(extract_features("https://paypa1.com/")["brand_lookalike"])
        self.assertTrue(extract_features("https://google.com.evil.tk/")["brand_impersonation"])
        self.assertFalse(extract_features("https://accounts.google.com/")["brand_impersonation"])

    def test_labels(self):
        s = Scorer()
        self.assertEqual(s.score("", extract_features("https://github.com/x")).label, "legitimate")
        self.assertEqual(s.score("", extract_features("http://google.com.verify-login.tk/a")).label, "phishing")

    def test_async_batch_keeps_order_and_survives_garbage(self):
        urls = ["https://github.com", "http://192.168.0.1/paypal/login", "http://[bad"]
        res = asyncio.run(check_urls(urls))
        self.assertEqual([r.url for r in res], urls)
        self.assertEqual(res[2].label, "error")


if __name__ == "__main__":
    unittest.main()
