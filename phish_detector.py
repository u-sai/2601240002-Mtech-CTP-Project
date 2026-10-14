"""Phishing URL Detection Engine (single file).

Usage:
    python phish_detector.py                      # checks built-in sample URLs
    python phish_detector.py URL [URL ...]        # check given URLs
    python phish_detector.py -f urls.txt          # one URL per line
    python phish_detector.py --dns URL            # also check DNS (needs internet)
"""
import argparse, asyncio, re, socket
from dataclasses import dataclass, field
from urllib.parse import urlparse

# ---------------- Feature extraction ----------------

SUSPICIOUS_WORDS = ("login", "signin", "verify", "update", "secure", "account",
                    "banking", "confirm", "password", "wallet", "suspend", "billing")
RISKY_TLDS = {"zip", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "country",
              "work", "support", "loan", "icu", "buzz"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rb.gy"}
# brand keyword -> official registered domains
BRANDS = {
    "paypal": {"paypal.com"}, "google": {"google.com"}, "apple": {"apple.com"},
    "microsoft": {"microsoft.com", "live.com"}, "amazon": {"amazon.com", "amazon.in"},
    "facebook": {"facebook.com"}, "netflix": {"netflix.com"},
    "sbi": {"sbi.co.in"}, "hdfcbank": {"hdfcbank.com"}, "icici": {"icicibank.com"},
}
SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu"}
IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def parse(url: str):
    url = url.strip()
    if "://" not in url:
        url = "http://" + url
    return urlparse(url)


def registered_domain(host: str) -> str:
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if len(labels[-1]) == 2 and labels[-2] in SECOND_LEVEL:  # e.g. sbi.co.in
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def lexical_features(url: str) -> dict:
    u = parse(url)
    host = (u.hostname or "").lower()
    full = url.lower()
    return {
        "url_length": len(url.strip()),
        "host_length": len(host),
        "num_dots": host.count("."),
        "num_hyphens": host.replace("xn--", "").count("-"),
        "num_digits_host": sum(c.isdigit() for c in host),
        "has_at": "@" in u.netloc or "@" in url,
        "has_ip_host": bool(IP_RE.match(host)),
        "uses_https": u.scheme == "https",
        "keyword_hits": sum(w in full for w in SUSPICIOUS_WORDS),
        "double_slash_in_path": "//" in u.path,
    }


def domain_features(url: str) -> dict:
    u = parse(url)
    host = (u.hostname or "").lower()
    reg = registered_domain(host)
    labels = host.split(".")
    sub_depth = max(len(labels) - len(reg.split(".")), 0)
    text = host + u.path.lower()
    brand_mismatch = any(b in text and reg not in official
                         for b, official in BRANDS.items())
    return {
        "host": host,
        "registered_domain": reg,
        "subdomain_depth": sub_depth,
        "tld": labels[-1] if labels else "",
        "risky_tld": labels[-1] in RISKY_TLDS if labels else False,
        "is_shortener": reg in SHORTENERS,
        "is_punycode": any(l.startswith("xn--") for l in labels),
        "brand_mismatch": brand_mismatch,
    }


def extract_features(url: str) -> dict:
    f = lexical_features(url)
    f.update(domain_features(url))
    return f
# ---------------- Greedy rule-based scoring ----------------

THRESHOLD = 50

# (name, weight, predicate over the feature dict)
RULES = [
    ("IP address used as host",           40, lambda f: f["has_ip_host"]),
    ("Brand name on unofficial domain",   35, lambda f: f["brand_mismatch"]),
    ("'@' symbol in URL",                 30, lambda f: f["has_at"]),
    ("Punycode (xn--) hostname",          40, lambda f: f["is_punycode"]),
    ("2+ suspicious keywords",            25, lambda f: f["keyword_hits"] >= 2),
    ("DNS lookup failed",                 20, lambda f: f.get("dns_resolves") is False),
    ("Risky TLD",                         20, lambda f: f["risky_tld"]),
    ("3+ subdomain levels",               20, lambda f: f["subdomain_depth"] >= 3),
    ("URL shortener",                     15, lambda f: f["is_shortener"]),
    ("3+ hyphens in host",                15, lambda f: f["num_hyphens"] >= 3),
    ("1 suspicious keyword",              10, lambda f: f["keyword_hits"] == 1),
    ("No HTTPS",                          10, lambda f: not f["uses_https"]),
    ("Very long URL (>75 chars)",         10, lambda f: f["url_length"] > 75),
    ("Digit-heavy host",                  10, lambda f: f["host_length"] > 0 and f["num_digits_host"] / f["host_length"] > 0.3),
    ("'//' inside path (redirect trick)", 10, lambda f: f["double_slash_in_path"]),
]


@dataclass
class Verdict:
    url: str
    is_phishing: bool
    score: int
    reasons: list = field(default_factory=list)

    @property
    def label(self) -> str:
        return "PHISHING" if self.is_phishing else "LEGITIMATE"


def score(url: str, features: dict, threshold: int = THRESHOLD) -> Verdict:
    total, reasons = 0, []
    for name, weight, rule in sorted(RULES, key=lambda r: -r[1]):
        if rule(features):
            total += weight
            reasons.append(f"{name} (+{weight})")
            if total >= threshold:      # greedy early exit
                break
    return Verdict(url, total >= threshold, total, reasons)
# ---------------- Async batch checking ----------------



async def _dns_resolves(host: str, timeout: float) -> bool:
    loop = asyncio.get_running_loop()
    try:
        await asyncio.wait_for(loop.getaddrinfo(host, None, type=socket.SOCK_STREAM), timeout)
        return True
    except (socket.gaierror, asyncio.TimeoutError, OSError):
        return False


async def check_url(url: str, use_dns: bool = False, timeout: float = 3.0,
                    threshold: int = THRESHOLD) -> Verdict:
    feats = extract_features(url)
    if use_dns and feats["host"] and not feats["has_ip_host"]:
        feats["dns_resolves"] = await _dns_resolves(feats["host"], timeout)
    return score(url, feats, threshold)


async def check_urls(urls, use_dns: bool = False, concurrency: int = 50,
                     timeout: float = 3.0, threshold: int = THRESHOLD) -> list:
    sem = asyncio.Semaphore(concurrency)

    async def worker(u):
        async with sem:
            return await check_url(u, use_dns, timeout, threshold)

    return await asyncio.gather(*(worker(u) for u in urls))


def check_urls_sync(urls, **kw):
    return asyncio.run(check_urls(urls, **kw))

# ---------------- Command line ----------------
SAMPLES = [
    "https://www.google.com/search?q=python",
    "https://github.com/anthropics",
    "https://www.sbi.co.in/web/personal-banking",
    "http://192.168.10.5/secure/login/verify-account",
    "http://paypal.account-verify.example.xyz/signin",
    "http://secure-login-sbi-update.top/verify",
    "https://xn--pple-43d.com/login",
    "http://user@evil-site.com/update/password",
]


def main():
    ap = argparse.ArgumentParser(description="Phishing URL Detection Engine")
    ap.add_argument("urls", nargs="*")
    ap.add_argument("-f", "--file", help="text file with one URL per line")
    ap.add_argument("--dns", action="store_true", help="also check DNS resolution")
    a = ap.parse_args()
    urls = list(a.urls)
    if a.file:
        with open(a.file) as fh:
            urls += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    urls = urls or SAMPLES
    results = asyncio.run(check_urls(urls, use_dns=a.dns))
    for r in results:
        print(f"[{r.label:10}] score={r.score:3}  {r.url}")
        for why in r.reasons:
            print(f"             - {why}")
    print(f"\n{sum(r.is_phishing for r in results)}/{len(results)} flagged as phishing")


if __name__ == "__main__":
    main()
