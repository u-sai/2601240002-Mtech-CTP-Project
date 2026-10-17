"""Lexical + domain-based feature extraction for URLs (stdlib only)."""
from __future__ import annotations

import math
import re
from collections import Counter
from ipaddress import ip_address
from urllib.parse import parse_qsl, unquote, urlparse

MULTI_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.in", "net.in", "org.in", "gov.in",
    "ac.in", "com.au", "co.jp", "com.br", "co.za", "com.sg", "co.nz",
}
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "club", "click", "work", "icu",
    "online", "site", "live", "support", "zip", "mov", "cam", "rest", "buzz",
}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy"}
BRANDS = {
    "paypal", "google", "apple", "microsoft", "amazon", "facebook", "netflix",
    "instagram", "whatsapp", "dropbox", "linkedin", "sbi", "hdfc", "icici",
}
KEYWORDS = {
    "login", "signin", "verify", "verification", "update", "secure", "account",
    "password", "confirm", "banking", "wallet", "suspend", "suspended", "unlock",
    "invoice", "payment", "billing", "kyc", "recover", "auth",
}
LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "@": "a", "$": "s"})


def levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def split_host(host: str) -> tuple[str, str, str]:
    """Return (subdomain, registered label, public suffix) with a small suffix heuristic."""
    parts = host.split(".")
    k = 3 if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_SUFFIXES else 2
    if len(parts) < k:
        return "", parts[0], ""
    return ".".join(parts[:-k]), parts[-k], ".".join(parts[-(k - 1):])


def _is_ip(host: str) -> bool:
    try:
        ip_address(host)
        return True
    except ValueError:
        return bool(re.fullmatch(r"(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){3}", host))


def _brand_signals(sub: str, label: str, path: str) -> tuple[bool, bool]:
    label_tokens = [t for t in re.split(r"[^a-z0-9]+", label) if t]
    other_tokens = {t for t in re.split(r"[^a-z0-9]+", f"{sub} {path}") if t}
    impersonation = label not in BRANDS and bool(BRANDS & (other_tokens | set(label_tokens)))
    lookalike = False
    for tok in label_tokens:
        if tok in BRANDS:
            continue
        norm = tok.translate(LEET)
        for b in BRANDS:
            if norm == b or (len(b) >= 6 and len(tok) >= 5 and levenshtein(norm, b) == 1):
                lookalike = True
    return impersonation, lookalike


def extract_features(url: str, dns_resolves: bool | None = None) -> dict:
    raw = url.strip()
    p = urlparse(raw if "://" in raw else "http://" + raw)
    host = (p.hostname or "").lower()
    try:
        port = p.port
    except ValueError:
        port = None
    path_q = unquote(p.path + ("?" + p.query if p.query else "")).lower()
    sub, label, suffix = split_host(host)
    tld = suffix.split(".")[-1] if suffix else ""
    impersonation, lookalike = _brand_signals(sub, label, p.path.lower())
    tokens = set(re.split(r"[^a-z0-9]+", host + " " + path_q))

    return {
        "url_length": len(raw),
        "host_length": len(host),
        "num_dots": host.count("."),
        "num_hyphens_host": host.count("-"),
        "num_digits_host": sum(c.isdigit() for c in host),
        "has_at_symbol": "@" in (p.netloc or ""),
        "uses_https": p.scheme == "https",
        "path_depth": len([s for s in p.path.split("/") if s]),
        "num_query_params": len(parse_qsl(p.query)),
        "double_slash_in_path": "//" in p.path,
        "encoded_chars": raw.count("%"),
        "embedded_url_in_query": bool(re.search(r"=https?(%3a|:)", raw.lower())),
        "keyword_count": len(KEYWORDS & tokens),
        "keyword_in_host": bool(KEYWORDS & set(re.split(r"[^a-z0-9]+", host))),
        "nonstandard_port": port not in (None, 80, 443),
        "has_ip_host": _is_ip(host),
        "num_subdomains": len([s for s in sub.split(".") if s]),
        "has_punycode": "xn--" in host,
        "suspicious_tld": tld in SUSPICIOUS_TLDS,
        "is_shortener": ".".join(host.split(".")[-2:]) in SHORTENERS,
        "label_entropy": round(entropy(label), 3),
        "label_length": len(label),
        "brand_impersonation": impersonation,
        "brand_lookalike": lookalike,
        "dns_resolves": dns_resolves,
    }
