"""Rule-based scoring + greedy weight tuning."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Callable

Test = Callable[[dict], bool]

RULES: dict[str, tuple[int, str, Test]] = {
    "ip_host": (35, "Host is a raw IP address", lambda f: f["has_ip_host"]),
    "at_symbol": (25, "'@' in authority hides the real host", lambda f: f["has_at_symbol"]),
    "brand_lookalike": (35, "Domain is a typo/leet variant of a known brand", lambda f: f["brand_lookalike"]),
    "brand_impersonation": (30, "Brand name used outside its real domain", lambda f: f["brand_impersonation"]),
    "punycode": (20, "Punycode (possible homograph) host", lambda f: f["has_punycode"]),
    "suspicious_tld": (15, "TLD commonly abused for phishing", lambda f: f["suspicious_tld"]),
    "shortener": (10, "URL shortener hides destination", lambda f: f["is_shortener"]),
    "no_https": (8, "Not served over HTTPS", lambda f: not f["uses_https"]),
    "many_subdomains": (12, "3+ subdomain levels", lambda f: f["num_subdomains"] >= 3),
    "long_url": (8, "URL longer than 75 chars", lambda f: f["url_length"] > 75),
    "long_host": (6, "Hostname longer than 30 chars", lambda f: f["host_length"] > 30),
    "hyphens_in_host": (10, "2+ hyphens in hostname", lambda f: f["num_hyphens_host"] >= 2),
    "digits_in_host": (8, "4+ digits in hostname", lambda f: f["num_digits_host"] >= 4),
    "keywords": (15, "2+ sensitive keywords (login, verify, ...)", lambda f: f["keyword_count"] >= 2),
    "keyword_in_host": (10, "Sensitive keyword inside hostname", lambda f: f["keyword_in_host"]),
    "high_entropy_label": (8, "Random-looking domain label", lambda f: f["label_length"] >= 10 and f["label_entropy"] > 3.6),
    "nonstandard_port": (12, "Non-standard port", lambda f: f["nonstandard_port"]),
    "double_slash_path": (8, "'//' inside path", lambda f: f["double_slash_in_path"]),
    "heavy_encoding": (6, "3+ percent-encoded chars", lambda f: f["encoded_chars"] >= 3),
    "embedded_url": (10, "Another URL embedded in query (redirect)", lambda f: f["embedded_url_in_query"]),
    "dns_unresolved": (10, "Domain does not resolve", lambda f: f["dns_resolves"] is False),
}


@dataclass
class Verdict:
    url: str
    score: int
    label: str
    reasons: list[tuple[str, int]] = field(default_factory=list)
    features: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"url": self.url, "score": self.score, "label": self.label,
                "reasons": [{"rule": n, "weight": w} for n, w in self.reasons]}


class Scorer:
    def __init__(self, weights: dict[str, int] | None = None,
                 phishing_threshold: int = 50, suspicious_threshold: int = 30):
        self.weights = {n: r[0] for n, r in RULES.items()}
        if weights:
            self.weights.update({k: v for k, v in weights.items() if k in RULES})
        self.phishing_threshold = phishing_threshold
        self.suspicious_threshold = suspicious_threshold

    def raw_score(self, f: dict) -> int:
        return sum(w for n, w in self.weights.items() if w and RULES[n][2](f))

    def score(self, url: str, f: dict) -> Verdict:
        fired = [(n, w) for n, w in self.weights.items() if w and RULES[n][2](f)]
        fired.sort(key=lambda x: -x[1])
        s = min(100, sum(w for _, w in fired))
        label = ("phishing" if s >= self.phishing_threshold
                 else "suspicious" if s >= self.suspicious_threshold else "legitimate")
        return Verdict(url, s, label, fired, f)

    def save(self, path: str) -> None:
        with open(path, "w") as fh:
            json.dump({"weights": self.weights, "phishing_threshold": self.phishing_threshold,
                       "suspicious_threshold": self.suspicious_threshold}, fh, indent=2)

    @classmethod
    def load(cls, path: str) -> "Scorer":
        with open(path) as fh:
            d = json.load(fh)
        return cls(d["weights"], d.get("phishing_threshold", 50), d.get("suspicious_threshold", 30))


def metrics(scorer: Scorer, data: list[tuple[dict, int]]) -> dict:
    tp = fp = tn = fn = 0
    for f, y in data:
        pred = min(100, scorer.raw_score(f)) >= scorer.phishing_threshold
        tp += pred and y
        fp += pred and not y
        tn += (not pred) and not y
        fn += (not pred) and y
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {"precision": prec, "recall": rec, "f1": f1,
            "accuracy": (tp + tn) / max(1, len(data)), "tp": tp, "fp": fp, "tn": tn, "fn": fn}


def greedy_tune(scorer: Scorer, data: list[tuple[dict, int]], max_rounds: int = 10,
                grid=range(0, 45, 5), thresholds=range(20, 75, 5)) -> Scorer:
    """Greedy coordinate ascent; stops at a local optimum."""
    def key(s: Scorer):
        return (metrics(s, data)["f1"], -sum(s.weights.values()))

    best = key(scorer)
    for _ in range(max_rounds):
        cand_best, cand = best, None
        for name in scorer.weights:
            for w in grid:
                if w == scorer.weights[name]:
                    continue
                trial = Scorer(dict(scorer.weights), scorer.phishing_threshold, scorer.suspicious_threshold)
                trial.weights[name] = w
                k = key(trial)
                if k > cand_best:
                    cand_best, cand = k, trial
        for t in thresholds:
            if t == scorer.phishing_threshold:
                continue
            trial = Scorer(dict(scorer.weights), t, min(scorer.suspicious_threshold, t - 5))
            k = key(trial)
            if k > cand_best:
                cand_best, cand = k, trial
        if cand is None:
            break
        scorer, best = cand, cand_best
    return scorer
