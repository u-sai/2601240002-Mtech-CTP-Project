import argparse
import asyncio
import csv
import json
import sys

from .engine import check_urls
from .features import extract_features
from .scorer import Scorer, greedy_tune, metrics

COLORS = {"phishing": "\033[91m", "suspicious": "\033[93m", "legitimate": "\033[92m"}


def _scorer(path):
    return Scorer.load(path) if path else Scorer()


def _print(verdicts, as_json):
    if as_json:
        print(json.dumps([v.to_dict() for v in verdicts], indent=2))
        return
    tty = sys.stdout.isatty()
    for v in verdicts:
        c, r = (COLORS.get(v.label, ""), "\033[0m") if tty else ("", "")
        why = ", ".join(f"{n}(+{w})" for n, w in v.reasons[:4]) or "-"
        print(f"{c}{v.label.upper():<11}{r}{v.score:>4}  {v.url}\n{'':<15}{why}")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="phishdetect", description="Phishing URL detection engine")
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("check", help="check one or more URLs")
    c.add_argument("urls", nargs="+")
    s = sub.add_parser("scan", help="batch-check URLs from a file (one per line, '-' for stdin)")
    s.add_argument("file")
    for p in (c, s):
        p.add_argument("--dns", action="store_true", help="async DNS resolution check")
        p.add_argument("--concurrency", type=int, default=100)
        p.add_argument("--weights", help="weights JSON produced by `tune`")
        p.add_argument("--json", action="store_true")
    e = sub.add_parser("evaluate", help="precision/recall/F1 on a labeled CSV (url,label)")
    e.add_argument("csv")
    e.add_argument("--weights")
    t = sub.add_parser("tune", help="greedy-tune rule weights + threshold on a labeled CSV")
    t.add_argument("csv")
    t.add_argument("--out", default="weights.json")

    a = ap.parse_args(argv)
    if a.cmd in ("check", "scan"):
        if a.cmd == "check":
            urls = a.urls
        else:
            fh = sys.stdin if a.file == "-" else open(a.file)
            urls = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
        _print(asyncio.run(check_urls(urls, _scorer(a.weights), a.concurrency, a.dns)), a.json)
        return

    with open(a.csv, newline="") as fh:
        data = [(extract_features(r["url"]), int(r["label"])) for r in csv.DictReader(fh)]
    fmt = lambda m: {k: round(v, 3) for k, v in m.items()}
    if a.cmd == "evaluate":
        print(fmt(metrics(_scorer(a.weights), data)))
    else:
        base = Scorer()
        print("before:", fmt(metrics(base, data)))
        tuned = greedy_tune(base, data)
        tuned.save(a.out)
        print("after: ", fmt(metrics(tuned, data)))
        print(f"threshold={tuned.phishing_threshold}  saved -> {a.out}")


if __name__ == "__main__":
    main()
