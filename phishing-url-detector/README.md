# Phishing URL Detection Engine

An explainable, dependency-free Python project for classifying URLs as **phishing**, **suspicious**, or **likely legitimate**. It combines lexical URL signals and domain-oriented heuristics into a weighted score and explains which rules contributed to each result.

> **Scope:** Educational and defensive triage tool. A score is a heuristic, not proof that a URL is safe or malicious.

## Features

- Lexical and domain indicators including URL length, IP-address hosts, subdomain depth, punycode, suspicious top-level domains, URL shorteners, encoded characters, login-related keywords, and brand lookalikes.
- Explainable weighted rules with a bounded 0–100 risk score.
- Batch processing with asyncio; optional DNS resolution with bounded concurrency and timeouts.
- Command-line commands for checking, scanning, evaluating labelled CSV data, and tuning rule weights.
- JSON output for automation and unit tests for core behaviour.
- Python standard library only; no third-party runtime dependencies.

## How it works

```text
URL input
   |
   v
Feature extraction ---> Weighted rule scorer ---> Risk score + reasons
   |                                               |
   +--- optional async DNS check                   v
                                            CLI / JSON output
```

Default thresholds:

| Score | Classification |
|---:|---|
| 50–100 | Phishing |
| 30–49 | Suspicious |
| 0–29 | Likely legitimate |

These thresholds and rules are configurable; results depend on the heuristics and dataset.

## Project structure

```text
phishing-url-detector/
├── data/
│   └── sample_urls.csv
├── phishdetect/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py
│   ├── engine.py
│   ├── features.py
│   └── scorer.py
├── tests/
│   └── test_detector.py
├── weights.json
└── README.md
```

## Requirements

- Python 3.9 or later
- No third-party packages required

Check your Python version with: python --version

## Quick start

From the repository root:

```bash
cd phishing-url-detector
python -m phishdetect check "https://github.com" "http://google.com.account-verify.xyz/login"
```

On Windows, use py instead of python if that is how Python is installed.

### Check one or more URLs

```bash
python -m phishdetect check https://github.com https://www.python.org
```

### Scan a file

Create a text file with one URL per line, then run:

```bash
python -m phishdetect scan urls.txt
python -m phishdetect scan urls.txt --json
```

Optional DNS resolution can make scanning slower and requires network/DNS access:

```bash
python -m phishdetect scan urls.txt --dns --concurrency 50
```

### Evaluate labelled data

The CSV must contain url,label columns, where label is 1 for phishing and 0 for non-phishing:

```bash
python -m phishdetect evaluate data/sample_urls.csv
```

### Tune and reuse rule weights

```bash
python -m phishdetect tune data/sample_urls.csv --out weights.json
python -m phishdetect check --weights weights.json https://example.com
```

Tuning on the included small dataset can overfit. Use a sufficiently large, representative dataset and a separate holdout set for any meaningful evaluation.

### Run tests

```bash
python -m unittest discover -s tests -v
```

## Python API

```python
import asyncio
from phishdetect import check_urls

urls = ["https://github.com", "http://google.com.account-verify.xyz/login"]
results = asyncio.run(check_urls(urls))

for result in results:
    print(result.label, result.score, result.reasons)
```

## Evaluation and limitations

- The included CSV is a small, hand-labelled demonstration dataset. Metrics from it are not evidence of real-world performance.
- URL patterns and domain heuristics can produce false positives and false negatives.
- Public-suffix handling is heuristic; it is not a replacement for a maintained Public Suffix List implementation.
- DNS resolution confirms only that a hostname resolves, not that the site is trustworthy.
- This project does not fetch page content, inspect certificates, or perform WHOIS/domain-age analysis.
- Attackers can adapt URLs to evade static rules. Combine multiple signals and independent security controls in real deployments.

## Responsible use

Use this project for learning, authorized defensive analysis, and security awareness. Do not visit suspicious links merely to test them. Never enter credentials into a URL you are investigating. Treat all classifications as advisory.

## Future improvements

- Evaluate against a larger, time-aware public dataset with a held-out test set.
- Report confusion matrix, precision, recall, F1, and ROC-AUC where appropriate.
- Add maintained public-suffix parsing and optional certificate/domain-age signals.
- Add CI automation, type checking, and reproducible experiment reports.

## License

No license is currently specified. Add a license file before redistributing or reusing the project under explicit open-source terms.
