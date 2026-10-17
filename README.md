# M.Tech CTP Project Portfolio

A collection of Computer Technology Project (CTP) work developed as part of the M.Tech programme.

## Projects

### Phishing URL Detection Engine

An explainable Python tool that assigns a risk score to URLs using lexical and domain-based indicators. It supports single-URL checks, batch scanning, optional asynchronous DNS checks, CSV evaluation, and rule-weight tuning.

- **Project folder:** [phishing-url-detector](./phishing-url-detector/)
- **Technology:** Python 3.9+, asyncio, standard library, unittest
- **Getting started:** follow the project README for setup, commands, tests, and limitations.

## Repository structure

```text
.
└── phishing-url-detector/
    ├── data/                 # Illustrative labelled URL dataset
    ├── phishdetect/          # Feature extraction, scoring, async engine and CLI
    ├── tests/                # Unit tests
    ├── weights.json          # Example rule weights
    └── README.md             # Project documentation
```

## Academic and responsible-use note

This repository is intended for educational and defensive security research. The sample dataset is small and illustrative; it is not a benchmark and must not be used to claim production-grade detection accuracy. Do not use the tool as the sole security control.

## License

No license has been specified. Unless a license is added, normal copyright restrictions apply.
