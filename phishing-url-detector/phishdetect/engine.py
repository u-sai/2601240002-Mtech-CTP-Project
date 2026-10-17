"""Async batch engine: features -> (optional async DNS check) -> score."""
from __future__ import annotations

import asyncio
from urllib.parse import urlparse

from .features import extract_features
from .scorer import Scorer, Verdict


def _host(url: str) -> str:
    try:
        return urlparse(url if "://" in url else "http://" + url).hostname or ""
    except ValueError:
        return ""


async def resolves(host: str, timeout: float) -> bool:
    if not host:
        return False
    loop = asyncio.get_running_loop()
    try:
        await asyncio.wait_for(loop.getaddrinfo(host, None), timeout)
        return True
    except (OSError, asyncio.TimeoutError):
        return False


async def _check_one(url: str, scorer: Scorer, sem: asyncio.Semaphore,
                     resolve_dns: bool, timeout: float) -> Verdict:
    try:
        dns = None
        if resolve_dns:
            async with sem:
                dns = await resolves(_host(url), timeout)
        return scorer.score(url, extract_features(url, dns))
    except Exception as exc:
        return Verdict(url, 0, "error", [(f"error:{type(exc).__name__}", 0)])


async def check_urls(urls: list[str], scorer: Scorer | None = None, concurrency: int = 100,
                     resolve_dns: bool = False, timeout: float = 2.0) -> list[Verdict]:
    scorer = scorer or Scorer()
    sem = asyncio.Semaphore(concurrency)
    return await asyncio.gather(*(_check_one(u, scorer, sem, resolve_dns, timeout) for u in urls))


def check_url_sync(url: str, scorer: Scorer | None = None) -> Verdict:
    return (scorer or Scorer()).score(url, extract_features(url))
