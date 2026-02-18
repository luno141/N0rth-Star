# backend/app/crawler.py
from __future__ import annotations

from dataclasses import dataclass
from typing import List
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from backend.app.scraper import scrape_url, ScrapeResult


@dataclass
class CrawlResult:
    root: ScrapeResult
    links: List[str]


def _same_host(a: str, b: str) -> bool:
    try:
        return urlparse(a).netloc == urlparse(b).netloc
    except Exception:
        return False


def extract_links(html: str, base_url: str, *, same_host_only: bool = True, limit: int = 8) -> List[str]:
    soup = BeautifulSoup(html or "", "html.parser")

    out: List[str] = []
    seen = set()

    for tag in soup.find_all("a"):
        href = tag.get("href")
        if not href:
            continue
        href = href.strip()

        if href.startswith("#") or href.startswith("mailto:") or href.startswith("javascript:"):
            continue

        full = urljoin(base_url, href)
        full = full.split("#")[0]

        if same_host_only and not _same_host(base_url, full):
            continue

        # skip non-http(s)
        if not full.startswith("http://") and not full.startswith("https://"):
            continue

        if full in seen:
            continue
        seen.add(full)
        out.append(full)

        if len(out) >= limit:
            break

    return out


def crawl_one_hop(start_url: str, *, max_links: int = 6, same_host_only: bool = True) -> CrawlResult:
    root = scrape_url(start_url)
    if not root.ok:
        return CrawlResult(root=root, links=[])

    links: List[str] = []
    if root.html:
        links = extract_links(root.html, root.url, same_host_only=same_host_only, limit=max_links)

    return CrawlResult(root=root, links=links)
