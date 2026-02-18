# backend/app/scraper.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
import re

import requests
from bs4 import BeautifulSoup


@dataclass
class ScrapeResult:
    ok: bool
    url: str
    status_code: Optional[int]
    text: str
    html: Optional[str] = None
    error: Optional[str] = None
    used_insecure_ssl: bool = False


DEFAULT_HEADERS = {
    "User-Agent": "NorthStarBot/1.0 (+defensive-osint)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}


def _clean_visible_text(html: str, max_chars: int = 25000) -> str:
    soup = BeautifulSoup(html or "", "html.parser")

    # remove noise
    for tag in soup(["script", "style", "noscript", "svg", "header", "footer", "nav", "aside"]):
        tag.decompose()

    text = soup.get_text(separator=" ", strip=True)
    text = re.sub(r"\s+", " ", text).strip()

    if len(text) > max_chars:
        text = text[:max_chars] + " …"
    return text


def scrape_url(url: str, timeout: int = 10, max_chars: int = 25000) -> ScrapeResult:
    """
    Defensive-only: fetch a URL and extract visible text.
    - First try normal TLS verification
    - If TLS verification fails, retry with verify=False (marks used_insecure_ssl=True)
    """
    if not url:
        return ScrapeResult(ok=False, url=url, status_code=None, text="", html=None, error="missing url")

    try:
        r = requests.get(url, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True)
        status = r.status_code
        html = r.text or ""
        text = _clean_visible_text(html, max_chars=max_chars)
        return ScrapeResult(ok=True, url=r.url, status_code=status, text=text, html=html, error=None, used_insecure_ssl=False)

    except requests.exceptions.SSLError as e:
        # Retry insecurely (some environments lack CA certs)
        try:
            r = requests.get(url, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True, verify=False)
            status = r.status_code
            html = r.text or ""
            text = _clean_visible_text(html, max_chars=max_chars)
            return ScrapeResult(
                ok=True,
                url=r.url,
                status_code=status,
                text=text,
                html=html,
                error=f"TLS verify failed, used verify=False: {str(e)}",
                used_insecure_ssl=True,
            )
        except Exception as e2:
            return ScrapeResult(ok=False, url=url, status_code=None, text="", html=None, error=str(e2), used_insecure_ssl=True)

    except Exception as e:
        return ScrapeResult(ok=False, url=url, status_code=None, text="", html=None, error=str(e), used_insecure_ssl=False)
