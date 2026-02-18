# backend/app/collector.py
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from pathlib import Path
import time
import json

import yaml
import requests
import feedparser
from dateutil import parser as dtparser

SOURCES_PATH = Path(__file__).resolve().parent / "sources.yaml"

UA = {
    "User-Agent": "NorthStarCollector/1.0 (+defensive-osint)",
    "Accept": "application/rss+xml, application/xml, text/xml, application/json, text/html;q=0.9, */*;q=0.8",
}


def load_sources_yaml() -> List[Dict[str, Any]]:
    if not SOURCES_PATH.exists():
        return []
    data = yaml.safe_load(SOURCES_PATH.read_text(encoding="utf-8")) or []
    if not isinstance(data, list):
        raise ValueError("sources.yaml must be a YAML list")
    return data


def _parse_time(val: Any) -> Optional[datetime]:
    if not val:
        return None
    try:
        if hasattr(val, "tm_year"):
            # struct_time from feedparser
            return datetime(*val[:6])
        if isinstance(val, (int, float)):
            return datetime.utcfromtimestamp(val)
        return dtparser.parse(str(val)).replace(tzinfo=None)
    except Exception:
        return None


def _clean_text(s: str) -> str:
    return (s or "").replace("\x00", " ").strip()


def _safe_get(d: Dict[str, Any], k: str, default=None):
    v = d.get(k, default)
    return v if v is not None else default


def _http_get(url: str, *, timeout: int, retries: int = 2) -> str:
    """
    Resilient fetch: retries with backoff. Helps with flaky networks / slow hosts.
    """
    last_err: Exception | None = None
    for i in range(retries + 1):
        try:
            r = requests.get(url, headers=UA, timeout=timeout)
            r.raise_for_status()
            return r.text
        except Exception as e:
            last_err = e
            if i < retries:
                time.sleep(1.0 + i * 1.5)
            else:
                raise last_err


def collect_source(cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Returns raw items in a common dict form:
    {
      source, url, title, author, created_at, text
    }
    """
    method = (cfg.get("method") or "").lower().strip()
    url = cfg.get("url")
    name = cfg.get("name") or "unknown"

    if not url:
        return []

    if method == "json":
        return _collect_json(name, url, cfg)

    if method == "rss":
        return _collect_rss(name, url, cfg)

    raise ValueError(f"Unknown method={method} for source={name}")


def _collect_json(source_name: str, url: str, cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    timeout = int(cfg.get("timeout_seconds", 30))
    body = _http_get(url, timeout=timeout, retries=2)

    try:
        payload = json.loads(body)
    except Exception as e:
        raise ValueError(f"Invalid JSON from {source_name}: {e}")

    items_path = cfg.get("json_items_path", "items")
    items = payload.get(items_path, [])
    if not isinstance(items, list):
        return []

    title_k = cfg.get("json_title_key", "title")
    url_k = cfg.get("json_url_key", "url")
    author_k = cfg.get("json_author_key", "author")
    time_k = cfg.get("json_time_key", "created_at")
    text_k = cfg.get("json_text_key", "text")

    out: List[Dict[str, Any]] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        created_at = _parse_time(it.get(time_k))
        out.append(
            {
                "source": source_name,
                "url": _safe_get(it, url_k),
                "title": _safe_get(it, title_k),
                "author": _safe_get(it, author_k),
                "created_at": created_at,
                "text": _clean_text(_safe_get(it, text_k, "")),
            }
        )
    return out


def _collect_rss(source_name: str, url: str, cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Uses feedparser so it works for:
    - ExploitDB RSS
    - CISA KEV XML feed
    - Reddit RSS
    - generic RSS/Atom
    """
    timeout = int(cfg.get("timeout_seconds", 45))
    xml = _http_get(url, timeout=timeout, retries=2)

    feed = feedparser.parse(xml)
    entries = feed.entries or []

    out: List[Dict[str, Any]] = []

    for e in entries:
        link = getattr(e, "link", None) or getattr(e, "id", None)
        title = getattr(e, "title", None)
        author = getattr(e, "author", None)

        published = getattr(e, "published", None) or getattr(e, "updated", None)
        published_parsed = getattr(e, "published_parsed", None) or getattr(e, "updated_parsed", None)
        created_at = _parse_time(published_parsed) or _parse_time(published)

        text = ""
        if getattr(e, "content", None):
            try:
                text = e.content[0].get("value", "") if isinstance(e.content, list) and e.content else ""
            except Exception:
                text = ""
        if not text:
            text = getattr(e, "summary", "") or getattr(e, "description", "") or ""

        combined = f"{title or ''}\n\n{text or ''}".strip()

        out.append(
            {
                "source": source_name,
                "url": link,
                "title": title,
                "author": author,
                "created_at": created_at,
                "text": _clean_text(combined),
            }
        )

    return out


def normalize_posts(posts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Ensure required keys exist and are safe strings.
    """
    out: List[Dict[str, Any]] = []
    for p in posts:
        if not isinstance(p, dict):
            continue

        url = (p.get("url") or "").strip()
        text = _clean_text(p.get("text") or "")

        # must have both
        if not url or not text:
            continue

        out.append(
            {
                "source": (p.get("source") or "unknown").strip(),
                "url": url,
                "title": (p.get("title") or None),
                "author": (p.get("author") or None),
                "created_at": p.get("created_at"),
                "text": text,
            }
        )
    return out
