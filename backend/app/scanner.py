from __future__ import annotations
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse
from datetime import datetime
import socket
import ssl
import httpx

SEC_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]

@dataclass
class ScanResult:
    ok: bool
    url: str
    http_status: Optional[int]
    redirects_to: Optional[str]
    missing_headers: list[str]
    server_header: Optional[str]
    tls_days_left: Optional[int]
    notes: list[str]

def _tls_days_left(host: str, port: int = 443) -> Optional[int]:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter")
                if not_after:
                    # example: 'Jun  5 12:00:00 2027 GMT'
                    exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    return (exp - datetime.utcnow()).days
    except Exception:
        return None
    return None

def passive_scan_url(url: str) -> ScanResult:
    notes = []
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "https://" + url
        parsed = urlparse(url)

    redirects_to = None
    http_status = None
    missing = []
    server = None
    tls_left = None

    try:
        with httpx.Client(follow_redirects=False, timeout=12) as client:
            r = client.get(url, headers={"User-Agent": "NorthStarScanner/1.0"})
            http_status = r.status_code
            server = r.headers.get("server")

            # redirect check
            if 300 <= r.status_code < 400 and r.headers.get("location"):
                redirects_to = r.headers.get("location")
                notes.append("Redirect detected")

            hlow = {k.lower(): v for k, v in r.headers.items()}
            for h in SEC_HEADERS:
                if h not in hlow:
                    missing.append(h)

        # tls expiry if https
        if parsed.scheme == "https" and parsed.hostname:
            tls_left = _tls_days_left(parsed.hostname, parsed.port or 443)
            if tls_left is not None and tls_left <= 14:
                notes.append("TLS expiring soon")

        # server disclosure
        if server:
            notes.append("Server header present")

        return ScanResult(True, url, http_status, redirects_to, missing, server, tls_left, notes)
    except Exception as e:
        return ScanResult(False, url, http_status, redirects_to, missing, server, tls_left, [str(e)])
