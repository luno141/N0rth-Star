import math
import re
from dataclasses import dataclass
from typing import List, Dict, Tuple

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    ent = 0.0
    n = len(s)
    for c in freq.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent

def mask_secret(s: str, keep_prefix: int = 4, keep_suffix: int = 4) -> str:
    if s is None:
        return ""
    if len(s) <= keep_prefix + keep_suffix + 2:
        return s[0:1] + "…" + s[-1:]
    return s[:keep_prefix] + "…" + s[-keep_suffix:]

def context_has_keywords(text: str, start: int, end: int, window: int = 40) -> bool:
    left = max(0, start - window)
    right = min(len(text), end + window)
    chunk = text[left:right].lower()
    keywords = [
        "password", "passwd", "pwd", "token", "api key", "apikey",
        "secret", "auth", "authorization", "credential", "creds",
        "bearer", "key="
    ]
    return any(k in chunk for k in keywords)

LEAK_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("AWS_ACCESS_KEY_ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GITHUB_TOKEN", re.compile(r"\bghp_[A-Za-z0-9]{30,}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("PRIVATE_KEY_BLOCK", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("PASSWORD_ASSIGNMENT", re.compile(r"(?i)\b(password|passwd|pwd)\s*[:=]\s*([^\s'\";]{6,})")),
    ("AUTH_HEADER", re.compile(r"(?i)\bAuthorization\s*:\s*Bearer\s+([A-Za-z0-9._\-]{10,})")),
    ("CONNECTION_STRING", re.compile(r"(?i)\b(postgres|postgresql|mysql|mongodb|mssql)://[^\s]+")),
]

@dataclass
class Finding:
    type: str
    confidence: float
    evidence: str
    masked_value: str

def leak_detector(text: str) -> List[Finding]:
    findings: List[Finding] = []
    if not text:
        return findings

    for ftype, pat in LEAK_PATTERNS:
        for m in pat.finditer(text):
            raw = m.group(0)
            start, end = m.start(), m.end()

            value = raw
            if ftype == "PASSWORD_ASSIGNMENT":
                value = m.group(2)
            elif ftype == "AUTH_HEADER":
                value = m.group(1)

            ent = shannon_entropy(value)
            has_ctx = context_has_keywords(text, start, end)

            base = {
                "PRIVATE_KEY_BLOCK": 0.95,
                "AWS_ACCESS_KEY_ID": 0.85,
                "GITHUB_TOKEN": 0.85,
                "JWT": 0.70,
                "CONNECTION_STRING": 0.80,
                "AUTH_HEADER": 0.75,
                "PASSWORD_ASSIGNMENT": 0.65,
            }.get(ftype, 0.60)

            conf = base
            if has_ctx:
                conf += 0.10
            if len(value) >= 12:
                if ent >= 3.5:
                    conf += 0.10
                elif ent < 2.8:
                    conf -= 0.10

            conf = max(0.0, min(1.0, conf))

            snippet_left = max(0, start - 40)
            snippet_right = min(len(text), end + 40)
            evidence = text[snippet_left:snippet_right].replace("\n", " ")

            findings.append(Finding(
                type=ftype,
                confidence=conf,
                evidence=evidence[:240],
                masked_value=mask_secret(value)
            ))

    uniq = []
    seen = set()
    for f in findings:
        key = (f.type, f.masked_value, f.evidence[:60])
        if key not in seen:
            uniq.append(f)
            seen.add(key)
    return uniq

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
DOMAIN_RE = re.compile(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b")
URL_RE = re.compile(r"\bhttps?://[^\s]+", re.IGNORECASE)

def entity_extractor(text: str) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    if not text:
        return out

    for ip in IP_RE.findall(text):
        out.append({"kind": "ip", "value": ip})

    for email in EMAIL_RE.findall(text):
        out.append({"kind": "email", "value": email})

    for url in URL_RE.findall(text):
        out.append({"kind": "url", "value": url})

    file_like_ext = {".json", ".txt", ".png", ".jpg", ".jpeg", ".pdf", ".zip", ".tar", ".gz", ".mp4"}
    for dom in DOMAIN_RE.findall(text):
        low = dom.lower()
        if any(low.endswith(ext) for ext in file_like_ext):
            continue
        out.append({"kind": "domain", "value": dom})

    seen = set()
    uniq = []
    for e in out:
        key = (e["kind"], e["value"])
        if key not in seen:
            uniq.append(e)
            seen.add(key)
    return uniq
