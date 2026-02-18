# lab/app.py
from __future__ import annotations

from fastapi import FastAPI, Query
from pydantic import BaseModel
from datetime import datetime
from pathlib import Path
import json
import random
import string
import uuid

app = FastAPI(title="North Star Lab", version="1.0")

LOG_PATH = Path("lab/logs/events.jsonl")
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)


def now_iso() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def write_event(item: dict) -> None:
    with LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(item, ensure_ascii=False) + "\n")


def rand_ip() -> str:
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def fake_token(prefix: str = "ghp_") -> str:
    alphabet = string.ascii_letters + string.digits
    return prefix + "".join(random.choice(alphabet) for _ in range(36))


SECTORS = ["telecom", "banking", "upi", "power_grid", "railways", "airport", "ports", "oil", "other"]
ATTACK_ACTIONS = ["ddos", "ransomware", "exploit", "breach", "dump", "creds", "sqli", "lfi", "bruteforce"]


class SimPayload(BaseModel):
    sector: str | None = None
    n: int = 1


@app.get("/health")
def health():
    return {"ok": True, "log_path": str(LOG_PATH)}


# -----------------------------
# Simulators (SAFE)
# These DO NOT attack anything.
# They just generate synthetic log events locally.
# -----------------------------
@app.post("/simulate/noise")
def simulate_noise(p: SimPayload):
    items = []
    for _ in range(max(1, min(p.n, 200))):
        sector = p.sector or random.choice(SECTORS)
        evt = {
            "id": str(uuid.uuid4()),
            "title": "normal traffic",
            "author": "user",
            "created_at": now_iso(),
            "url": f"lab://noise/{uuid.uuid4().hex[:8]}",
            "source": "northstar_lab",
            "text": f"User browsing homepage. sector_hint={sector}. user_agent=Firefox. ip={rand_ip()}",
            "kind": "noise",
        }
        write_event(evt)
        items.append(evt)
    return {"ok": True, "written": len(items)}


@app.post("/simulate/bruteforce")
def simulate_bruteforce(p: SimPayload):
    items = []
    for _ in range(max(1, min(p.n, 200))):
        sector = p.sector or random.choice(SECTORS)
        evt = {
            "id": str(uuid.uuid4()),
            "title": "failed auth burst detected",
            "author": "lab_auth",
            "created_at": now_iso(),
            "url": f"lab://auth/{uuid.uuid4().hex[:8]}",
            "source": "northstar_lab",
            "text": (
                f"Multiple failed login attempts detected for user=admin "
                f"from ip={rand_ip()} on sector={sector}. action=bruteforce"
            ),
            "kind": "attack",
        }
        write_event(evt)
        items.append(evt)
    return {"ok": True, "written": len(items)}


@app.post("/simulate/sqli_probe")
def simulate_sqli_probe(p: SimPayload):
    payloads = ["' OR 1=1 --", "\" OR \"1\"=\"1", "UNION SELECT", "sleep(5)", "../etc/passwd"]
    items = []
    for _ in range(max(1, min(p.n, 200))):
        sector = p.sector or random.choice(SECTORS)
        probe = random.choice(payloads)
        evt = {
            "id": str(uuid.uuid4()),
            "title": "suspicious query pattern",
            "author": "lab_web",
            "created_at": now_iso(),
            "url": f"lab://web/{uuid.uuid4().hex[:8]}",
            "source": "northstar_lab",
            "text": (
                f"Suspicious input observed in parameter q={probe!r} "
                f"ip={rand_ip()} sector={sector}. action=sqli_probe"
            ),
            "kind": "attack",
        }
        write_event(evt)
        items.append(evt)
    return {"ok": True, "written": len(items)}


@app.post("/simulate/leak")
def simulate_leak(p: SimPayload):
    items = []
    for _ in range(max(1, min(p.n, 200))):
        sector = p.sector or random.choice(SECTORS)
        tok = fake_token()
        evt = {
            "id": str(uuid.uuid4()),
            "title": "debug token exposure",
            "author": "lab_api",
            "created_at": now_iso(),
            "url": f"lab://debug/{uuid.uuid4().hex[:8]}",
            "source": "northstar_lab",
            "text": (
                f"DEBUG MODE ON: Authorization: Bearer {tok}\n"
                f"sector={sector} env=prod\n"
                f"note=This is synthetic demo data"
            ),
            "kind": "leak",
        }
        write_event(evt)
        items.append(evt)
    return {"ok": True, "written": len(items)}


# -----------------------------
# Feed endpoint (collector ingests this)
# -----------------------------
@app.get("/logs/feed.json")
def feed(limit: int = Query(50, ge=1, le=200)):
    if not LOG_PATH.exists():
        return {"items": []}
    lines = LOG_PATH.read_text(encoding="utf-8").splitlines()
    tail = lines[-limit:]
    items = []
    for ln in tail[::-1]:  # newest first
        try:
            items.append(json.loads(ln))
        except Exception:
            pass
    # Convert to your ingestion schema keys
    normalized = []
    for it in items:
        normalized.append({
            "title": it.get("title"),
            "author": it.get("author"),
            "created_at": it.get("created_at"),
            "url": it.get("url"),
            "text": it.get("text"),
        })
    return {"items": normalized}
