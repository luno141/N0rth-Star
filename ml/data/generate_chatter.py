# ml/data/generate_chatter.py
from __future__ import annotations

import json
import random
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple

RNG = random.Random(1337)

INTENTS = ["planning", "claim", "leak", "discussion", "irrelevant"]

SECTORS = ["banking", "upi", "railways", "power_grid", "telecom", "airport", "ports", "oil", "other"]

SECTOR_HINTS: Dict[str, List[str]] = {
    "banking": ["bank", "atm", "swift", "core banking", "netbanking"],
    "upi": ["upi", "npci", "payment gateway", "upi switch", "upi gateway"],
    "railways": ["irctc", "railways", "train", "rail", "reservation"],
    "power_grid": ["power grid", "scada", "substation", "grid", "electric"],
    "telecom": ["telecom", "telco", "sim swap", "5g", "lte", "tower"],
    "airport": ["airport", "aviation", "airline"],
    "ports": ["port", "container terminal", "harbor", "harbour", "dock"],
    "oil": ["refinery", "pipeline", "oil", "gas plant", "petroleum"],
    "other": ["infrastructure", "critical", "india", "system"],
}

ATTACK_ACTIONS = [
    "ddos", "ransomware", "exploit", "breach", "dump", "leak", "deface", "take down",
    "gain access", "initial access", "sell access", "hit", "target",
]

SECURITY_TERMS = [
    "creds", "credentials", "password", "token", "api key", "private key", "panel", "database",
    "vpn", "rdp", "ssh", "admin", "root", "auth bypass", "0day", "zero-day", "cve",
]

NOISE_TOPICS = [
    "football match tonight", "movie release next week", "college fest schedule",
    "best laptop for coding", "anime recommendations", "recipe for biryani",
    "new phone launch", "random memes", "gaming tournament", "weather is nice today",
]

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

def fake_url(i: int) -> str:
    return f"local://synthetic/{i}"

def pick_sector() -> str:
    # bias a bit towards critical sectors used in hackathons
    return RNG.choices(
        SECTORS,
        weights=[1.2, 1.3, 0.9, 1.0, 1.2, 0.7, 0.7, 0.7, 0.5],
        k=1
    )[0]

def sector_phrase(sector: str) -> str:
    return RNG.choice(SECTOR_HINTS.get(sector, ["system"]))

def make_planning(sector: str) -> str:
    when = RNG.choice(["tonight", "tomorrow", "at 2am", "this weekend", "in 3 hours"])
    action = RNG.choice(["ddos", "ransomware", "exploit", "take down", "breach", "dump"])
    target = sector_phrase(sector)
    extras = RNG.choice([
        "need botnet", "have creds", "found exposed admin", "need vuln chain", "buy access", "zero-day ready"
    ])
    return f"planning {action} on {target} {when}. {extras}."

def make_claim(sector: str) -> str:
    action = RNG.choice(["breached", "dumped", "owned", "pwned", "leaked", "exfiltrated"])
    target = sector_phrase(sector)
    proof = RNG.choice([
        "screenshots posted", "sample data uploaded", "hashes available", "db rows shown", "panel screenshot"
    ])
    return f"we {action} {target}. {proof}. DM for details."

def make_leak(sector: str) -> str:
    # obvious fake secrets (safe) but match leak patterns
    style = RNG.choice(["password=", "Authorization: Bearer", "AWS_ACCESS_KEY_ID", "-----BEGIN PRIVATE KEY-----", "mongodb://"])
    target = sector_phrase(sector)

    if style == "password=":
        return f"{target} creds leaked. username=admin password=hunter2 (fake)."
    if style == "Authorization: Bearer":
        return f"{target} API leak: Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.FAKE.SIGNATURE"
    if style == "AWS_ACCESS_KEY_ID":
        return f"{target} config exposed: AWS_ACCESS_KEY_ID=AKIAFAKEFAKEFAKEFAKE AWS_SECRET_ACCESS_KEY=FAKESECRET1234567890"
    if style == "-----BEGIN PRIVATE KEY-----":
        return f"{target} key leaked:\n-----BEGIN PRIVATE KEY-----\nMIIE...FAKE\n-----END PRIVATE KEY-----"
    if style == "mongodb://":
        return f"{target} connection string exposed: mongodb://user:pass@db.example.com:27017/prod"
    return f"{target} leaked token: ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE"

def make_discussion(sector: str) -> str:
    cve = RNG.choice(["CVE-2024-3094", "CVE-2023-34362", "CVE-2021-44228", "CVE-2022-22965"])
    target = sector_phrase(sector)
    q = RNG.choice([
        "anyone tested?", "is this exploitable in prod?", "need mitigation steps",
        "does WAF stop it?", "patch status?", "PoC link?"
    ])
    return f"discussion: {cve} affecting {target}. {q}"

def make_irrelevant() -> str:
    return RNG.choice(NOISE_TOPICS)

def sample_intent_text(label: str, sector: str) -> str:
    if label == "planning":
        return make_planning(sector)
    if label == "claim":
        return make_claim(sector)
    if label == "leak":
        return make_leak(sector)
    if label == "discussion":
        return make_discussion(sector)
    return make_irrelevant()

def write_jsonl(path: Path, rows: List[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

def split_train_val(rows: List[dict], val_ratio: float = 0.15) -> Tuple[List[dict], List[dict]]:
    RNG.shuffle(rows)
    n_val = int(len(rows) * val_ratio)
    return rows[n_val:], rows[:n_val]

def main(total: int = 1000) -> None:
    # Balanced intents: make sure planning/claim/leak are strong
    per_intent = {
        "planning": int(total * 0.30),
        "claim": int(total * 0.20),
        "leak": int(total * 0.25),
        "discussion": int(total * 0.15),
        "irrelevant": total - (int(total * 0.30) + int(total * 0.20) + int(total * 0.25) + int(total * 0.15)),
    }

    intent_rows: List[dict] = []
    sector_rows: List[dict] = []

    idx = 1
    for label, count in per_intent.items():
        for _ in range(count):
            sector = pick_sector()
            text = sample_intent_text(label, sector)

            intent_rows.append({
                "text": text,
                "label": label,
                "created_at": now_iso(),
                "source": "synthetic_chatter",
                "url": fake_url(idx),
            })

            # Sector dataset: ONLY include items that actually reference a sector term
            # If intent is irrelevant, push it to "other" so we don't confuse sector model.
            sector_label = sector if label != "irrelevant" else "other"
            sector_rows.append({
                "text": text,
                "label": sector_label,
                "created_at": now_iso(),
                "source": "synthetic_chatter",
                "url": fake_url(idx),
            })

            idx += 1

    intent_train, intent_val = split_train_val(intent_rows, 0.15)
    sector_train, sector_val = split_train_val(sector_rows, 0.15)

    out_intent_train = Path("ml/data/intent_train.jsonl")
    out_intent_val = Path("ml/data/intent_val.jsonl")
    out_sector_train = Path("ml/data/sector_train.jsonl")
    out_sector_val = Path("ml/data/sector_val.jsonl")

    write_jsonl(out_intent_train, intent_train)
    write_jsonl(out_intent_val, intent_val)
    write_jsonl(out_sector_train, sector_train)
    write_jsonl(out_sector_val, sector_val)

    print("Wrote:")
    print(" -", out_intent_train, len(intent_train))
    print(" -", out_intent_val, len(intent_val))
    print(" -", out_sector_train, len(sector_train))
    print(" -", out_sector_val, len(sector_val))

if __name__ == "__main__":
    main(1000)
