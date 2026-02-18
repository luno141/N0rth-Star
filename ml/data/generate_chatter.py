# ml/data/generate_chatter.py
from __future__ import annotations

import json
import random
from pathlib import Path
from datetime import datetime

OUT_DIR = Path("ml/data")
OUT_DIR.mkdir(parents=True, exist_ok=True)

SECTORS = ["telecom","banking","upi","power_grid","railways","airport","ports","oil","other"]
INTENTS = ["planning","claim","leak","discussion","irrelevant"]

ATTACK_ACTIONS = [
    "ddos", "ransomware", "exploit", "breach", "dump", "sell access", "creds for sale",
    "0day", "cve", "botnet", "pwn", "owned", "steal", "take down"
]

LEAK_PHRASES = [
    "password=hunter2",
    "Authorization: Bearer ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE",
    "-----BEGIN PRIVATE KEY-----\nMIIE...FAKE\n-----END PRIVATE KEY-----",
    "postgres://user:pass@host:5432/db",
    "api_key=AKIAFAKEFAKEFAKEFAKE"
]

NOISE = [
    "football match tonight was great",
    "anyone playing valorant?",
    "new movie was insane",
    "college fest was lit",
    "need help with linux wifi"
]

def now_iso():
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"

def make_text(intent: str, sector: str) -> str:
    s = sector
    if intent == "planning":
        a = random.choice(ATTACK_ACTIONS)
        return f"planning {a} on {s} systems tonight. target={s}. creds needed."
    if intent == "claim":
        a = random.choice(["breach","dump","owned","leak"])
        return f"we just {a} {s}. proof soon. access confirmed."
    if intent == "leak":
        leak = random.choice(LEAK_PHRASES)
        return f"{s} leak drop: {leak}"
    if intent == "discussion":
        a = random.choice(["cve","exploit","ddos","ransomware","breach"])
        return f"discussion: impact of {a} trends on {s} infrastructure. anyone seen similar?"
    return random.choice(NOISE)

def write_jsonl(path: Path, rows: list[dict]):
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

def stratified_split(rows, val_ratio=0.15, key="label"):
    by = {}
    for r in rows:
        by.setdefault(r[key], []).append(r)
    train, val = [], []
    for k, items in by.items():
        random.shuffle(items)
        n_val = max(1, int(len(items) * val_ratio))
        val.extend(items[:n_val])
        train.extend(items[n_val:])
    random.shuffle(train)
    random.shuffle(val)
    return train, val

def main(n=1000, seed=7):
    random.seed(seed)

    # Intent dataset
    intent_rows = []
    # distribution: more planning/leak/claim than irrelevant
    intent_dist = (
        ["planning"] * 320 +
        ["leak"] * 220 +
        ["claim"] * 180 +
        ["discussion"] * 180 +
        ["irrelevant"] * 100
    )
    intent_dist = intent_dist[:n]
    random.shuffle(intent_dist)

    for i in range(n):
        intent = intent_dist[i]
        sector = random.choice(SECTORS)
        text = make_text(intent, sector)
        intent_rows.append({"text": text, "label": intent, "meta": {"sector_hint": sector, "created_at": now_iso()}})

    intent_train, intent_val = stratified_split(intent_rows, val_ratio=0.15, key="label")
    write_jsonl(OUT_DIR / "intent_train.jsonl", intent_train)
    write_jsonl(OUT_DIR / "intent_val.jsonl", intent_val)

    # Sector dataset (multi-label style can be added later; for now single-label)
    sector_rows = []
    for i in range(n):
        sector = random.choice(SECTORS)
        intent = random.choice(["planning","leak","discussion","irrelevant"])
        text = make_text(intent, sector)
        sector_rows.append({"text": text, "label": sector, "meta": {"intent_hint": intent, "created_at": now_iso()}})

    sector_train, sector_val = stratified_split(sector_rows, val_ratio=0.15, key="label")
    write_jsonl(OUT_DIR / "sector_train.jsonl", sector_train)
    write_jsonl(OUT_DIR / "sector_val.jsonl", sector_val)

    print("Wrote:")
    print(" - ml/data/intent_train.jsonl", len(intent_train))
    print(" - ml/data/intent_val.jsonl", len(intent_val))
    print(" - ml/data/sector_train.jsonl", len(sector_train))
    print(" - ml/data/sector_val.jsonl", len(sector_val))

if __name__ == "__main__":
    main(n=1000, seed=7)
