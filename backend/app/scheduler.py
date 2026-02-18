import json
from pathlib import Path
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from sqlmodel import Session

from backend.app.db import engine
from backend.app.pipeline_store import upsert_post_and_alert

DEMO_FEED_PATH = Path("backend/app/demo_feed.json")

scheduler = BackgroundScheduler()

def _parse_dt(s: str | None):
    if not s:
        return None
    return datetime.fromisoformat(s.replace("Z", "+00:00")).replace(tzinfo=None)

def ingest_demo_feed_once() -> dict:
    """
    Reads demo_feed.json and ingests any new posts (dedup via hash).
    Returns stats.
    """
    if not DEMO_FEED_PATH.exists():
        return {"ok": False, "error": f"missing {DEMO_FEED_PATH}"}

    data = json.loads(DEMO_FEED_PATH.read_text(encoding="utf-8"))
    inserted_posts = 0
    created_alerts = 0

    with Session(engine) as session:
        for item in data:
            source = item.get("source", "demo_forum")
            url = item.get("url", "local://demo")
            title = item.get("title")
            author = item.get("author")
            created_at = _parse_dt(item.get("created_at"))
            text = item.get("text", "")
            vuln_features = item.get("vuln_features")

            post_id, alert_id = upsert_post_and_alert(
                session,
                source=source,
                url=url,
                title=title,
                author=author,
                created_at=created_at,
                text=text,
                vuln_features=vuln_features
            )

            if alert_id is not None:
                inserted_posts += 1
                created_alerts += 1

    return {"ok": True, "inserted_posts": inserted_posts, "created_alerts": created_alerts}

def start_scheduler(interval_seconds: int = 30):
    """
    For hackathon demo, 30s makes it feel real-time.
    Set to 300 for 5 minutes later.
    """
    scheduler.add_job(ingest_demo_feed_once, "interval", seconds=interval_seconds, id="demo_feed_job", replace_existing=True)
    scheduler.start()
