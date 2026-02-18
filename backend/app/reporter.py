from __future__ import annotations
from datetime import datetime, timedelta
from sqlmodel import Session, select
from backend.app.models import Alert, Post

def build_report_context(session: Session, days: int = 7, limit: int = 50) -> dict:
    since = datetime.utcnow() - timedelta(days=days)
    alerts = session.exec(
        select(Alert).where(Alert.created_at >= since).order_by(Alert.score.desc()).limit(limit)
    ).all()

    rows = []
    for a in alerts:
        p = session.get(Post, a.post_id) if a.post_id else None
        rows.append({
            "id": a.id,
            "score": round(a.score, 2),
            "category": a.category,
            "sector": a.sector,
            "intent": a.intent,
            "created_at": a.created_at.isoformat(timespec="seconds"),
            "title": (p.title if p else None) or "(no title)",
            "url": (p.url if p else None),
            "source": (p.source if p else None),
            "reasons": a.score_reasons or {},
        })

    return {
        "generated_at": datetime.utcnow().isoformat(timespec="seconds"),
        "range_days": days,
        "count": len(rows),
        "alerts": rows
    }
