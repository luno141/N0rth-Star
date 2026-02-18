from __future__ import annotations
from datetime import datetime
from sqlmodel import Session, select
from backend.app.models import Post, Alert, Finding, Entity
import hashlib

from ml.pipeline import build_alert

def _hash(source: str, url: str, text: str) -> str:
    h = hashlib.sha256()
    h.update((source + "||" + url + "||" + text.strip()).encode("utf-8", errors="ignore"))
    return h.hexdigest()

def upsert_post_and_alert(
    session: Session,
    *,
    source: str,
    url: str,
    title: str | None,
    author: str | None,
    created_at: datetime | None,
    text: str,
    vuln_features: dict | None = None
) -> tuple[int, int]:
    h = _hash(source, url, text)
    existing = session.exec(select(Post).where(Post.hash == h)).first()
    if existing:
        # already ingested
        a = session.exec(select(Alert).where(Alert.post_id == existing.id).order_by(Alert.id.desc())).first()
        return existing.id, (a.id if a else -1)

    post = Post(
        source=source,
        url=url,
        title=title,
        author=author,
        created_at=created_at,
        text=text,
        hash=h
    )
    session.add(post)
    session.commit()
    session.refresh(post)

    # run ML + detectors
    alert_obj = build_alert(text, post_meta={
        "source": source,
        "url": url,
        "title": title,
        "author": author,
        "created_at": created_at.isoformat() if created_at else None
    }, vuln_features=vuln_features)

    # findings/entities
    for f in alert_obj.get("findings", []):
        session.add(Finding(
            post_id=post.id,
            type=f["type"],
            confidence=float(f["confidence"]),
            evidence=f["evidence"],
            masked_value=f["masked_value"]
        ))

    for e in alert_obj.get("entities", []):
        session.add(Entity(post_id=post.id, kind=e["kind"], value=e["value"]))

    # alert row
    vuln_risk = alert_obj.get("vuln_risk")
    a = Alert(
        post_id=post.id,
        category=alert_obj["category"],
        sector=alert_obj["sector"],
        intent=alert_obj["intent"]["label"],
        intent_confidence=float(alert_obj["intent"]["confidence"]),
        score=float(alert_obj["score"]),
        score_reasons={"reasons": alert_obj.get("score_reasons", [])},
        status="open",
        created_at=datetime.utcnow(),
        vuln_risk_score=float(vuln_risk["score"]) if vuln_risk else None,
        vuln_risk_method=vuln_risk.get("method") if vuln_risk else None,
    )
    session.add(a)
    session.commit()
    session.refresh(a)

    return post.id, a.id
