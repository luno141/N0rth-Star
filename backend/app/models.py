from __future__ import annotations
from typing import Optional
from datetime import datetime
from sqlmodel import SQLModel, Field, Column
from sqlalchemy import JSON

class Source(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True, unique=True)
    url: str
    method: str  # rss|html|json
    interval_seconds: int = 300
    enabled: bool = True
    # for html/json parsing
    selector_item: Optional[str] = None
    selector_title: Optional[str] = None
    selector_url: Optional[str] = None
    selector_author: Optional[str] = None
    selector_time: Optional[str] = None
    selector_text: Optional[str] = None
    json_items_path: Optional[str] = None  # e.g. "items" or "data.items"
    json_title_key: Optional[str] = None
    json_url_key: Optional[str] = None
    json_author_key: Optional[str] = None
    json_time_key: Optional[str] = None
    json_text_key: Optional[str] = None

    last_run_at: Optional[datetime] = None
    cursor: Optional[str] = None  # etag/last_modified/last_seen_id etc.

class Post(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    source: str = Field(index=True)
    url: str = Field(index=True)
    title: Optional[str] = None
    author: Optional[str] = None
    created_at: Optional[datetime] = Field(default=None, index=True)
    text: str
    hash: str = Field(index=True, unique=True)

class Finding(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    post_id: int = Field(index=True)
    type: str
    confidence: float
    evidence: str
    masked_value: str

class Entity(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    post_id: int = Field(index=True)
    kind: str
    value: str

class Alert(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    post_id: Optional[int] = Field(default=None, index=True)
    asset_id: Optional[int] = Field(default=None, index=True)

    category: str = Field(index=True)  # leak|attack_chatter|vulnerability|noise|discussion
    sector: str = Field(index=True)
    intent: str = Field(index=True)
    intent_confidence: float

    score: float = Field(index=True)
    score_reasons: dict = Field(default_factory=dict, sa_column=Column(JSON))
    status: str = Field(default="open", index=True)
    created_at: datetime = Field(default_factory=datetime.utcnow, index=True)

    vuln_risk_score: Optional[float] = None
    vuln_risk_method: Optional[str] = None

class Run(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    kind: str = Field(index=True)  # collect|scan
    started_at: datetime = Field(default_factory=datetime.utcnow)
    ended_at: Optional[datetime] = None
    stats_json: dict = Field(default_factory=dict, sa_column=Column(JSON))

# ---------------------------
# Passive scanning (allowlist)
# ---------------------------

class Asset(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    kind: str = Field(default="url", index=True)  # url|ip
    value: str = Field(index=True, unique=True)
    owner: Optional[str] = None
    tags: dict = Field(default_factory=dict, sa_column=Column(JSON))
    active: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)

class ScanFinding(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    asset_id: int = Field(index=True)
    created_at: datetime = Field(default_factory=datetime.utcnow, index=True)
    type: str = Field(index=True)  # missing_header|tls_expiring|server_disclosure|http_redirect etc.
    severity: int = Field(index=True)  # 1..10
    evidence_json: dict = Field(default_factory=dict, sa_column=Column(JSON))
