from sqlmodel import SQLModel, create_engine, Session
from pathlib import Path
import os

REPO_ROOT = Path(__file__).resolve().parents[2]
default_sqlite_path = REPO_ROOT / "northstar.db"
default_db_url = f"sqlite:///{default_sqlite_path}"

DB_URL = os.getenv("DB_URL", default_db_url)
connect_args = {"check_same_thread": False} if DB_URL.startswith("sqlite") else {}

engine = create_engine(DB_URL, echo=False, connect_args=connect_args)

def init_db() -> None:
    SQLModel.metadata.create_all(engine)

def get_session():
    with Session(engine) as session:
        yield session
