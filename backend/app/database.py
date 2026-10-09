"""
Database setup for the forensic MVP.

Per spec section 7: "If there is no database, use SQLite for the MVP."
This project has no pre-existing backend/database, so we use SQLite via
SQLAlchemy. The DB file lives next to the backend so it's easy to find,
inspect (e.g. with `sqlite3 forensics.db`), or wipe between demos.
"""

import os
from sqlalchemy import create_engine, inspect, text, event
from sqlalchemy.orm import sessionmaker, declarative_base

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.environ.get("FORENSICS_DB_PATH", os.path.join(BACKEND_DIR, "forensics.db"))
DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False, "timeout": 15},  # needed for SQLite + FastAPI
)

# Enable Write-Ahead Logging (WAL) and busy timeout to avoid database lock contention
@event.listens_for(engine, "connect")
def _set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL;")
    cursor.execute("PRAGMA synchronous=NORMAL;")
    cursor.execute("PRAGMA busy_timeout=5000;")
    cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def init_db():
    """Create tables and apply local SQLite compatibility migrations."""
    from app import models  # noqa: F401  (ensure models are registered)
    Base.metadata.create_all(bind=engine)

    columns = {column["name"] for column in inspect(engine).get_columns("events")}
    with engine.begin() as connection:
        if "operating_system" not in columns:
            connection.execute(text("ALTER TABLE events ADD COLUMN operating_system VARCHAR"))
            connection.execute(text("CREATE INDEX IF NOT EXISTS ix_events_operating_system ON events (operating_system)"))
        if "evidence_hash" not in columns:
            connection.execute(text("ALTER TABLE events ADD COLUMN evidence_hash VARCHAR"))
            connection.execute(text("CREATE INDEX IF NOT EXISTS ix_events_evidence_hash ON events (evidence_hash)"))
        if "previous_hash" not in columns:
            connection.execute(text("ALTER TABLE events ADD COLUMN previous_hash VARCHAR"))

    _backfill_operating_system()


def _backfill_operating_system():
    """Classify legacy rows without touching raw evidence or existing scores."""
    from app.filtering import infer_operating_system
    from app.models import Event

    db = SessionLocal()
    try:
        rows = db.query(Event).filter(Event.operating_system.is_(None)).all()
        for row in rows:
            inferred = infer_operating_system(
                log_source=row.log_source,
                provider=row.provider,
                data_origin=row.data_origin,
                raw_data=row.raw_data,
            )
            if inferred:
                row.operating_system = inferred
        db.commit()
    finally:
        db.close()


def get_db():
    """FastAPI dependency: yields a DB session and always closes it."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
