from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, declarative_base
import os

# Use SQLite by default. Override with DATABASE_URL env var for Postgres:
# export DATABASE_URL="postgresql://user:password@localhost/r3p"
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./r3p.db")

if SQLALCHEMY_DATABASE_URL.startswith("sqlite"):
    engine = create_engine(
        SQLALCHEMY_DATABASE_URL,
        connect_args={
            "check_same_thread": False,
            "timeout": 30,          # wait up to 30s for a write lock (handles bursts)
        },
        # Pool settings for 100+ concurrent agents hitting /ingest at once
        pool_size=20,
        max_overflow=40,
    )

    # Enable WAL mode so readers don't block writers and vice versa.
    # This is the single biggest improvement for concurrent SQLite access.
    @event.listens_for(engine, "connect")
    def _set_wal_mode(dbapi_conn, _):
        dbapi_conn.execute("PRAGMA journal_mode=WAL;")
        dbapi_conn.execute("PRAGMA synchronous=NORMAL;")  # safe + faster than FULL

else:
    # PostgreSQL / other — no special args needed; handles concurrency natively
    engine = create_engine(
        SQLALCHEMY_DATABASE_URL,
        pool_size=20,
        max_overflow=40,
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()
