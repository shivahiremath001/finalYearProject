from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
import os

# Default to SQLite local testing instance (as per README)
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./r3p.db")

if SQLALCHEMY_DATABASE_URL.startswith("sqlite"):
    # SQLite doesn't support pool_size and needs check_same_thread=False for FastAPI
    engine = create_engine(
        SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
    )
else:
    engine = create_engine(
        SQLALCHEMY_DATABASE_URL,
        pool_size=20,
        max_overflow=40,
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()
