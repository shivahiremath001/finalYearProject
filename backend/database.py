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


def sync_db_schema(engine, base_cls):
    """
    Automatically alters existing SQLite database tables to add any columns 
    defined in SQLAlchemy models that are missing in the database table schema.
    """
    try:
        from sqlalchemy import inspect, text

        inspector = inspect(engine)
        existing_tables = inspector.get_table_names()
        for table_name, table in base_cls.metadata.tables.items():
            if table_name in existing_tables:
                existing_columns = {
                    col["name"] for col in inspector.get_columns(table_name)
                }
                for column in table.columns:
                    if column.name not in existing_columns:
                        col_type = column.type.compile(engine.dialect)
                        default_clause = ""
                        if column.default is not None and column.default.is_scalar:
                            val = column.default.arg
                            if isinstance(val, str):
                                default_clause = f" DEFAULT '{val}'"
                            elif isinstance(val, (int, float, bool)):
                                default_clause = f" DEFAULT {val}"
                        stmt = f'ALTER TABLE "{table_name}" ADD COLUMN "{column.name}" {col_type}{default_clause}'
                        with engine.begin() as conn:
                            conn.execute(text(stmt))
    except Exception as e:
        print(f"Auto schema sync notice: {e}")

