from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker


DATABASE_URL = "sqlite:///./gateway_logs.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def init_db() -> None:
    from logstore.models import LogEntry

    Base.metadata.create_all(bind=engine)

    # Lightweight schema migration for local SQLite deployments.
    required_columns = {
        "attack_type": "ALTER TABLE logs ADD COLUMN attack_type VARCHAR(32) NOT NULL DEFAULT 'unknown'",
        "incident_status": "ALTER TABLE logs ADD COLUMN incident_status VARCHAR(32) NOT NULL DEFAULT 'NEW'",
        "incident_notes": "ALTER TABLE logs ADD COLUMN incident_notes TEXT NOT NULL DEFAULT ''",
        "updated_at": "ALTER TABLE logs ADD COLUMN updated_at DATETIME DEFAULT CURRENT_TIMESTAMP",
    }

    with engine.begin() as connection:
        existing = {
            row[1]
            for row in connection.execute(text("PRAGMA table_info(logs)")).fetchall()
        }
        for column_name, statement in required_columns.items():
            if column_name not in existing:
                connection.execute(text(statement))


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
