from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker


DATABASE_URL = "sqlite:///./gateway_logs.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def init_db() -> None:
    from logstore.models import LogEntry
    from incidents.models import Incident, IncidentTimelineEvent

    Base.metadata.create_all(bind=engine)

    # Lightweight schema migration for local SQLite deployments.
    required_columns = {
        "attack_type": "ALTER TABLE logs ADD COLUMN attack_type VARCHAR(32) NOT NULL DEFAULT 'unknown'",
        "incident_status": "ALTER TABLE logs ADD COLUMN incident_status VARCHAR(32) NOT NULL DEFAULT 'NEW'",
        "incident_notes": "ALTER TABLE logs ADD COLUMN incident_notes TEXT NOT NULL DEFAULT ''",
        # SQLite does not allow non-constant defaults like CURRENT_TIMESTAMP in
        # ALTER TABLE ADD COLUMN, so we add the column first and backfill later.
        "updated_at": "ALTER TABLE logs ADD COLUMN updated_at DATETIME",
    }

    with engine.begin() as connection:
        existing = {
            row[1]
            for row in connection.execute(text("PRAGMA table_info(logs)")).fetchall()
        }
        for column_name, statement in required_columns.items():
            if column_name not in existing:
                connection.execute(text(statement))

        # Backfill any missing timestamps after the column exists.
        if "updated_at" not in existing:
            connection.execute(
                text(
                    """
                    UPDATE logs
                    SET updated_at = COALESCE(created_at, CURRENT_TIMESTAMP)
                    WHERE updated_at IS NULL
                    """
                )
            )


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
