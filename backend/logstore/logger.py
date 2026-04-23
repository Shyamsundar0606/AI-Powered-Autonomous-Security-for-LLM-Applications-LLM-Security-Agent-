from math import ceil

from sqlalchemy.orm import Session

from logstore.models import LogEntry


def log_request(db: Session, data: dict) -> LogEntry:
    log_entry = LogEntry(
        user_input=data["user_input"],
        risk_score=data["risk_score"],
        label=data["label"],
        reason=data["reason"],
    )
    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)
    return log_entry


def get_logs(db: Session, page: int = 1, page_size: int = 10) -> dict:
    safe_page = max(page, 1)
    safe_page_size = max(1, min(page_size, 100))

    total = db.query(LogEntry).count()
    entries = (
        db.query(LogEntry)
        .order_by(LogEntry.created_at.desc(), LogEntry.id.desc())
        .offset((safe_page - 1) * safe_page_size)
        .limit(safe_page_size)
        .all()
    )

    return {
        "items": entries,
        "page": safe_page,
        "page_size": safe_page_size,
        "total": total,
        "total_pages": ceil(total / safe_page_size) if total else 0,
    }
