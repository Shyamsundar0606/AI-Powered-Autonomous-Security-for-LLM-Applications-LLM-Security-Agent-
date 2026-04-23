from sqlalchemy import func
from sqlalchemy.orm import Session

from logstore.models import LogEntry


def get_paginated_logs(db: Session, page: int = 1, page_size: int = 10) -> dict:
    safe_page = max(page, 1)
    safe_page_size = max(1, min(page_size, 100))

    total = db.query(func.count(LogEntry.id)).scalar() or 0
    items = (
        db.query(LogEntry)
        .order_by(LogEntry.created_at.desc(), LogEntry.id.desc())
        .offset((safe_page - 1) * safe_page_size)
        .limit(safe_page_size)
        .all()
    )

    total_pages = (total + safe_page_size - 1) // safe_page_size if total else 0
    return {
        "items": items,
        "page": safe_page,
        "page_size": safe_page_size,
        "total": total,
        "total_pages": total_pages,
    }


def get_log_stats(db: Session) -> dict:
    total_requests = db.query(func.count(LogEntry.id)).scalar() or 0
    average_risk_score = db.query(func.avg(LogEntry.risk_score)).scalar()

    label_rows = (
        db.query(LogEntry.label, func.count(LogEntry.id))
        .group_by(LogEntry.label)
        .all()
    )
    label_counts = {label: count for label, count in label_rows}

    return {
        "total_requests": total_requests,
        "labels": {
            "SAFE": label_counts.get("SAFE", 0),
            "SUSPICIOUS": label_counts.get("SUSPICIOUS", 0),
            "MALICIOUS": label_counts.get("MALICIOUS", 0),
        },
        "average_risk_score": round(float(average_risk_score or 0), 2),
    }


def get_high_risk_logs(db: Session, page: int = 1, page_size: int = 10) -> dict:
    safe_page = max(page, 1)
    safe_page_size = max(1, min(page_size, 100))

    query = db.query(LogEntry).filter(LogEntry.label == "MALICIOUS")
    total = query.with_entities(func.count(LogEntry.id)).scalar() or 0
    items = (
        query.order_by(LogEntry.created_at.desc(), LogEntry.id.desc())
        .offset((safe_page - 1) * safe_page_size)
        .limit(safe_page_size)
        .all()
    )

    total_pages = (total + safe_page_size - 1) // safe_page_size if total else 0
    return {
        "items": items,
        "page": safe_page,
        "page_size": safe_page_size,
        "total": total,
        "total_pages": total_pages,
    }
