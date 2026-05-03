from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from analytics.service import (
    get_attack_distribution,
    get_attack_trends,
    get_risk_distribution,
    get_top_attack_types,
)
from logstore.models import LogEntry


VALID_INCIDENT_STATUSES = {"NEW", "INVESTIGATING", "ESCALATED", "RESOLVED", "FALSE_POSITIVE"}


def get_paginated_logs(
    db: Session,
    page: int = 1,
    page_size: int = 10,
    label: str | None = None,
    incident_status: str | None = None,
    attack_type: str | None = None,
    search: str | None = None,
    min_risk: int | None = None,
    max_risk: int | None = None,
) -> dict:
    safe_page = max(page, 1)
    safe_page_size = max(1, min(page_size, 100))

    query = db.query(LogEntry)
    query = _apply_log_filters(
        query,
        label=label,
        incident_status=incident_status,
        attack_type=attack_type,
        search=search,
        min_risk=min_risk,
        max_risk=max_risk,
    )

    total = query.with_entities(func.count(LogEntry.id)).scalar() or 0
    items = (
        query
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


def get_high_risk_logs(
    db: Session,
    page: int = 1,
    page_size: int = 10,
    incident_status: str | None = None,
    search: str | None = None,
) -> dict:
    safe_page = max(page, 1)
    safe_page_size = max(1, min(page_size, 100))

    query = db.query(LogEntry).filter(LogEntry.label == "MALICIOUS")
    query = _apply_log_filters(
        query,
        incident_status=incident_status,
        search=search,
    )
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


def get_soc_analytics(db: Session) -> dict:
    return {
        "trends": get_attack_trends(db)["trends"],
        "distribution": get_attack_distribution(db),
        "attack_types": get_top_attack_types(db)["attack_types"],
        "histogram": get_risk_distribution(db)["histogram"],
    }


def update_incident_status(
    db: Session,
    log_id: int,
    incident_status: str,
    incident_notes: str = "",
) -> LogEntry:
    normalized_status = incident_status.strip().upper()
    if normalized_status not in VALID_INCIDENT_STATUSES:
        raise ValueError(
            "Invalid incident status. Use NEW, INVESTIGATING, ESCALATED, RESOLVED, or FALSE_POSITIVE."
        )

    log_entry = db.query(LogEntry).filter(LogEntry.id == log_id).first()
    if log_entry is None:
        raise ValueError(f"Log entry {log_id} not found.")

    log_entry.incident_status = normalized_status
    log_entry.incident_notes = incident_notes.strip()
    db.commit()
    db.refresh(log_entry)
    return log_entry


def _apply_log_filters(
    query,
    label: str | None = None,
    incident_status: str | None = None,
    attack_type: str | None = None,
    search: str | None = None,
    min_risk: int | None = None,
    max_risk: int | None = None,
):
    if label:
        query = query.filter(LogEntry.label == label.strip().upper())
    if incident_status:
        query = query.filter(LogEntry.incident_status == incident_status.strip().upper())
    if attack_type:
        query = query.filter(LogEntry.attack_type == attack_type.strip().lower())
    if search:
        search_term = f"%{search.strip()}%"
        query = query.filter(
            or_(
                LogEntry.user_input.ilike(search_term),
                LogEntry.reason.ilike(search_term),
                LogEntry.incident_notes.ilike(search_term),
            )
        )
    if min_risk is not None:
        query = query.filter(LogEntry.risk_score >= min_risk)
    if max_risk is not None:
        query = query.filter(LogEntry.risk_score <= max_risk)
    return query
