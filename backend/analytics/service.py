from __future__ import annotations

from sqlalchemy import case, func
from sqlalchemy.orm import Session

from logstore.models import LogEntry


def get_attack_trends(db: Session) -> dict:
    """
    Return request volume grouped by day and split by security label.
    """
    day_bucket = func.date(LogEntry.created_at)

    rows = (
        db.query(
            day_bucket.label("day"),
            func.count(LogEntry.id).label("total"),
            func.sum(case((LogEntry.label == "SAFE", 1), else_=0)).label("safe"),
            func.sum(case((LogEntry.label == "SUSPICIOUS", 1), else_=0)).label("suspicious"),
            func.sum(case((LogEntry.label == "MALICIOUS", 1), else_=0)).label("malicious"),
        )
        .group_by(day_bucket)
        .order_by(day_bucket.asc())
        .all()
    )

    return {
        "trends": [
            {
                "date": row.day,
                "total": int(row.total or 0),
                "SAFE": int(row.safe or 0),
                "SUSPICIOUS": int(row.suspicious or 0),
                "MALICIOUS": int(row.malicious or 0),
            }
            for row in rows
        ]
    }


def get_attack_distribution(db: Session) -> dict:
    """
    Return percentage distribution for SAFE / SUSPICIOUS / MALICIOUS labels.
    """
    total = db.query(func.count(LogEntry.id)).scalar() or 0

    rows = (
        db.query(LogEntry.label, func.count(LogEntry.id).label("count"))
        .group_by(LogEntry.label)
        .all()
    )

    counts = {label: int(count) for label, count in rows}

    def percentage(label: str) -> float:
        if total == 0:
            return 0.0
        return round((counts.get(label, 0) / total) * 100, 2)

    return {
        "total": int(total),
        "distribution": {
            "SAFE": {
                "count": counts.get("SAFE", 0),
                "percentage": percentage("SAFE"),
            },
            "SUSPICIOUS": {
                "count": counts.get("SUSPICIOUS", 0),
                "percentage": percentage("SUSPICIOUS"),
            },
            "MALICIOUS": {
                "count": counts.get("MALICIOUS", 0),
                "percentage": percentage("MALICIOUS"),
            },
        },
    }


def get_top_attack_types(db: Session) -> dict:
    """
    Infer high-level attack categories from stored analysis reasons.

    Since the current schema does not persist an explicit attack type, this
    function classifies logs using the detector names recorded in `reason`.
    """
    rows = (
        db.query(
            func.sum(
                case((func.lower(LogEntry.reason).contains("prompt_injection"), 1), else_=0)
            ).label("prompt_injection"),
            func.sum(
                case((func.lower(LogEntry.reason).contains("jailbreak"), 1), else_=0)
            ).label("jailbreak"),
            func.sum(
                case((func.lower(LogEntry.reason).contains("data_leakage"), 1), else_=0)
            ).label("data_leak"),
        )
        .one()
    )

    attack_counts = {
        "prompt_injection": int(rows.prompt_injection or 0),
        "jailbreak": int(rows.jailbreak or 0),
        "data_leak": int(rows.data_leak or 0),
    }

    sorted_types = sorted(attack_counts.items(), key=lambda item: item[1], reverse=True)

    return {
        "attack_types": [
            {"type": attack_type, "count": count}
            for attack_type, count in sorted_types
        ]
    }


def get_risk_distribution(db: Session) -> dict:
    """
    Return a histogram of risk scores using 20-point buckets.
    """
    bucket = case(
        (LogEntry.risk_score <= 20, "0-20"),
        (LogEntry.risk_score <= 40, "21-40"),
        (LogEntry.risk_score <= 60, "41-60"),
        (LogEntry.risk_score <= 80, "61-80"),
        else_="81-100",
    )

    rows = (
        db.query(bucket.label("range"), func.count(LogEntry.id).label("count"))
        .group_by(bucket)
        .all()
    )

    counts = {row.range: int(row.count) for row in rows}
    ordered_ranges = ["0-20", "21-40", "41-60", "61-80", "81-100"]

    return {
        "histogram": [
            {"range": score_range, "count": counts.get(score_range, 0)}
            for score_range in ordered_ranges
        ]
    }
