from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from math import ceil
import re

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from alerts.notifier import notify_incident
from incidents.models import Incident, IncidentTimelineEvent
from logstore.models import LogEntry


VALID_INCIDENT_STATUSES = {"NEW", "INVESTIGATING", "ESCALATED", "RESOLVED", "FALSE_POSITIVE"}
VALID_SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def create_or_update_incident_for_log(db: Session, log_entry: LogEntry) -> tuple[Incident | None, dict | None]:
    """
    Create a new incident for malicious log entries and escalate repeat attacks.

    The gateway treats log rows as evidence and incidents as higher-level SOC
    cases. SAFE and SUSPICIOUS prompts do not auto-create incidents.
    """
    if log_entry.label != "MALICIOUS":
        return None, None

    existing = db.query(Incident).filter(Incident.source_log_id == log_entry.id).first()
    if existing is not None:
        return existing, None

    repeated_count = _count_similar_malicious_patterns(
        db,
        prompt=log_entry.user_input,
        attack_type=log_entry.attack_type,
        exclude_log_id=log_entry.id,
    )
    severity = determine_severity(
        risk_score=log_entry.risk_score,
        label=log_entry.label,
        repeated_count=repeated_count,
    )
    status = "ESCALATED" if repeated_count >= 2 else "NEW"

    incident = Incident(
        source_log_id=log_entry.id,
        prompt_summary=summarize_prompt(log_entry.user_input),
        attack_type=log_entry.attack_type,
        label=log_entry.label,
        risk_score=log_entry.risk_score,
        severity=severity,
        status=status,
        notes=log_entry.reason,
        repeated_count=repeated_count,
    )
    db.add(incident)
    db.flush()

    _add_timeline_event(
        db,
        incident_id=incident.id,
        event_type="CREATED",
        actor="system",
        new_status=incident.status,
        new_severity=incident.severity,
        notes=f"Incident opened from log {log_entry.id}.",
    )

    if repeated_count >= 2:
        _add_timeline_event(
            db,
            incident_id=incident.id,
            event_type="AUTO_ESCALATED",
            actor="system",
            new_status="ESCALATED",
            new_severity=incident.severity,
            notes=f"Repeated malicious pattern seen {repeated_count} times in historical logs.",
        )

    alert_payload = notify_incident(incident)
    incident.alert_count = len(alert_payload["alerts"])
    _add_timeline_event(
        db,
        incident_id=incident.id,
        event_type="ALERT_DISPATCHED",
        actor="system",
        new_status=incident.status,
        new_severity=incident.severity,
        notes="Generated email and Slack-style alert payloads.",
    )

    log_entry.incident_status = incident.status
    log_entry.incident_notes = incident.notes
    db.commit()
    db.refresh(incident)
    return incident, alert_payload


def list_incidents(
    db: Session,
    page: int = 1,
    page_size: int = 10,
    status: str | None = None,
    severity: str | None = None,
    attack_type: str | None = None,
    assignee: str | None = None,
    search: str | None = None,
) -> dict:
    safe_page = max(page, 1)
    safe_page_size = max(1, min(page_size, 100))

    query = db.query(Incident)
    query = _apply_incident_filters(
        query,
        status=status,
        severity=severity,
        attack_type=attack_type,
        assignee=assignee,
        search=search,
    )

    total = query.with_entities(func.count(Incident.id)).scalar() or 0
    items = (
        query.order_by(Incident.created_at.desc(), Incident.id.desc())
        .offset((safe_page - 1) * safe_page_size)
        .limit(safe_page_size)
        .all()
    )

    return {
        "items": items,
        "page": safe_page,
        "page_size": safe_page_size,
        "total": total,
        "total_pages": ceil(total / safe_page_size) if total else 0,
    }


def get_incident_by_id(db: Session, incident_id: int) -> Incident:
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if incident is None:
        raise ValueError(f"Incident {incident_id} not found.")
    return incident


def get_incident_timeline(db: Session, incident_id: int) -> list[IncidentTimelineEvent]:
    get_incident_by_id(db, incident_id)
    return (
        db.query(IncidentTimelineEvent)
        .filter(IncidentTimelineEvent.incident_id == incident_id)
        .order_by(IncidentTimelineEvent.created_at.asc(), IncidentTimelineEvent.id.asc())
        .all()
    )


def update_incident(
    db: Session,
    incident_id: int,
    status: str | None = None,
    severity: str | None = None,
    assignee: str | None = None,
    notes: str | None = None,
    actor: str = "admin",
) -> Incident:
    incident = get_incident_by_id(db, incident_id)

    previous_status = incident.status
    previous_severity = incident.severity
    previous_assignee = incident.assignee

    if status is not None:
        normalized_status = status.strip().upper()
        if normalized_status not in VALID_INCIDENT_STATUSES:
            raise ValueError("Invalid incident status.")
        incident.status = normalized_status

    if severity is not None:
        normalized_severity = severity.strip().upper()
        if normalized_severity not in VALID_SEVERITIES:
            raise ValueError("Invalid incident severity.")
        incident.severity = normalized_severity

    if assignee is not None:
        incident.assignee = assignee.strip()

    if notes is not None:
        incident.notes = notes.strip()

    if incident.status == "RESOLVED":
        incident.resolved_at = datetime.now(timezone.utc)
    elif status is not None:
        incident.resolved_at = None

    if incident.status != previous_status or incident.severity != previous_severity:
        _add_timeline_event(
            db,
            incident_id=incident.id,
            event_type="STATUS_UPDATED",
            actor=actor,
            previous_status=previous_status,
            new_status=incident.status,
            previous_severity=previous_severity,
            new_severity=incident.severity,
            notes=incident.notes,
        )

    if assignee is not None and incident.assignee != previous_assignee:
        _add_timeline_event(
            db,
            incident_id=incident.id,
            event_type="ASSIGNED",
            actor=actor,
            new_status=incident.status,
            new_severity=incident.severity,
            notes=f"Assigned to {incident.assignee or 'unassigned'}.",
        )

    source_log = db.query(LogEntry).filter(LogEntry.id == incident.source_log_id).first()
    if source_log is not None:
        source_log.incident_status = incident.status
        source_log.incident_notes = incident.notes

    db.commit()
    db.refresh(incident)
    return incident


def determine_severity(risk_score: int, label: str, repeated_count: int = 0) -> str:
    if label == "MALICIOUS":
        severity = "HIGH" if risk_score < 80 else "CRITICAL"
    elif label == "SUSPICIOUS":
        severity = "MEDIUM"
    else:
        severity = "LOW"

    if repeated_count >= 2:
        severity = _bump_severity(severity)
    if repeated_count >= 4:
        severity = _bump_severity(severity)
    return severity


def summarize_prompt(prompt: str, max_length: int = 180) -> str:
    compact = " ".join(prompt.split())
    if len(compact) <= max_length:
        return compact
    return f"{compact[: max_length - 3]}..."


def _count_similar_malicious_patterns(
    db: Session,
    prompt: str,
    attack_type: str,
    exclude_log_id: int | None = None,
) -> int:
    query = db.query(LogEntry).filter(LogEntry.label == "MALICIOUS")
    if attack_type and attack_type != "unknown":
        query = query.filter(LogEntry.attack_type == attack_type)
    if exclude_log_id is not None:
        query = query.filter(LogEntry.id != exclude_log_id)

    candidates = query.order_by(LogEntry.created_at.desc()).limit(100).all()
    base_tokens = _tokenize(prompt)
    if not base_tokens:
        return 0

    similar = 0
    for candidate in candidates:
        score = _jaccard_similarity(base_tokens, _tokenize(candidate.user_input))
        if score >= 0.45:
            similar += 1
    return similar


def _apply_incident_filters(
    query,
    status: str | None = None,
    severity: str | None = None,
    attack_type: str | None = None,
    assignee: str | None = None,
    search: str | None = None,
):
    if status:
        query = query.filter(Incident.status == status.strip().upper())
    if severity:
        query = query.filter(Incident.severity == severity.strip().upper())
    if attack_type:
        query = query.filter(Incident.attack_type == attack_type.strip().lower())
    if assignee:
        query = query.filter(Incident.assignee.ilike(f"%{assignee.strip()}%"))
    if search:
        term = f"%{search.strip()}%"
        query = query.filter(
            or_(
                Incident.prompt_summary.ilike(term),
                Incident.notes.ilike(term),
                Incident.attack_type.ilike(term),
            )
        )
    return query


def _add_timeline_event(
    db: Session,
    incident_id: int,
    event_type: str,
    actor: str,
    previous_status: str | None = None,
    new_status: str | None = None,
    previous_severity: str | None = None,
    new_severity: str | None = None,
    notes: str = "",
) -> None:
    db.add(
        IncidentTimelineEvent(
            incident_id=incident_id,
            event_type=event_type,
            previous_status=previous_status,
            new_status=new_status,
            previous_severity=previous_severity,
            new_severity=new_severity,
            actor=actor,
            notes=notes,
        )
    )


def _bump_severity(severity: str) -> str:
    order = list(VALID_SEVERITIES)
    current_index = order.index(severity)
    return order[min(current_index + 1, len(order) - 1)]


def _tokenize(text: str) -> set[str]:
    tokens = re.findall(r"[a-zA-Z0-9_]{3,}", text.lower())
    counts = Counter(tokens)
    # Lightweight keyword emphasis: repeated words often indicate the same attack pattern.
    return {token for token, count in counts.items() if count >= 1}


def _jaccard_similarity(left: set[str], right: set[str]) -> float:
    if not left or not right:
        return 0.0
    union = left | right
    if not union:
        return 0.0
    return len(left & right) / len(union)
