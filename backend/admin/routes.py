from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from admin.service import (
    get_high_risk_logs,
    get_log_stats,
    get_paginated_logs,
    get_soc_analytics,
    update_incident_status,
)
from api.schemas import (
    AdminAnalyticsResponse,
    AdminStatsResponse,
    IncidentPatchRequest,
    IncidentResponse,
    IncidentTimelineResponse,
    IncidentUpdateRequest,
    LogResponse,
    PaginatedIncidentsResponse,
    PaginatedLogsResponse,
)
from auth.auth_handler import get_admin_user
from auth.models import UserInDB
from incidents.service import (
    get_incident_by_id,
    get_incident_timeline,
    list_incidents,
    update_incident,
)
from logstore.db import get_db


router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/logs", response_model=PaginatedLogsResponse)
def list_admin_logs(
    _: UserInDB = Depends(get_admin_user),
    db: Session = Depends(get_db),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=10, ge=1, le=100),
    label: str | None = Query(default=None),
    incident_status: str | None = Query(default=None),
    attack_type: str | None = Query(default=None),
    search: str | None = Query(default=None),
    min_risk: int | None = Query(default=None, ge=0, le=100),
    max_risk: int | None = Query(default=None, ge=0, le=100),
) -> PaginatedLogsResponse:
    """Return paginated security logs for administrators."""
    return PaginatedLogsResponse(
        **get_paginated_logs(
            db,
            page=page,
            page_size=page_size,
            label=label,
            incident_status=incident_status,
            attack_type=attack_type,
            search=search,
            min_risk=min_risk,
            max_risk=max_risk,
        )
    )


@router.get("/stats", response_model=AdminStatsResponse)
def get_admin_stats(
    _: UserInDB = Depends(get_admin_user),
    db: Session = Depends(get_db),
) -> AdminStatsResponse:
    """Return aggregate security statistics for admin dashboards."""
    return AdminStatsResponse(**get_log_stats(db))


@router.get("/high-risk", response_model=PaginatedLogsResponse)
def list_high_risk_logs(
    _: UserInDB = Depends(get_admin_user),
    db: Session = Depends(get_db),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=10, ge=1, le=100),
    incident_status: str | None = Query(default=None),
    search: str | None = Query(default=None),
) -> PaginatedLogsResponse:
    """Return only malicious security log entries."""
    return PaginatedLogsResponse(
        **get_high_risk_logs(
            db,
            page=page,
            page_size=page_size,
            incident_status=incident_status,
            search=search,
        )
    )


@router.get("/analytics", response_model=AdminAnalyticsResponse)
def get_admin_analytics(
    _: UserInDB = Depends(get_admin_user),
    db: Session = Depends(get_db),
) -> AdminAnalyticsResponse:
    """Return SOC-style analytics for charts and investigations."""
    return AdminAnalyticsResponse(**get_soc_analytics(db))


@router.patch("/incidents/{log_id}", response_model=LogResponse)
def update_log_incident(
    log_id: int,
    payload: IncidentUpdateRequest,
    _: UserInDB = Depends(get_admin_user),
    db: Session = Depends(get_db),
) -> LogResponse:
    """Update incident review status and notes for a security log."""
    return update_incident_status(
        db,
        log_id=log_id,
        incident_status=payload.incident_status,
        incident_notes=payload.incident_notes,
    )


@router.get("/incidents", response_model=PaginatedIncidentsResponse)
def list_admin_incidents(
    _: UserInDB = Depends(get_admin_user),
    db: Session = Depends(get_db),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=10, ge=1, le=100),
    status: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    attack_type: str | None = Query(default=None),
    assignee: str | None = Query(default=None),
    search: str | None = Query(default=None),
) -> PaginatedIncidentsResponse:
    """Return paginated SOC incidents for analyst workflows."""
    return PaginatedIncidentsResponse(
        **list_incidents(
            db,
            page=page,
            page_size=page_size,
            status=status,
            severity=severity,
            attack_type=attack_type,
            assignee=assignee,
            search=search,
        )
    )


@router.get("/incidents/{incident_id}", response_model=IncidentResponse)
def get_admin_incident(
    incident_id: int,
    _: UserInDB = Depends(get_admin_user),
    db: Session = Depends(get_db),
) -> IncidentResponse:
    """Return a single incident by id."""
    return get_incident_by_id(db, incident_id)


@router.patch("/incidents/{incident_id}", response_model=IncidentResponse)
def patch_admin_incident(
    incident_id: int,
    payload: IncidentPatchRequest,
    current_user: UserInDB = Depends(get_admin_user),
    db: Session = Depends(get_db),
) -> IncidentResponse:
    """Update incident ownership, severity, notes, or resolution state."""
    return update_incident(
        db,
        incident_id=incident_id,
        status=payload.status,
        severity=payload.severity,
        assignee=payload.assignee,
        notes=payload.notes,
        actor=current_user.username,
    )


@router.get("/incidents/{incident_id}/timeline", response_model=IncidentTimelineResponse)
def get_admin_incident_timeline(
    incident_id: int,
    _: UserInDB = Depends(get_admin_user),
    db: Session = Depends(get_db),
) -> IncidentTimelineResponse:
    """Return the full timeline for a single incident."""
    return IncidentTimelineResponse(
        incident_id=incident_id,
        events=get_incident_timeline(db, incident_id),
    )
