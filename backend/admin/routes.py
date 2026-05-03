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
    IncidentUpdateRequest,
    LogResponse,
    PaginatedLogsResponse,
)
from auth.auth_handler import get_admin_user
from auth.models import UserInDB
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
