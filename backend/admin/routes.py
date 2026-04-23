from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from admin.service import get_high_risk_logs, get_log_stats, get_paginated_logs
from api.schemas import AdminStatsResponse, PaginatedLogsResponse
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
) -> PaginatedLogsResponse:
    """Return paginated security logs for administrators."""
    return PaginatedLogsResponse(**get_paginated_logs(db, page=page, page_size=page_size))


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
) -> PaginatedLogsResponse:
    """Return only malicious security log entries."""
    return PaginatedLogsResponse(**get_high_risk_logs(db, page=page, page_size=page_size))
