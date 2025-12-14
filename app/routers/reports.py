"""
Content reporting endpoints (Phase 4).
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
import uuid

from app.database import get_db
from app.models import ContentReport, User
from app.schemas.report import (
    ReportSubmitRequest,
    ReportResponse,
    ReportReviewRequest,
    ReportListResponse,
    ReportListItem,
    UnlockUserResponse
)
from app.dependencies.rbac import require_roles
from app.services.reports import check_auto_lock, unlock_user


router = APIRouter(prefix="/reports", tags=["reports"])


@router.post("", response_model=ReportResponse, status_code=201)
async def submit_report(
    request: ReportSubmitRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["contributor", "curator", "admin"]))
) -> ReportResponse:
    """
    Submit a content report (contributor+ only).
    
    Reports target specific edits from Library Service edit_history.
    Automatically checks for auto-lock threshold (10+ distinct trusted reporters).
    
    Requires:
    - Role: contributor, curator, or admin
    - Trust score: >= 10 (contributor threshold)
    """
    # Check trust score (contributor threshold)
    if current_user.trust_score < 10:
        raise HTTPException(
            status_code=403,
            detail="Insufficient trust score to submit reports (need >= 10)"
        )
    
    # Check for duplicate report on same edit
    stmt = select(ContentReport).where(
        ContentReport.reporter_id == current_user.id,
        ContentReport.target["edit_id"].as_string() == str(request.target.edit_id),
        ContentReport.status.in_(["pending", "approved"])
    )
    result = await db.execute(stmt)
    existing = result.scalar_one_or_none()
    
    if existing:
        raise HTTPException(
            status_code=409,
            detail="You have already reported this edit"
        )
    
    # Create report
    report = ContentReport(
        id=uuid.uuid4(),
        reporter_id=current_user.id,
        target=request.target.model_dump(mode='json'),  # Serialize UUIDs to strings
        reason=request.reason,
        category=request.category,
        status="pending"
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)
    
    # Check auto-lock threshold
    await check_auto_lock(db, request.target.actor_id)
    
    return report


@router.get("", response_model=ReportListResponse)
async def list_reports(
    status: str | None = Query(None, pattern="^(pending|approved|rejected)$"),
    category: str | None = Query(None, pattern="^(spam|inappropriate|vandalism|copyright|other)$"),
    actor_id: uuid.UUID | None = None,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["admin"]))
) -> ReportListResponse:
    """
    List all reports with filters (admin only).
    
    Filters:
    - status: pending, approved, or rejected
    - category: spam, inappropriate, vandalism, copyright, other
    - actor_id: UUID of user being reported
    """
    # Build query
    stmt = select(ContentReport).order_by(ContentReport.created_at.desc())
    
    if status:
        stmt = stmt.where(ContentReport.status == status)
    if category:
        stmt = stmt.where(ContentReport.category == category)
    if actor_id:
        stmt = stmt.where(
            ContentReport.target["actor_id"].as_string() == str(actor_id)
        )
    
    # Count total
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total_result = await db.execute(count_stmt)
    total = total_result.scalar_one()
    
    # Apply pagination
    stmt = stmt.limit(limit).offset(offset)
    result = await db.execute(stmt)
    reports = result.scalars().all()
    
    return ReportListResponse(
        items=[ReportListItem.model_validate(r) for r in reports],
        total=total,
        limit=limit,
        offset=offset
    )


@router.post("/{report_id}/review", response_model=ReportResponse)
async def review_report(
    report_id: uuid.UUID,
    request: ReportReviewRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["admin"]))
) -> ReportResponse:
    """
    Review a report: approve or reject (admin only).
    
    - Approved reports count toward auto-lock threshold
    - Rejected reports do not count (false reports excluded)
    - Automatically checks for auto-lock after approval
    """
    report = await db.get(ContentReport, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    if report.status != "pending":
        raise HTTPException(
            status_code=409,
            detail=f"Report already reviewed (status: {report.status})"
        )
    
    # Update report
    from datetime import datetime, timezone
    status_map = {"approve": "approved", "reject": "rejected"}
    report.status = status_map[request.action]
    report.reviewed_by = current_user.id
    report.reviewed_at = datetime.now(timezone.utc)
    report.review_notes = request.notes
    
    await db.commit()
    await db.refresh(report)
    
    # Check auto-lock if approved
    if request.action == "approve":
        actor_id = uuid.UUID(report.target["actor_id"])
        await check_auto_lock(db, actor_id, admin_id=current_user.id)
    
    return report


@router.post("/users/{user_id}/unlock", response_model=UnlockUserResponse)
async def unlock_user_endpoint(
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["admin"]))
) -> UnlockUserResponse:
    """
    Unlock a user (admin only).
    
    Clears is_locked flag and recalculates roles based on trust score.
    Creates audit trail in trust_history.
    """
    try:
        await unlock_user(db, user_id, current_user.id)
        
        # Get updated user
        user = await db.get(User, user_id)
        
        return UnlockUserResponse(
            user_id=user_id,
            is_locked=user.is_locked if user else False,
            message="User unlocked successfully"
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
