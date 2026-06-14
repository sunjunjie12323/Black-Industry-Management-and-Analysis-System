from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query
from loguru import logger
from sqlalchemy import func, select, desc, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import User, get_current_user
from app.core.exceptions import AppException
from app.db.database import get_db
from app.db.tables import AuditLogTable

router = APIRouter(prefix="/audit-log", tags=["audit-log"])


def _row_to_dict(row: AuditLogTable) -> dict:
    return {
        "id": row.id,
        "user_id": row.user_id,
        "username": row.username,
        "action": row.action,
        "resource": row.resource,
        "detail": row.detail,
        "ip_address": row.ip_address,
        "user_agent": row.user_agent,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


@router.get("")
async def list_audit_logs(
    offset: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    action: Optional[str] = Query(None, max_length=64),
    user_id: Optional[str] = Query(None, max_length=64),
    username: Optional[str] = Query(None, max_length=64),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    keyword: Optional[str] = Query(None, max_length=200),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    try:
        q = select(AuditLogTable)

        if action:
            q = q.where(AuditLogTable.action == action)
        if user_id:
            q = q.where(AuditLogTable.user_id == user_id)
        if username:
            safe_un = username.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
            q = q.where(AuditLogTable.username.ilike(f"%{safe_un}%", escape='\\'))
        if date_from:
            try:
                df = datetime.fromisoformat(date_from)
                q = q.where(AuditLogTable.created_at >= df)
            except ValueError:
                pass
        if date_to:
            try:
                dt = datetime.fromisoformat(date_to)
                q = q.where(AuditLogTable.created_at <= dt)
            except ValueError:
                pass
        if keyword:
            safe_kw = keyword.replace("%", "\\%").replace("_", "\\_")
            kw = f"%{safe_kw}%"
            q = q.where(
                or_(
                    AuditLogTable.action.ilike(kw),
                    AuditLogTable.resource.ilike(kw),
                    AuditLogTable.detail.ilike(kw),
                    AuditLogTable.username.ilike(kw),
                )
            )

        count_q = select(func.count()).select_from(q.subquery())
        total_result = await db.execute(count_q)
        total = total_result.scalar() or 0

        q = q.order_by(desc(AuditLogTable.created_at)).offset(offset).limit(limit)
        result = await db.execute(q)
        rows = result.scalars().all()

        items = [_row_to_dict(r) for r in rows]
        return {"items": items, "total": total, "offset": offset, "limit": limit}
    except (AppException,):
        raise
    except Exception as exc:
        logger.error(f"List audit logs failed: {exc}")
        raise AppException(detail="获取审计日志列表失败", error_code="DATABASE_ERROR", status_code=500)


@router.get("/statistics")
async def get_audit_log_statistics(
    days: int = Query(30, ge=1, le=90),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    now = datetime.now(timezone.utc)
    try:
        total_result = await db.execute(
            select(func.count()).select_from(AuditLogTable)
        )
        total_count = total_result.scalar() or 0

        by_action_result = await db.execute(
            select(AuditLogTable.action, func.count())
            .group_by(AuditLogTable.action)
            .order_by(func.count().desc())
            .limit(20)
        )
        by_action = {row[0]: row[1] for row in by_action_result.all()}

        by_user_result = await db.execute(
            select(AuditLogTable.username, func.count())
            .where(AuditLogTable.username.isnot(None))
            .group_by(AuditLogTable.username)
            .order_by(func.count().desc())
            .limit(20)
        )
        by_user = {row[0]: row[1] for row in by_user_result.all()}

        recent_result = await db.execute(
            select(func.count()).select_from(AuditLogTable).where(
                AuditLogTable.created_at >= now.replace(
                    hour=0, minute=0, second=0, microsecond=0
                )
            )
        )
        today_count = recent_result.scalar() or 0

        trend_result = await db.execute(
            select(func.date(AuditLogTable.created_at), func.count())
            .where(AuditLogTable.created_at >= now.replace(
                hour=0, minute=0, second=0, microsecond=0
            ).replace(day=1) if now.day <= days else now)
            .group_by(func.date(AuditLogTable.created_at))
            .order_by(func.date(AuditLogTable.created_at))
            .limit(days)
        )
        trend_data = [{"date": str(row[0]), "count": row[1]} for row in trend_result.all()]

        return {
            "total_count": total_count,
            "today_count": today_count,
            "by_action": by_action,
            "by_user": by_user,
            "trend_data": trend_data,
            "days": days,
        }
    except (AppException,):
        raise
    except Exception as exc:
        logger.error(f"Get audit log statistics failed: {exc}")
        raise AppException(detail="获取审计日志统计失败", error_code="DATABASE_ERROR", status_code=500)
