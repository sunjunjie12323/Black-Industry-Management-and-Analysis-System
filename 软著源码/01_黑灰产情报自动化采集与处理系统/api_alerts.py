import hashlib
import json
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select, delete, or_, and_, cast, Date
from sqlalchemy.ext.asyncio import AsyncSession
from loguru import logger

from app.core.auth import User, get_current_user, require_role, Role
from app.core.exceptions import AppException, NotFoundException, ForbiddenException, ValidationException
from app.db.database import get_db, async_session_factory
from app.db.tables import AnalyzedIntelligenceTable, CleanedIntelligenceTable, AlertRuleTable

router = APIRouter(prefix="/alerts", tags=["alerts"])


class CreateAlertRuleRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=256)
    description: str = Field(default="", max_length=2000)
    conditions: List[Dict[str, Any]] = Field(default_factory=list)
    severity: str = Field(default="high", pattern="^(critical|high|medium|low|info)$")
    is_enabled: bool = Field(default=True)


class UpdateAlertRuleRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=256)
    description: Optional[str] = Field(None, max_length=2000)
    conditions: Optional[List[Dict[str, Any]]] = None
    severity: Optional[str] = Field(None, pattern="^(critical|high|medium|low|info)$")
    is_enabled: Optional[bool] = None


class BatchAcknowledgeRequest(BaseModel):
    alert_ids: List[str] = Field(..., min_length=1, max_length=100)


def _analyzed_to_alert_dict(row) -> dict:
    summary = row.analysis_summary or "威胁情报告警"
    row_id = str(row.id) if row.id else "unknown"
    return {
        "id": row_id,
        "alert_id": f"db-{row_id[:12]}",
        "title": f"[{(row.threat_level or 'unknown').upper()}] {summary[:60]}",
        "severity": row.threat_level or "medium",
        "source": "intelligence_analysis",
        "status": "pending",
        "message": summary,
        "description": summary,
        "created_at": row.analyzed_at.isoformat() if row.analyzed_at else None,
        "triggered_at": row.analyzed_at.isoformat() if row.analyzed_at else None,
        "intelligence_id": row_id,
        "confidence_score": getattr(row, "confidence_score", None),
    }


def _rule_row_to_dict(row) -> dict:
    conditions = []
    try:
        conditions = json.loads(row.conditions_json) if row.conditions_json else []
    except (json.JSONDecodeError, TypeError):
        conditions = []
    return {
        "id": row.id,
        "name": row.name,
        "description": row.description,
        "conditions": conditions,
        "severity": row.severity,
        "is_enabled": row.is_enabled,
        "cooldown_minutes": row.cooldown_minutes,
        "last_triggered": row.last_triggered.isoformat() if row.last_triggered else None,
        "created_by": row.created_by,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


@router.get("/active")
async def get_active_alerts(
    request: Request,
    severity: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
):
    engine = getattr(request.app.state, "alert_engine", None)
    alerts_from_engine = []

    if engine is not None:
        try:
            alerts_from_engine = await engine.get_active_alerts(user_id=current_user.id)
        except Exception as exc:
            logger.warning(f"Alert engine get_active_alerts failed: {exc}")

    if alerts_from_engine:
        if severity:
            alerts_from_engine = [a for a in alerts_from_engine if a.get("severity") == severity]
        return {"alerts": alerts_from_engine, "total": len(alerts_from_engine)}

    try:
        async with async_session_factory() as session:
            stmt = (
                select(AnalyzedIntelligenceTable)
                .join(CleanedIntelligenceTable, AnalyzedIntelligenceTable.cleaned_id == CleanedIntelligenceTable.id)
                .where(AnalyzedIntelligenceTable.threat_level.in_(["critical", "high"]))
            )
            if severity:
                stmt = stmt.where(AnalyzedIntelligenceTable.threat_level == severity)
            stmt = stmt.order_by(AnalyzedIntelligenceTable.analyzed_at.desc()).limit(50)
            result = await session.execute(stmt)
            rows = result.scalars().all()

            if rows:
                alert_items = [_analyzed_to_alert_dict(r) for r in rows]
                logger.info(f"Alerts fallback from DB: {len(alert_items)} records")
                return {"alerts": alert_items, "total": len(alert_items)}
    except Exception as exc:
        logger.warning(f"Alerts DB fallback failed: {exc}")

    return {"alerts": [], "total": 0}


@router.get("/stats")
async def get_alert_stats(request: Request, current_user: User = Depends(get_current_user)):
    engine = getattr(request.app.state, "alert_engine", None)

    if engine is not None:
        stats = engine.get_alert_stats()
        if stats.get("active_alerts", 0) > 0:
            return stats

    try:
        async with async_session_factory() as session:
            critical_count = await session.execute(
                select(func.count()).select_from(AnalyzedIntelligenceTable).where(
                    AnalyzedIntelligenceTable.threat_level == "critical"
                )
            )
            high_count = await session.execute(
                select(func.count()).select_from(AnalyzedIntelligenceTable).where(
                    AnalyzedIntelligenceTable.threat_level == "high"
                )
            )
            medium_count = await session.execute(
                select(func.count()).select_from(AnalyzedIntelligenceTable).where(
                    AnalyzedIntelligenceTable.threat_level == "medium"
                )
            )
            low_count = await session.execute(
                select(func.count()).select_from(AnalyzedIntelligenceTable).where(
                    AnalyzedIntelligenceTable.threat_level == "low"
                )
            )

            c = critical_count.scalar() or 0
            h = high_count.scalar() or 0
            m = medium_count.scalar() or 0
            l = low_count.scalar() or 0
            total_active = c + h

            return {
                "total_alerts": c + h + m + l,
                "active_alerts": total_active,
                "acknowledged": 0,
                "by_severity": {"critical": c, "high": h, "medium": m, "low": l},
                "by_status": {"pending": total_active, "acknowledged": 0},
                "rules_total": len(engine.rules) if engine else 8,
                "rules_enabled": sum(1 for r in engine.rules.values() if r.enabled) if engine else 8,
                "data_source": "database_fallback",
            }
    except Exception as exc:
        logger.warning(f"Alert stats DB fallback failed: {exc}")
        if engine is not None:
            return engine.get_alert_stats()
        return {"total": 0, "by_severity": {}, "by_status": {}, "data_source": "unavailable"}

    return engine.get_alert_stats()


@router.post("/{alert_id}/acknowledge")
async def acknowledge_alert(
    request: Request,
    alert_id: str,
    current_user: User = Depends(get_current_user),
):
    engine = getattr(request.app.state, "alert_engine", None)
    if engine is None:
        raise AppException(detail="Alert engine not available", error_code="SERVICE_NOT_AVAILABLE", status_code=503)

    try:
        if alert_id.startswith("db-"):
            db_id = alert_id[3:]
            try:
                async with async_session_factory() as session:
                    result = await session.execute(
                        select(AnalyzedIntelligenceTable).where(AnalyzedIntelligenceTable.id == db_id)
                    )
                    row = result.scalar_one_or_none()
                    if not row:
                        raise NotFoundException(detail="Alert not found")
                    return {"status": "acknowledged", "message": f"情报 {db_id} 已确认处理"}
            except (AppException, NotFoundException):
                raise
            except Exception as exc:
                logger.warning(f"DB acknowledge failed: {exc}")

        if not await engine.acknowledge_alert(alert_id):
            raise NotFoundException(detail="Alert not found")
        return {"status": "acknowledged"}
    except (AppException, NotFoundException):
        raise
    except Exception as exc:
        logger.error(f"Failed to acknowledge alert: {exc}")
        raise HTTPException(status_code=500, detail=f"确认告警失败: {str(exc)}")


@router.get("/rules")
async def get_alert_rules(request: Request, current_user: User = Depends(get_current_user)):
    engine = getattr(request.app.state, "alert_engine", None)
    if engine is None:
        return {"rules": []}
    return {"rules": [r.to_dict() for r in engine.rules.values()]}


@router.put("/rules/{rule_id}/toggle")
async def toggle_alert_rule(
    request: Request,
    rule_id: str,
    enabled: bool = Query(...),
    current_user: User = Depends(get_current_user),
):
    engine = getattr(request.app.state, "alert_engine", None)
    if engine is None:
        raise AppException(detail="Alert engine not available", error_code="SERVICE_NOT_AVAILABLE", status_code=503)
    if rule_id not in engine.rules:
        raise NotFoundException(detail="Rule not found")
    engine.rules[rule_id].enabled = enabled
    engine._save()
    return {"status": "updated", "enabled": enabled}


@router.post("/test-trigger")
async def test_trigger_alert(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    engine = getattr(request.app.state, "alert_engine", None)
    if engine is None:
        raise AppException(detail="Alert engine not available", error_code="SERVICE_NOT_AVAILABLE", status_code=503)
    test_intel = {
        "id": "test-" + hashlib.md5(datetime.now(timezone.utc).isoformat().encode()).hexdigest()[:8],
        "content": "检测到新的零日漏洞CVE-2025-0001，已被APT组织在暗网出售利用工具",
        "threat_level": "critical",
        "entity_type": "vulnerability",
        "value": "CVE-2025-0001",
    }
    alerts = await engine.evaluate_intelligence(test_intel, skip_cooldown=True)
    return {"triggered_alerts": len(alerts), "alerts": [a.to_dict() for a in alerts]}


@router.post("/rules")
async def create_alert_rule(
    data: CreateAlertRuleRequest,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
    db: AsyncSession = Depends(get_db),
):
    rule_id = uuid.uuid4().hex
    conditions_json = json.dumps(data.conditions, ensure_ascii=False)

    try:
        row = AlertRuleTable(
            id=rule_id,
            name=data.name,
            description=data.description,
            conditions_json=conditions_json,
            severity=data.severity,
            is_enabled=data.is_enabled,
            cooldown_minutes=60,
            created_by=current_user.username,
        )
        db.add(row)
        await db.commit()
    except Exception as exc:
        logger.error(f"Create alert rule failed: {exc}")
        raise AppException(detail="创建告警规则失败", error_code="DATABASE_ERROR", status_code=500)

    engine = getattr(request.app.state, "alert_engine", None)
    if engine is not None:
        from app.core.alert_engine import AlertRule
        engine.rules[rule_id] = AlertRule(
            rule_id=rule_id,
            name=data.name,
            description=data.description,
            conditions=data.conditions if data.conditions else {},
            severity=data.severity,
            enabled=data.is_enabled,
            cooldown_minutes=60,
        )
        engine._save()

    return {
        "status": "created",
        "rule": {
            "id": rule_id,
            "name": data.name,
            "description": data.description,
            "conditions": data.conditions,
            "severity": data.severity,
            "is_enabled": data.is_enabled,
        },
    }


@router.put("/rules/{rule_id}")
async def update_alert_rule(
    rule_id: str,
    data: UpdateAlertRuleRequest,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
    db: AsyncSession = Depends(get_db),
):
    try:
        result = await db.execute(
            select(AlertRuleTable).where(AlertRuleTable.id == rule_id)
        )
        row = result.scalar_one_or_none()
        if not row:
            raise NotFoundException(detail="告警规则不存在")

        if data.name is not None:
            row.name = data.name
        if data.description is not None:
            row.description = data.description
        if data.conditions is not None:
            row.conditions_json = json.dumps(data.conditions, ensure_ascii=False)
        if data.severity is not None:
            row.severity = data.severity
        if data.is_enabled is not None:
            row.is_enabled = data.is_enabled
        row.updated_at = datetime.now(timezone.utc)

        await db.commit()

        updated_rule = _rule_row_to_dict(row)

    except (AppException, NotFoundException):
        raise
    except Exception as exc:
        logger.error(f"Update alert rule failed: {exc}")
        raise AppException(detail="更新告警规则失败", error_code="DATABASE_ERROR", status_code=500)

    engine = getattr(request.app.state, "alert_engine", None)
    if engine is not None and rule_id in engine.rules:
        rule = engine.rules[rule_id]
        if data.name is not None:
            rule.name = data.name
        if data.description is not None:
            rule.description = data.description
        if data.conditions is not None:
            rule.conditions = data.conditions if data.conditions else {}
        if data.severity is not None:
            rule.severity = data.severity
        if data.is_enabled is not None:
            rule.enabled = data.is_enabled
        engine._save()

    return {"status": "updated", "rule": updated_rule}


@router.delete("/rules/{rule_id}")
async def delete_alert_rule(
    rule_id: str,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN)),
    db: AsyncSession = Depends(get_db),
):
    try:
        result = await db.execute(
            select(AlertRuleTable).where(AlertRuleTable.id == rule_id)
        )
        row = result.scalar_one_or_none()
        if not row:
            raise NotFoundException(detail="告警规则不存在")

        await db.delete(row)
        await db.commit()
    except (AppException, NotFoundException):
        raise
    except Exception as exc:
        logger.error(f"Delete alert rule failed: {exc}")
        raise AppException(detail="删除告警规则失败", error_code="DATABASE_ERROR", status_code=500)

    engine = getattr(request.app.state, "alert_engine", None)
    if engine is not None and rule_id in engine.rules:
        del engine.rules[rule_id]
        engine._save()

    return {"status": "deleted", "rule_id": rule_id}


@router.post("/batch-acknowledge")
async def batch_acknowledge_alerts(
    data: BatchAcknowledgeRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    engine = getattr(request.app.state, "alert_engine", None)
    acknowledged = []
    failed = []

    for alert_id in data.alert_ids:
        try:
            if alert_id.startswith("db-"):
                db_id = alert_id[3:]
                result = await db.execute(
                    select(AnalyzedIntelligenceTable).where(AnalyzedIntelligenceTable.id == db_id)
                )
                row = result.scalar_one_or_none()
                if row:
                    acknowledged.append(alert_id)
                else:
                    failed.append({"alert_id": alert_id, "reason": "未找到"})
            elif engine is not None:
                if await engine.acknowledge_alert(alert_id):
                    acknowledged.append(alert_id)
                else:
                    failed.append({"alert_id": alert_id, "reason": "未找到"})
            else:
                failed.append({"alert_id": alert_id, "reason": "引擎不可用"})
        except Exception as exc:
            logger.warning(f"Batch acknowledge failed for {alert_id}: {exc}")
            failed.append({"alert_id": alert_id, "reason": str(exc)[:100]})

    return {
        "status": "completed",
        "acknowledged_count": len(acknowledged),
        "failed_count": len(failed),
        "acknowledged": acknowledged,
        "failed": failed,
    }


@router.get("/trend")
async def get_alert_trend(
    request: Request,
    days: int = Query(7, ge=1, le=90),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    now = datetime.now(timezone.utc)
    date_from = now - timedelta(days=days)

    trend_data = []
    try:
        stmt = (
            select(
                cast(AnalyzedIntelligenceTable.analyzed_at, Date).label("date"),
                AnalyzedIntelligenceTable.threat_level.label("severity"),
                func.count().label("count"),
            )
            .where(
                AnalyzedIntelligenceTable.analyzed_at >= date_from,
                AnalyzedIntelligenceTable.threat_level.in_(["critical", "high", "medium", "low"]),
            )
            .group_by("date", "severity")
            .order_by("date")
        )
        result = await db.execute(stmt)
        rows = result.all()

        daily_map: Dict[str, Dict[str, int]] = {}
        for row in rows:
            date_str = row.date.isoformat() if row.date else "unknown"
            if date_str not in daily_map:
                daily_map[date_str] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
            daily_map[date_str][row.severity] = row.count
            daily_map[date_str]["total"] += row.count

        for i in range(days):
            d = (date_from + timedelta(days=i)).date()
            date_str = d.isoformat()
            if date_str not in daily_map:
                daily_map[date_str] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}

        for date_str in sorted(daily_map.keys()):
            trend_data.append({"date": date_str, **daily_map[date_str]})

    except Exception as exc:
        logger.warning(f"Alert trend query failed: {exc}")
        engine = getattr(request.app.state, "alert_engine", None)
        if engine is not None:
            history = engine.alert_history
            daily_map: Dict[str, Dict[str, int]] = {}
            for alert in history:
                try:
                    ts = alert.timestamp
                    if ts:
                        date_str = ts[:10]
                        if date_str not in daily_map:
                            daily_map[date_str] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
                        sev = alert.severity if alert.severity in daily_map[date_str] else "medium"
                        daily_map[date_str][sev] += 1
                        daily_map[date_str]["total"] += 1
                except Exception:
                    pass
            for date_str in sorted(daily_map.keys()):
                trend_data.append({"date": date_str, **daily_map[date_str]})

    return {"days": days, "trend": trend_data}


@router.get("/search")
async def search_alerts(
    request: Request,
    severity: Optional[str] = Query(None, pattern="^(critical|high|medium|low|info)$"),
    status: Optional[str] = Query(None, pattern="^(acknowledged|active)$"),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    keyword: Optional[str] = Query(None, max_length=200),
    offset: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    engine = getattr(request.app.state, "alert_engine", None)

    engine_alerts = []
    if engine is not None:
        all_alerts = list(engine.active_alerts.values()) + engine.alert_history
        seen_ids = set()
        for a in all_alerts:
            if a.alert_id not in seen_ids:
                seen_ids.add(a.alert_id)
                engine_alerts.append(a.to_dict())

    db_alerts = []
    try:
        stmt = (
            select(AnalyzedIntelligenceTable)
            .join(CleanedIntelligenceTable, AnalyzedIntelligenceTable.cleaned_id == CleanedIntelligenceTable.id)
        )

        if severity:
            stmt = stmt.where(AnalyzedIntelligenceTable.threat_level == severity)
        else:
            stmt = stmt.where(AnalyzedIntelligenceTable.threat_level.in_(["critical", "high", "medium", "low"]))

        if date_from:
            try:
                df = datetime.fromisoformat(date_from)
                stmt = stmt.where(AnalyzedIntelligenceTable.analyzed_at >= df)
            except ValueError:
                raise ValidationException(detail="date_from 格式无效，请使用 ISO 8601 格式")

        if date_to:
            try:
                dt = datetime.fromisoformat(date_to)
                stmt = stmt.where(AnalyzedIntelligenceTable.analyzed_at <= dt)
            except ValueError:
                raise ValidationException(detail="date_to 格式无效，请使用 ISO 8601 格式")

        if keyword:
            safe_kw = keyword.replace("%", "\\%").replace("_", "\\_")
            kw = f"%{safe_kw}%"
            stmt = stmt.where(
                or_(
                    AnalyzedIntelligenceTable.analysis_summary.ilike(kw),
                    CleanedIntelligenceTable.content.ilike(kw),
                )
            )

        count_stmt = select(func.count()).select_from(stmt.subquery())
        total_result = await db.execute(count_stmt)
        total = total_result.scalar() or 0

        stmt = stmt.order_by(AnalyzedIntelligenceTable.analyzed_at.desc()).offset(offset).limit(limit)
        result = await db.execute(stmt)
        rows = result.scalars().all()

        for row in rows:
            alert_dict = _analyzed_to_alert_dict(row)
            if status == "acknowledged":
                alert_dict["status"] = "acknowledged"
            elif status == "active":
                alert_dict["status"] = "active"
            db_alerts.append(alert_dict)

    except (AppException, ValidationException):
        raise
    except Exception as exc:
        logger.warning(f"Alert search DB query failed: {exc}")

    merged = db_alerts

    if engine_alerts:
        existing_ids = {a["alert_id"] for a in merged}
        for ea in engine_alerts:
            if ea.get("alert_id") not in existing_ids:
                if severity and ea.get("severity") != severity:
                    continue
                if keyword:
                    kw_lower = keyword.lower()
                    if kw_lower not in (ea.get("title", "") + ea.get("description", "")).lower():
                        continue
                if status == "acknowledged" and not ea.get("acknowledged"):
                    continue
                if status == "active" and ea.get("acknowledged"):
                    continue
                merged.append(ea)

    merged.sort(key=lambda x: x.get("triggered_at") or x.get("created_at") or "", reverse=True)

    paginated = merged[offset:offset + limit]

    return {
        "alerts": paginated,
        "total": len(merged),
        "offset": offset,
        "limit": limit,
    }
