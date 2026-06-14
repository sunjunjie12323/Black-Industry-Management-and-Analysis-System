from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select, func
from app.core.auth import get_current_user, User
from app.config import settings
from app.db.database import get_db
from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter(prefix="/economic", tags=["economic"])


@router.get("/dashboard")
async def get_dashboard(
    current_user: User = Depends(get_current_user),
):
    raise HTTPException(status_code=410, detail="经济系统已移除，请使用情报分析相关功能")


@router.get("/data-sources")
async def get_data_sources(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    from app.db.tables import RawIntelligenceTable
    from app.models.intelligence import IntelligenceSource

    sources = []
    for source in IntelligenceSource:
        result = await db.execute(
            select(func.count(RawIntelligenceTable.id)).where(RawIntelligenceTable.source == source.value)
        )
        count = result.scalar() or 0
        if count > 0:
            sources.append({"sector": "威胁情报", "provider": source.value, "status": "available", "count": count})

    if not sources:
        sources = [
            {"sector": "威胁情报", "provider": "CISA KEV", "status": "unavailable", "count": 0},
            {"sector": "恶意URL", "provider": "URLhaus", "status": "unavailable", "count": 0},
            {"sector": "恶意软件", "provider": "MalwareBazaar", "status": "unavailable", "count": 0},
        ]

    return {"sources": sources, "total": len(sources)}


@router.get("/impact")
async def get_impact_alias(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    from app.db.tables import CleanedIntelligenceTable, AlertRuleTable
    from app.models.intelligence import ThreatLevel

    total_intel_result = await db.execute(select(func.count(CleanedIntelligenceTable.id)))
    total_intel = total_intel_result.scalar() or 0

    critical_result = await db.execute(
        select(func.count(CleanedIntelligenceTable.id)).where(CleanedIntelligenceTable.threat_level == ThreatLevel.CRITICAL.value)
    )
    critical_count = critical_result.scalar() or 0

    high_result = await db.execute(
        select(func.count(CleanedIntelligenceTable.id)).where(CleanedIntelligenceTable.threat_level == ThreatLevel.HIGH.value)
    )
    high_count = high_result.scalar() or 0

    active_alerts_result = await db.execute(select(func.count(AlertRuleTable.id)))
    active_alerts = active_alerts_result.scalar() or 0

    return {
        "impact_summary": {
            "threats_detected": total_intel,
            "threats_mitigated": critical_count + high_count,
            "economic_loss_prevented": (
                # Simplified estimation model: each severity level is assigned a
                # fixed monetary multiplier.  Adjust via ECONOMIC_LOSS_CRITICAL_MULTIPLIER
                # and ECONOMIC_LOSS_HIGH_MULTIPLIER env vars for domain-specific tuning.
                critical_count * settings.ECONOMIC_LOSS_CRITICAL_MULTIPLIER
                + high_count * settings.ECONOMIC_LOSS_HIGH_MULTIPLIER
            ),
        },
        "active_alerts": active_alerts,
        "status": "active",
    }
