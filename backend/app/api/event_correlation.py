"""
事件关联分析API
提供跨事件关联、因果推理、攻击链重建接口
"""
import json
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Dict, Any
from pydantic import BaseModel
from datetime import datetime

from app.core.auth import get_current_user, User
from app.db.database import get_db
from app.db.tables import RawIntelligenceTable
from app.api.utils import raw_intelligence_to_dict

router = APIRouter(prefix="/event-correlation", tags=["事件关联分析"])


class CorrelationAnalysisRequest(BaseModel):
    event_ids: List[str]
    time_window_hours: int = 72
    methods: List[str] = ["temporal", "entity", "semantic"]


class CorrelationAnalysisResponse(BaseModel):
    correlations: List[Dict[str, Any]]
    clusters: List[Dict[str, Any]]
    attack_chains: List[Dict[str, Any]]
    summary: Dict[str, Any]


@router.post("/analyze", response_model=CorrelationAnalysisResponse)
async def analyze_event_correlations(
    request: CorrelationAnalysisRequest,
    req: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    分析事件关联性
    支持时间关联、实体关联、语义关联多种方法
    """
    correlation_engine = req.app.state.event_correlation_engine
    if not correlation_engine:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="事件关联分析引擎未初始化"
        )

    from sqlalchemy import select

    stmt = select(RawIntelligenceTable).where(RawIntelligenceTable.id.in_(request.event_ids))
    result = await db.execute(stmt)
    events = result.scalars().all()

    if not events:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="未找到指定的事件数据"
        )

    events_dict = [raw_intelligence_to_dict(e) for e in events]

    analysis_result = await correlation_engine.find_correlations(
        events=events_dict,
        time_window_hours=request.time_window_hours,
        methods=request.methods
    )

    return CorrelationAnalysisResponse(
        correlations=analysis_result["correlations"],
        clusters=analysis_result["clusters"],
        attack_chains=analysis_result["attack_chains"],
        summary=analysis_result["summary"]
    )


@router.get("/temporal/{event_id}")
async def get_temporal_correlations(
    event_id: str,
    req: Request,
    window_hours: int = 72,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    获取指定事件的时间关联事件
    """
    correlation_engine = req.app.state.event_correlation_engine
    if not correlation_engine:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="事件关联分析引擎未初始化"
        )

    from sqlalchemy import select
    from datetime import timedelta

    stmt = select(RawIntelligenceTable).where(RawIntelligenceTable.id == event_id)
    result = await db.execute(stmt)
    target_event = result.scalar_one_or_none()

    if not target_event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="未找到指定的事件"
        )

    time_start = target_event.collected_at - timedelta(hours=window_hours)
    time_end = target_event.collected_at + timedelta(hours=window_hours)

    stmt = (
        select(RawIntelligenceTable)
        .where(
            RawIntelligenceTable.collected_at >= time_start,
            RawIntelligenceTable.collected_at <= time_end,
            RawIntelligenceTable.id != event_id
        )
        .limit(100)
    )
    result = await db.execute(stmt)
    related_events = result.scalars().all()

    events_dict = [raw_intelligence_to_dict(e) for e in related_events]
    target_dict = raw_intelligence_to_dict(target_event)

    correlations = correlation_engine.temporal_correlation(
        events=[target_dict] + events_dict,
        window_hours=window_hours
    )

    target_correlations = [
        corr for corr in correlations
        if corr["event_a"]["id"] == event_id or corr["event_b"]["id"] == event_id
    ]

    return {
        "event_id": event_id,
        "window_hours": window_hours,
        "correlations": target_correlations,
        "total_related": len(target_correlations)
    }


@router.post("/reconstruct-attack-chain")
async def reconstruct_attack_chain(
    req: Request,
    event_ids: List[str],
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    基于关联事件重建攻击链
    """
    correlation_engine = req.app.state.event_correlation_engine
    if not correlation_engine:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="事件关联分析引擎未初始化"
        )

    from sqlalchemy import select

    stmt = select(RawIntelligenceTable).where(RawIntelligenceTable.id.in_(event_ids))
    result = await db.execute(stmt)
    events = result.scalars().all()

    if not events:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="未找到指定的事件数据"
        )

    events_dict = []
    for e in events:
        d = _row_to_dict(e)
        d["tactics"] = d["metadata"].get("tactics", [])
        events_dict.append(d)

    attack_chain = correlation_engine.reconstruct_attack_chain(events_dict)

    return {
        "event_count": len(events),
        "attack_chain": attack_chain,
        "timeline": [
            {
                "phase": step["phase"],
                "event_id": step["event_id"],
                "timestamp": step["timestamp"],
                "description": step["description"]
            }
            for step in attack_chain["steps"]
        ]
    }
