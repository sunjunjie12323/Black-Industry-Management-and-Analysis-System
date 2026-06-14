"""
动态风险评分API
提供实时风险评估、风险衰减、级联风险分析接口
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

router = APIRouter(prefix="/risk-scoring", tags=["动态风险评分"])


class RiskScoreRequest(BaseModel):
    threat_event: Dict[str, Any]
    context: Dict[str, Any] = None


class RiskScoreResponse(BaseModel):
    risk_score: float
    risk_level: str
    risk_factors: Dict[str, float]
    recommendation: str
    timestamp: str


@router.post("/calculate", response_model=RiskScoreResponse)
async def calculate_risk_score(
    request: RiskScoreRequest,
    req: Request,
    current_user: User = Depends(get_current_user)
):
    """
    计算威胁事件的实时风险评分
    基于多维度因子加权计算
    """
    risk_engine = req.app.state.dynamic_risk_scorer
    if not risk_engine:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="动态风险评分引擎未初始化"
        )

    result = risk_engine.calculate_risk_score(
        request.threat_event,
        request.context
    )

    return RiskScoreResponse(
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        risk_factors=result["risk_factors"],
        recommendation=result["recommendation"],
        timestamp=result["timestamp"]
    )


@router.post("/batch-calculate")
async def batch_calculate_risk_scores(
    req: Request,
    threat_events: List[Dict[str, Any]],
    context: Dict[str, Any] = None,
    current_user: User = Depends(get_current_user)
):
    """
    批量计算多个威胁事件的风险评分
    """
    risk_engine = req.app.state.dynamic_risk_scorer
    if not risk_engine:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="动态风险评分引擎未初始化"
        )

    results = risk_engine.batch_calculate(threat_events, context)

    return {
        "total_events": len(threat_events),
        "results": results,
        "summary": {
            "avg_risk_score": sum(r["risk_score"] for r in results) / len(results),
            "critical_count": sum(1 for r in results if r["risk_level"] == "critical"),
            "high_count": sum(1 for r in results if r["risk_level"] == "high"),
            "medium_count": sum(1 for r in results if r["risk_level"] == "medium"),
            "low_count": sum(1 for r in results if r["risk_level"] == "low")
        }
    }


@router.post("/decay")
async def calculate_risk_decay(
    req: Request,
    initial_score: float,
    event_timestamp: str,
    decay_model: str = "exponential",
    current_user: User = Depends(get_current_user)
):
    """
    计算风险评分随时间的衰减
    """
    risk_engine = req.app.state.dynamic_risk_scorer
    if not risk_engine:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="动态风险评分引擎未初始化"
        )

    try:
        event_time = datetime.fromisoformat(event_timestamp)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="无效的时间戳格式，请使用ISO格式"
        )

    result = risk_engine.calculate_risk_decay(
        initial_score,
        event_time,
        decay_model
    )

    return {
        "initial_score": initial_score,
        "current_score": result["current_score"],
        "decay_rate": result["decay_rate"],
        "hours_elapsed": result["hours_elapsed"],
        "decay_model": decay_model
    }


@router.post("/cascade-analysis")
async def analyze_cascade_risk(
    req: Request,
    primary_event_id: str,
    dependent_event_ids: List[str],
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    分析级联风险
    评估主要事件对依赖事件的影响
    """
    risk_engine = req.app.state.dynamic_risk_scorer
    if not risk_engine:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="动态风险评分引擎未初始化"
        )

    from sqlalchemy import select

    stmt = select(RawIntelligenceTable).where(RawIntelligenceTable.id == primary_event_id)
    result = await db.execute(stmt)
    primary_event = result.scalar_one_or_none()

    if not primary_event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="未找到主要事件"
        )

    stmt = select(RawIntelligenceTable).where(RawIntelligenceTable.id.in_(dependent_event_ids))
    result = await db.execute(stmt)
    dependent_events = result.scalars().all()

    if not dependent_events:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="未找到依赖事件"
        )

    primary_dict = raw_intelligence_to_dict(primary_event)
    dependent_dicts = [raw_intelligence_to_dict(e) for e in dependent_events]

    result = risk_engine.analyze_cascade_risk(primary_dict, dependent_dicts)

    return {
        "primary_event_id": primary_event_id,
        "primary_risk_score": result["primary_risk_score"],
        "cascade_effects": result["cascade_effects"],
        "total_cascade_impact": result["total_cascade_impact"],
        "recommendations": result["recommendations"]
    }


@router.get("/risk-matrix/{industry}")
async def get_industry_risk_matrix(
    industry: str,
    req: Request,
    current_user: User = Depends(get_current_user)
):
    """
    获取指定行业的风险矩阵配置
    """
    risk_engine = req.app.state.dynamic_risk_scorer
    if not risk_engine:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="动态风险评分引擎未初始化"
        )

    matrix = risk_engine.get_risk_matrix(industry)

    if not matrix:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"未找到行业 '{industry}' 的风险矩阵配置"
        )

    return {
        "industry": industry,
        "matrix": matrix
    }


@router.get("/thresholds/{industry}")
async def get_risk_thresholds(
    industry: str,
    req: Request,
    current_user: User = Depends(get_current_user)
):
    """
    获取指定行业的风险等级阈值
    """
    risk_engine = req.app.state.dynamic_risk_scorer
    if not risk_engine:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="动态风险评分引擎未初始化"
        )

    thresholds = risk_engine.get_risk_thresholds(industry)

    if not thresholds:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"未找到行业 '{industry}' 的风险阈值配置"
        )

    return {
        "industry": industry,
        "thresholds": thresholds
    }
