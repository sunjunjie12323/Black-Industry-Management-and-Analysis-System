"""
情报质量评估API
提供情报可信度、完整性、时效性、一致性评估接口
"""
import json
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Dict, Any
from pydantic import BaseModel

from app.core.auth import get_current_user, User
from app.db.database import get_db
from app.db.tables import RawIntelligenceTable
from app.api.utils import raw_intelligence_to_dict

router = APIRouter(prefix="/intelligence-quality", tags=["情报质量评估"])


class QualityAssessmentRequest(BaseModel):
    intelligence_ids: List[str]


class QualityAssessmentResponse(BaseModel):
    assessments: List[Dict[str, Any]]
    summary: Dict[str, Any]


@router.post("/assess", response_model=QualityAssessmentResponse)
async def assess_intelligence_quality(
    request: QualityAssessmentRequest,
    req: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    批量评估情报质量
    返回每条情报的可信度、完整性、时效性、一致性评分
    """
    quality_engine = req.app.state.intelligence_quality_engine
    if not quality_engine:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="情报质量评估引擎未初始化"
        )

    from sqlalchemy import select

    stmt = select(RawIntelligenceTable).where(RawIntelligenceTable.id.in_(request.intelligence_ids))
    result = await db.execute(stmt)
    intelligence_items = result.scalars().all()

    if not intelligence_items:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="未找到指定的情报数据"
        )

    items_dict = [raw_intelligence_to_dict(item) for item in intelligence_items]

    assessments = await quality_engine.assess_quality(items_dict)

    summary = {
        "total_count": len(assessments),
        "avg_credibility": sum(a["credibility_score"] for a in assessments) / len(assessments),
        "avg_completeness": sum(a["completeness_score"] for a in assessments) / len(assessments),
        "avg_timeliness": sum(a["timeliness_score"] for a in assessments) / len(assessments),
        "avg_consistency": sum(a["consistency_score"] for a in assessments) / len(assessments),
        "avg_overall": sum(a["overall_score"] for a in assessments) / len(assessments),
        "grade_distribution": {
            "A": sum(1 for a in assessments if a["grade"] == "A"),
            "B": sum(1 for a in assessments if a["grade"] == "B"),
            "C": sum(1 for a in assessments if a["grade"] == "C"),
            "D": sum(1 for a in assessments if a["grade"] == "D"),
            "F": sum(1 for a in assessments if a["grade"] == "F"),
        }
    }

    return QualityAssessmentResponse(
        assessments=assessments,
        summary=summary
    )


@router.get("/source-reputation/{source}")
async def get_source_reputation(
    source: str,
    req: Request,
    current_user: User = Depends(get_current_user)
):
    """
    获取指定来源的信誉评分
    """
    quality_engine = req.app.state.intelligence_quality_engine
    if not quality_engine:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="情报质量评估引擎未初始化"
        )

    reputation = quality_engine.get_source_reputation(source)
    trend = quality_engine.get_source_trend(source)

    return {
        "source": source,
        "reputation_score": reputation,
        "trend": trend,
        "history": quality_engine.get_source_history(source, limit=20)
    }


@router.post("/update-source-reputation")
async def update_source_reputation(
    source: str,
    req: Request,
    was_accurate: bool,
    weight: float = 0.1,
    current_user: User = Depends(get_current_user)
):
    """
    更新来源信誉评分
    基于情报准确性反馈进行贝叶斯更新
    """
    quality_engine = req.app.state.intelligence_quality_engine
    if not quality_engine:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="情报质量评估引擎未初始化"
        )

    new_reputation = await quality_engine.update_source_reputation(
        source=source,
        was_accurate=was_accurate,
        weight=weight
    )

    return {
        "source": source,
        "was_accurate": was_accurate,
        "new_reputation": new_reputation,
        "message": "来源信誉已更新"
    }
