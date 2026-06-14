from fastapi import APIRouter, Depends, HTTPException, Query, Request
from loguru import logger
from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import User, get_current_user
from app.core.db_utils import db_write
from app.db.database import get_db

router = APIRouter(prefix="/threat-analysis", tags=["黑灰产情报分析"])


class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=50000, description="待分析的情报文本")
    intelligence_id: Optional[str] = Field(None, description="情报ID")
    industry: Optional[str] = Field(None, description="行业场景: threat_intel/manufacturing/education/healthcare/finance")
    use_llm: bool = Field(True, description="是否使用LLM增强分析")


class ClassifyRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=50000)
    use_llm: bool = Field(True)


class ExtractRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=50000)
    use_llm: bool = Field(True)


class BatchAnalyzeRequest(BaseModel):
    texts: List[str] = Field(..., min_length=1, max_length=20)
    industry: Optional[str] = None


@router.post("/analyze")
async def analyze_intelligence(request: AnalyzeRequest, req: Request, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    service = getattr(req.app.state, "threat_intel_service", None)
    if not service:
        raise HTTPException(status_code=503, detail="ThreatIntelService未初始化")
    result = await service.analyze(request.text, request.intelligence_id or "", request.industry or "")
    if result is None:
        raise HTTPException(status_code=500, detail="分析服务返回空结果，请稍后重试")
    summary = getattr(result, 'analysis_summary', None) or ""
    threat_categories = getattr(result, 'threat_categories', None) or []
    confidence = getattr(result, 'confidence', None)
    if confidence is None:
        summary_dict = getattr(result, 'summary', None) or {}
        if isinstance(summary_dict, dict):
            threat_categories = summary_dict.get('threats', threat_categories)
        else:
            threat_categories = getattr(summary_dict, 'threats', threat_categories)
        confidence = getattr(result, 'confidence', 0.0)
    try:
        from app.db.tables import AnalysisResultTable
        from uuid import uuid4
        llm = getattr(req.app.state, "llm", None)
        model_name = llm.model_name if llm and hasattr(llm, 'model_name') else "rule-based"
        entry = AnalysisResultTable(
            id=uuid4().hex,
            analysis_type="threat_analysis",
            target_id=request.intelligence_id or "",
            result_summary=summary,
            findings_json=threat_categories if isinstance(threat_categories, str) else str(threat_categories),
            confidence_score=confidence if isinstance(confidence, (int, float)) else 0.0,
            input_content=request.text[:2000],
            model_name=model_name,
        )
        async with db_write(db, operation="保存分析结果"):
            db.add(entry)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to save analysis result to database: {e}")
    return result.to_dict()


@router.post("/classify")
async def classify_threat(request: ClassifyRequest, req: Request, current_user: User = Depends(get_current_user)):
    service = getattr(req.app.state, "threat_intel_service", None)
    if not service:
        raise HTTPException(status_code=503, detail="ThreatIntelService未初始化")
    result = await service.classify_only(request.text)
    if result is None:
        raise HTTPException(status_code=500, detail="分类服务返回空结果，请稍后重试")
    return result.to_dict()


@router.post("/extract-entities")
async def extract_entities(request: ExtractRequest, req: Request, current_user: User = Depends(get_current_user)):
    service = getattr(req.app.state, "threat_intel_service", None)
    if not service:
        raise HTTPException(status_code=503, detail="ThreatIntelService未初始化")
    result = await service.extract_entities_only(request.text)
    if result is None or (isinstance(result, list) and len(result) == 0):
        return {"entities": [], "total": 0, "message": "未找到匹配的实体"}
    entities = []
    for e in result:
        try:
            entities.append(e.to_dict() if hasattr(e, 'to_dict') else {"value": str(e)})
        except Exception:
            logger.exception("Unexpected error serializing entity")
            entities.append({"value": str(e)})
    return {"entities": entities, "total": len(entities)}


@router.post("/batch-analyze")
async def batch_analyze(request: BatchAnalyzeRequest, req: Request, current_user: User = Depends(get_current_user)):
    service = getattr(req.app.state, "threat_intel_service", None)
    if not service:
        raise HTTPException(status_code=503, detail="ThreatIntelService未初始化")
    import asyncio
    semaphore = asyncio.Semaphore(5)
    async def _analyze_one(text: str):
        async with semaphore:
            return await service.analyze(text, "", request.industry or "")
    tasks = [_analyze_one(text) for text in request.texts[:20]]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    output = []
    for r in results:
        if isinstance(r, Exception):
            output.append({"error": "分析失败，请稍后重试"})
        else:
            output.append(r.to_dict())
    return {"results": output, "total": len(output)}


@router.get("/statistics")
async def get_statistics(req: Request, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    from datetime import datetime, timedelta, timezone
    from sqlalchemy import select, func, case

    from app.db.tables import AnalysisResultTable, AnalyzedIntelligenceTable

    now = datetime.now(timezone.utc)
    twenty_four_hours_ago = now - timedelta(hours=24)

    try:
        type_counts_stmt = (
            select(AnalysisResultTable.analysis_type, func.count(AnalysisResultTable.id))
            .group_by(AnalysisResultTable.analysis_type)
        )
        type_result = await db.execute(type_counts_stmt)
        analysis_counts_by_type = {row[0]: row[1] for row in type_result.all()}

        threat_level_stmt = (
            select(AnalyzedIntelligenceTable.threat_level, func.count(AnalyzedIntelligenceTable.id))
            .group_by(AnalyzedIntelligenceTable.threat_level)
        )
        level_result = await db.execute(threat_level_stmt)
        threat_level_distribution = {row[0]: row[1] for row in level_result.all()}

        recent_stmt = (
            select(func.count(AnalysisResultTable.id))
            .where(AnalysisResultTable.analyzed_at >= twenty_four_hours_ago)
        )
        recent_result = await db.execute(recent_stmt)
        recent_activity_count = recent_result.scalar() or 0
    except Exception as e:
        logger.error(f"Failed to query statistics: {e}")
        analysis_counts_by_type = {}
        threat_level_distribution = {}
        recent_activity_count = 0

    return {
        "analysis_counts_by_type": analysis_counts_by_type,
        "threat_level_distribution": threat_level_distribution,
        "recent_activity_count": recent_activity_count,
    }


@router.get("/threat-categories")
async def get_threat_categories(req: Request, current_user: User = Depends(get_current_user)):
    service = getattr(req.app.state, "threat_intel_service", None)
    if not service:
        raise HTTPException(status_code=503, detail="ThreatIntelService未初始化")
    return service.get_threat_categories()


@router.get("/entity-types")
async def get_entity_types(req: Request, current_user: User = Depends(get_current_user)):
    service = getattr(req.app.state, "threat_intel_service", None)
    if not service:
        raise HTTPException(status_code=503, detail="ThreatIntelService未初始化")
    return service.get_entity_types()


@router.get("/industries")
async def get_industries(req: Request, current_user: User = Depends(get_current_user)):
    service = getattr(req.app.state, "threat_intel_service", None)
    if not service:
        raise HTTPException(status_code=503, detail="ThreatIntelService未初始化")
    industries = service.get_all_industries()
    return {
        k: {
            "name": v["name"],
            "threat_focus": v["threat_focus"],
            "keywords": v["keywords"],
        }
        for k, v in industries.items()
    }


@router.get("/industries/{industry}")
async def get_industry_detail(industry: str, req: Request, current_user: User = Depends(get_current_user)):
    service = getattr(req.app.state, "threat_intel_service", None)
    if not service:
        raise HTTPException(status_code=503, detail="ThreatIntelService未初始化")
    config = service.get_industry_config(industry)
    if not config:
        raise HTTPException(status_code=404, detail=f"行业 {industry} 不存在")
    return config


@router.get("/recent")
async def get_recent_analyses(
    req: Request,
    limit: int = Query(20, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    from datetime import datetime, timezone
    from sqlalchemy import select
    from app.db.tables import AnalysisResultTable

    try:
        stmt = (
            select(AnalysisResultTable)
            .order_by(AnalysisResultTable.analyzed_at.desc())
            .offset(offset)
            .limit(limit)
        )
        result = await db.execute(stmt)
        rows = result.scalars().all()

        items = []
        for row in rows:
            items.append({
                "id": row.id,
                "analysis_type": row.analysis_type,
                "target_id": row.target_id,
                "result_summary": row.result_summary,
                "confidence_score": row.confidence_score,
                "model_name": row.model_name,
                "analyzed_at": row.analyzed_at.isoformat() if row.analyzed_at else None,
            })
        return {"items": items, "total": len(items), "offset": offset, "limit": limit}
    except Exception as e:
        logger.error(f"Failed to get recent analyses: {e}")
        return {"items": [], "total": 0, "offset": offset, "limit": limit, "message": "暂无分析记录"}
