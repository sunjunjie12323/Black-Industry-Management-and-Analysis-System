import json
from datetime import datetime
from typing import Any, Dict, List, Optional
import asyncio

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from loguru import logger
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.audit import audit_log_async
from app.core.auth import User, get_current_user, require_role, Role
from app.core.rule_based_extractor import rule_extractor
from app.db.crud import IntelligenceCRUD
from app.db.database import get_db
from app.db.tables import (
    AnalyzedIntelligenceTable,
    CleanedIntelligenceTable,
    RawIntelligenceTable,
)
from app.models.intelligence import (
    AnalyzedIntelligence,
    CleanedIntelligence,
    IntelligenceSource,
    IntelligenceStatus,
    RawIntelligence,
    ThreatLevel,
)
from app.middleware import request_id_ctx
from app.utils.db_helpers import safe_json_loads_list, safe_json_loads_dict, truncate_content

router = APIRouter(prefix="/intelligence", tags=["intelligence"])
pipeline_router = APIRouter(prefix="/intelligence/pipeline", tags=["intelligence-pipeline"])


class RawIntelligenceCreate(BaseModel):
    source: IntelligenceSource = IntelligenceSource.OTHER
    source_url: Optional[str] = None
    content: str = Field(..., min_length=1)
    raw_content: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class StatusUpdateRequest(BaseModel):
    status: IntelligenceStatus


class IntelligenceStatsResponse(BaseModel):
    by_source: Dict[str, int] = {}
    by_threat_level: Dict[str, int] = {}
    by_status: Dict[str, int] = {}
    total: int = 0


@router.get("")
async def list_intelligence(
    source: Optional[str] = None,
    threat_level: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    items: List[Dict[str, Any]] = []
    total = 0

    try:
        conditions_raw = []
        conditions_cleaned = []
        conditions_analyzed = []

        if source:
            conditions_raw.append(RawIntelligenceTable.source == source)

        if status:
            conditions_raw.append(RawIntelligenceTable.status == status)
            if status in ("cleaned", "analyzed"):
                conditions_cleaned.append(RawIntelligenceTable.status == status)

        if threat_level:
            conditions_cleaned.append(CleanedIntelligenceTable.threat_level == threat_level)
            conditions_analyzed.append(AnalyzedIntelligenceTable.threat_level == threat_level)

        if search:
            safe_search = search.replace("%", "\\%").replace("_", "\\_")
            search_pattern = f"%{safe_search}%"
            conditions_raw.append(RawIntelligenceTable.content.ilike(search_pattern))
            conditions_cleaned.append(CleanedIntelligenceTable.content.ilike(search_pattern))
            conditions_analyzed.append(AnalyzedIntelligenceTable.analysis_summary.ilike(search_pattern))

        raw_stmt = (
            select(RawIntelligenceTable)
            .options(selectinload(RawIntelligenceTable.cleaned))
        )
        raw_count_stmt = select(func.count()).select_from(RawIntelligenceTable)
        for cond in conditions_raw:
            raw_stmt = raw_stmt.where(cond)
            raw_count_stmt = raw_count_stmt.where(cond)

        raw_total_result = await db.execute(raw_count_stmt)
        raw_total = raw_total_result.scalar() or 0

        raw_stmt = raw_stmt.order_by(RawIntelligenceTable.collected_at.desc()).offset(offset).limit(limit)
        raw_result = await db.execute(raw_stmt)
        raw_rows = raw_result.scalars().all()

        for row in raw_rows:
            items.append({
                "id": row.id,
                "source": row.source,
                "content": truncate_content(row.content, 300),
                "threat_level": None,
                "status": row.status,
                "collected_at": row.collected_at.isoformat() if row.collected_at else None,
                "entities_count": 0,
                "blacktalk_count": 0,
                "type": "raw",
            })

        remaining = limit - len(raw_rows)
        cleaned_offset = max(0, offset - raw_total) if offset > raw_total else 0

        if remaining > 0 or threat_level or (status and status in ("cleaned", "analyzed")):
            cleaned_stmt = (
                select(CleanedIntelligenceTable)
                .options(selectinload(CleanedIntelligenceTable.analyzed))
            )
            cleaned_count_stmt = select(func.count()).select_from(CleanedIntelligenceTable)
            for cond in conditions_cleaned:
                cleaned_stmt = cleaned_stmt.where(cond)
                cleaned_count_stmt = cleaned_count_stmt.where(cond)

            cleaned_total_result = await db.execute(cleaned_count_stmt)
            cleaned_total = cleaned_total_result.scalar() or 0

            if not threat_level and not (status and status in ("cleaned", "analyzed")):
                cleaned_stmt = cleaned_stmt.order_by(CleanedIntelligenceTable.cleaned_at.desc()).offset(cleaned_offset).limit(remaining)
            else:
                cleaned_stmt = cleaned_stmt.order_by(CleanedIntelligenceTable.cleaned_at.desc()).offset(offset).limit(limit)

            cleaned_result = await db.execute(cleaned_stmt)
            cleaned_rows = cleaned_result.scalars().all()

            for row in cleaned_rows:
                entities = safe_json_loads_list(row.entities_json)
                blacktalk_terms = safe_json_loads_dict(row.blacktalk_terms_json)

                items.append({
                    "id": row.id,
                    "source": None,
                    "content": truncate_content(row.content, 300),
                    "threat_level": row.threat_level,
                    "status": "cleaned",
                    "collected_at": row.cleaned_at.isoformat() if row.cleaned_at else None,
                    "entities_count": len(entities) if isinstance(entities, list) else 0,
                    "blacktalk_count": len(blacktalk_terms) if isinstance(blacktalk_terms, dict) else 0,
                    "type": "cleaned",
                })

            analyzed_stmt = (
                select(AnalyzedIntelligenceTable)
                .options(selectinload(AnalyzedIntelligenceTable.cleaned))
            )
            analyzed_count_stmt = select(func.count()).select_from(AnalyzedIntelligenceTable)
            for cond in conditions_analyzed:
                analyzed_stmt = analyzed_stmt.where(cond)
                analyzed_count_stmt = analyzed_count_stmt.where(cond)

            analyzed_total_result = await db.execute(analyzed_count_stmt)
            analyzed_total = analyzed_total_result.scalar() or 0

            analyzed_stmt = analyzed_stmt.order_by(AnalyzedIntelligenceTable.analyzed_at.desc()).offset(offset).limit(limit)
            analyzed_result = await db.execute(analyzed_stmt)
            analyzed_rows = analyzed_result.scalars().all()

            for row in analyzed_rows:
                items.append({
                    "id": row.id,
                    "source": None,
                    "content": truncate_content(row.analysis_summary, 300),
                    "threat_level": row.threat_level,
                    "status": "analyzed",
                    "collected_at": row.analyzed_at.isoformat() if row.analyzed_at else None,
                    "entities_count": 0,
                    "blacktalk_count": 0,
                    "type": "analyzed",
                })

            total = raw_total + cleaned_total + analyzed_total
        else:
            total = raw_total

        if threat_level:
            items = [i for i in items if i.get("threat_level") == threat_level]
            total = len(items)

        items.sort(key=lambda x: x.get("collected_at") or "", reverse=True)
        items = items[:limit]

    except Exception as exc:
        logger.error(f"Failed to list unified intelligence: {exc}")
        raise HTTPException(status_code=500, detail=f"查询情报列表失败: {exc}")

    if not items and total == 0:
        return {"items": [], "total": 0, "offset": offset, "limit": limit, "message": "暂无情报数据"}
    return {"items": items, "total": total, "offset": offset, "limit": limit}


_CATEGORY_NAME_MAP = {
    "fraud": "诈骗模式", "gambling": "赌博模式", "hacking": "黑客攻击模式",
    "money_laundering": "洗钱模式", "phishing": "钓鱼攻击模式",
    "ransomware": "勒索软件模式", "data_theft": "数据盗窃模式",
    "tool_sales": "工具售卖模式", "drug": "毒品相关模式",
}


@router.get("/stats")
async def get_intelligence_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    by_source: Dict[str, int] = {}
    by_threat_level: Dict[str, int] = {}
    by_status: Dict[str, int] = {}
    total = 0

    try:
        by_source_stmt = select(
            RawIntelligenceTable.source,
            func.count().label("count"),
        ).group_by(RawIntelligenceTable.source)
        by_status_stmt = select(
            RawIntelligenceTable.status,
            func.count().label("count"),
        ).group_by(RawIntelligenceTable.status)
        cleaned_threat_stmt = select(
            CleanedIntelligenceTable.threat_level,
            func.count().label("count"),
        ).group_by(CleanedIntelligenceTable.threat_level)
        analyzed_threat_stmt = select(
            AnalyzedIntelligenceTable.threat_level,
            func.count().label("count"),
        ).group_by(AnalyzedIntelligenceTable.threat_level)

        for source, count in (await db.execute(by_source_stmt)).all():
            by_source[source] = count
            total += count

        for status_val, count in (await db.execute(by_status_stmt)).all():
            by_status[status_val] = count

        for level, count in (await db.execute(cleaned_threat_stmt)).all():
            by_threat_level[level] = by_threat_level.get(level, 0) + count

        for level, count in (await db.execute(analyzed_threat_stmt)).all():
            by_threat_level[level] = by_threat_level.get(level, 0) + count

        cleaned_count_result = await db.execute(select(func.count()).select_from(CleanedIntelligenceTable))
        analyzed_count_result = await db.execute(select(func.count()).select_from(AnalyzedIntelligenceTable))
        total += (cleaned_count_result.scalar() or 0) + (analyzed_count_result.scalar() or 0)

    except Exception as exc:
        logger.error(f"Failed to get intelligence stats: {exc}")
        raise HTTPException(status_code=500, detail=f"查询情报统计失败: {exc}")

    return {
        "by_source": by_source,
        "by_threat_level": by_threat_level,
        "by_status": by_status,
        "total": total,
    }


@router.get("/{intel_id}")
async def get_intelligence_detail(
    intel_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    crud = IntelligenceCRUD(db)

    raw = await crud.get_raw(intel_id)
    if raw is not None:
        return {"type": "raw", "data": raw.model_dump()}

    cleaned = await crud.get_cleaned(intel_id)
    if cleaned is not None:
        return {"type": "cleaned", "data": cleaned.model_dump()}

    analyzed = await crud.get_analyzed(intel_id)
    if analyzed is not None:
        return {"type": "analyzed", "data": analyzed.model_dump()}

    raise HTTPException(status_code=404, detail="Intelligence not found")


@router.post("", status_code=201)
async def create_intelligence(
    data: RawIntelligenceCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    crud = IntelligenceCRUD(db)
    raw = RawIntelligence(
        source=data.source,
        source_url=data.source_url,
        content=data.content,
        raw_content=data.raw_content,
        metadata=data.metadata,
    )
    result = await crud.create_raw(raw)
    if result is None:
        raise HTTPException(status_code=409, detail="该情报内容已存在")
    await db.commit()
    client_ip = request.client.host if request.client else None
    await audit_log_async(
        action="CREATE_INTEL",
        user_id=current_user.id,
        username=current_user.username,
        resource_type="intelligence",
        resource_id=result.id,
        ip_address=client_ip,
        request_id=request_id_ctx.get(),
        status="success",
        details={"source": data.source.value},
    )
    return result.model_dump()


@router.patch("/{intel_id}/status")
async def update_intelligence_status(
    intel_id: str,
    data: StatusUpdateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    crud = IntelligenceCRUD(db)
    result = await crud.update_status(intel_id, data.status)
    if result is None:
        raise HTTPException(status_code=404, detail="Intelligence not found")
    await db.commit()
    client_ip = request.client.host if request.client else None
    await audit_log_async(
        action="UPDATE_INTEL_STATUS",
        user_id=current_user.id,
        username=current_user.username,
        resource_type="intelligence",
        resource_id=intel_id,
        ip_address=client_ip,
        request_id=request_id_ctx.get(),
        status="success",
        details={"new_status": data.status.value},
    )
    return result.model_dump()


@router.delete("/{intel_id}", status_code=204)
async def delete_intelligence(
    intel_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    crud = IntelligenceCRUD(db)
    deleted = await crud.delete_raw(intel_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Intelligence not found")
    await db.commit()
    client_ip = request.client.host if request.client else None
    await audit_log_async(
        action="DELETE_INTEL",
        user_id=current_user.id,
        username=current_user.username,
        resource_type="intelligence",
        resource_id=intel_id,
        ip_address=client_ip,
        request_id=request_id_ctx.get(),
        status="success",
    )


@router.post("/raw", response_model=RawIntelligence, status_code=201)
async def create_raw_intelligence(
    data: RawIntelligence,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    crud = IntelligenceCRUD(db)
    result = await crud.create_raw(data)
    await db.commit()
    return result


@router.get("/raw", response_model=dict)
async def list_raw_intelligence(
    source: IntelligenceSource | None = None,
    status: IntelligenceStatus | None = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    crud = IntelligenceCRUD(db)
    items, total = await crud.list_raw(source=source, status=status, offset=offset, limit=limit)
    await db.commit()
    return {"items": items, "total": total, "offset": offset, "limit": limit}


@router.get("/raw/{raw_id}", response_model=RawIntelligence)
async def get_raw_intelligence(
    raw_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    crud = IntelligenceCRUD(db)
    result = await crud.get_raw(raw_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Raw intelligence not found")
    return result


@router.patch("/raw/{raw_id}/status", response_model=RawIntelligence)
async def update_raw_status(
    raw_id: str,
    status: IntelligenceStatus,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    crud = IntelligenceCRUD(db)
    result = await crud.update_status(raw_id, status)
    if result is None:
        raise HTTPException(status_code=404, detail="Raw intelligence not found")
    await db.commit()
    return result


@router.delete("/raw/{raw_id}", status_code=204)
async def delete_raw_intelligence(
    raw_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    crud = IntelligenceCRUD(db)
    deleted = await crud.delete_raw(raw_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Raw intelligence not found")
    await db.commit()


@router.post("/cleaned", response_model=CleanedIntelligence, status_code=201)
async def create_cleaned_intelligence(
    data: CleanedIntelligence,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    crud = IntelligenceCRUD(db)
    raw = await crud.get_raw(data.raw_id)
    if raw is None:
        raise HTTPException(status_code=400, detail="Referenced raw intelligence not found")
    result = await crud.create_cleaned(data)
    await db.commit()
    return result


@router.get("/cleaned", response_model=dict)
async def list_cleaned_intelligence(
    threat_level: ThreatLevel | None = None,
    raw_id: str | None = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    crud = IntelligenceCRUD(db)
    items, total = await crud.list_cleaned(
        threat_level=threat_level, raw_id=raw_id, offset=offset, limit=limit
    )
    await db.commit()
    return {"items": items, "total": total, "offset": offset, "limit": limit}


@router.get("/cleaned/{cleaned_id}", response_model=CleanedIntelligence)
async def get_cleaned_intelligence(
    cleaned_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    crud = IntelligenceCRUD(db)
    result = await crud.get_cleaned(cleaned_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Cleaned intelligence not found")
    return result


@router.post("/analyzed", response_model=AnalyzedIntelligence, status_code=201)
async def create_analyzed_intelligence(
    data: AnalyzedIntelligence,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    crud = IntelligenceCRUD(db)
    cleaned = await crud.get_cleaned(data.cleaned_id)
    if cleaned is None:
        raise HTTPException(status_code=400, detail="Referenced cleaned intelligence not found")
    result = await crud.create_analyzed(data)
    await db.commit()
    return result


@router.get("/analyzed", response_model=dict)
async def list_analyzed_intelligence(
    threat_level: ThreatLevel | None = None,
    cleaned_id: str | None = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    crud = IntelligenceCRUD(db)
    items, total = await crud.list_analyzed(
        threat_level=threat_level, cleaned_id=cleaned_id, offset=offset, limit=limit
    )
    await db.commit()
    return {"items": items, "total": total, "offset": offset, "limit": limit}


@router.get("/analyzed/{analyzed_id}", response_model=AnalyzedIntelligence)
async def get_analyzed_intelligence(
    analyzed_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    crud = IntelligenceCRUD(db)
    result = await crud.get_analyzed(analyzed_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Analyzed intelligence not found")
    return result


@router.post("/{intelligence_id}/export/stix")
async def export_intelligence_stix(
    intelligence_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    from app.core.stix_exporter import STIXExporter
    exporter = STIXExporter()
    intel_data = None
    if vs := getattr(request.app.state, "vector_store", None):
        try:
            results = vs.search(intelligence_id, n_results=1)
            if results and isinstance(results, list) and len(results) > 0:
                intel_data = results[0]
        except Exception:
            pass
    if not intel_data:
        try:
            crud = IntelligenceCRUD(db)
            raw = await crud.get_raw(intelligence_id)
            if raw:
                intel_data = {"id": str(raw.id), "content": raw.content, "threat_level": getattr(raw, 'threat_level', 'info'), "entity_type": raw.source}
        except Exception:
            pass
    if not intel_data:
        raise HTTPException(status_code=404, detail="未找到指定情报数据")
    bundle = exporter.export_bundle([intel_data])
    return bundle


@router.post("/export/stix-bundle")
async def export_stix_bundle(
    request: Request,
    limit: int = Query(50, le=200),
    threat_level: Optional[str] = None,
    current_user: User = Depends(get_current_user),
):
    from app.core.stix_exporter import STIXExporter
    exporter = STIXExporter()
    vs = getattr(request.app.state, "vector_store", None)
    results = []
    if vs is not None:
        try:
            results = vs.search("threat malware vulnerability", n_results=limit)
        except Exception:
            pass
    if threat_level:
        results = [r for r in results if isinstance(r, dict) and r.get("metadata", {}).get("threat_level") == threat_level]
    if not results:
        raise HTTPException(status_code=404, detail="暂无可导出的情报数据")
    bundle = exporter.export_bundle(results)
    return bundle


class CleanRequest(BaseModel):
    content: str = Field(..., min_length=1)
    source: Optional[str] = None


class AnalyzeRequest(BaseModel):
    content: str = Field(..., min_length=1)
    cleaned_data: Optional[Dict[str, Any]] = None


@pipeline_router.post("/clean")
async def clean_intelligence(
    data: CleanRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    orchestrator = getattr(request.app.state, "orchestrator", None)
    cleaner = getattr(orchestrator, "cleaner", None) if orchestrator else None

    if cleaner:
        try:
            raw_intel = {"content": data.content, "source": data.source or "unknown"}
            result = await asyncio.wait_for(
                cleaner.clean(raw_intel, decode_blacktalk=True, extract_entities=True),
                timeout=10.0,
            )
            return {"status": "success", "data": result}
        except asyncio.TimeoutError:
            logger.warning("Cleaner agent timed out (10s), using rule-based fallback")
        except Exception as exc:
            logger.warning(f"Cleaner agent failed, using rule-based fallback: {exc}")

    cleaned_content = rule_extractor.remove_noise_rule_based(data.content)
    entities = rule_extractor.extract_entities(cleaned_content)
    threat_level, _ = rule_extractor.assess_threat_level(cleaned_content)
    categories, cat_conf = rule_extractor.classify_threat(cleaned_content)

    return {
        "status": "success",
        "data": {
            "cleaned_content": cleaned_content,
            "entities": entities,
            "threat_level": threat_level,
            "threat_categories": categories,
            "decoded_terms": {},
        },
        "fallback": True,
    }


@pipeline_router.post("/analyze")
async def analyze_intelligence(
    data: AnalyzeRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    orchestrator = getattr(request.app.state, "orchestrator", None)
    analyst = getattr(orchestrator, "analyst", None) if orchestrator else None

    cleaned_intel = data.cleaned_data or {"content": data.content}

    if analyst:
        try:
            result = await asyncio.wait_for(analyst.analyze(cleaned_intel), timeout=10.0)
            return {"status": "success", "data": result}
        except asyncio.TimeoutError:
            logger.warning("Analyst agent timed out (10s), using rule-based fallback")
        except Exception as exc:
            logger.warning(f"Analyst agent failed, using rule-based fallback: {exc}")

    categories, cat_conf = rule_extractor.classify_threat(data.content)
    threat_level, _ = rule_extractor.assess_threat_level(data.content)
    entities = rule_extractor.extract_entities(data.content)

    category_name_map = _CATEGORY_NAME_MAP

    patterns = []
    for cat in categories:
        patterns.append({
            "name": category_name_map.get(cat, cat),
            "description": f"基于关键词匹配识别到{category_name_map.get(cat, cat)}特征",
            "indicators": [cat],
            "severity": "high" if cat in ("fraud", "hacking", "money_laundering", "ransomware", "drug") else "medium",
        })

    technical_chain = []
    stage_keywords = {
        "resource_acquisition": ["获取", "购买", "收集", "采集", "抓取", "脱库", "撞库"],
        "tool_preparation": ["搭建", "配置", "部署", "准备", "工具", "平台", "猫池", "群控"],
        "attack_execution": ["攻击", "入侵", "诈骗", "钓鱼", "勒索", "挂马", "DDoS"],
        "money_flow": ["转账", "收款", "洗钱", "跑分", "套现", "提现", "通道"],
    }
    for stage, keywords in stage_keywords.items():
        if any(kw in data.content for kw in keywords):
            technical_chain.append({
                "stage": stage,
                "description": f"基于关键词匹配识别到{stage}阶段特征",
                "confidence": 0.6,
            })

    return {
        "status": "success",
        "data": {
            "patterns": patterns,
            "technical_chain": technical_chain,
            "threat_categories": categories,
            "confidence": cat_conf,
            "summary": f"检测到{', '.join(categories) if categories else '未知'}类威胁，置信度{cat_conf:.0%}。提取{len(entities)}个实体，识别{len(patterns)}个攻击模式。",
        },
        "fallback": True,
    }


@pipeline_router.get("/recent")
async def get_recent_intelligence(
    limit: int = Query(20, ge=1, le=200),
    request: Request = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    items = []
    vs = getattr(request.app.state, "vector_store", None)
    if vs:
        try:
            results = vs.search("threat intelligence", n_results=limit)
            if results and isinstance(results, list):
                items = results[:limit]
        except Exception as exc:
            logger.warning(f"Vector store search failed: {exc}")

    if not items:
        try:
            crud = IntelligenceCRUD(db)
            raw_items, _ = await crud.list_raw(offset=0, limit=limit)
            for item in raw_items:
                d = item.model_dump() if hasattr(item, "model_dump") else item
                items.append(d)
        except Exception as exc:
            logger.warning(f"Database query failed: {exc}")

    return {"items": items, "total": len(items)}


@pipeline_router.get("/entities")
async def get_extracted_entities(
    type: Optional[str] = None,
    keyword: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    request: Request = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    entities = []
    seen_values = set()
    try:
        remaining_needed = max(limit, 0)
        if remaining_needed > 0:
            stmt = (
                select(CleanedIntelligenceTable)
                .options(selectinload(CleanedIntelligenceTable.analyzed))
                .order_by(CleanedIntelligenceTable.cleaned_at.desc())
                .limit(remaining_needed)
            )
            result = await db.execute(stmt)
            rows = result.scalars().all()
        else:
            rows = []

        for row in rows:
            row_entities = safe_json_loads_list(row.entities_json)

            for entity in row_entities:
                if isinstance(entity, dict):
                    val = entity.get("value", "")
                    if val in seen_values:
                        continue
                    if type and entity.get("type") != type:
                        continue
                    if keyword and keyword.lower() not in str(val).lower():
                        continue
                    seen_values.add(val)
                    entities.append(entity)
                elif isinstance(entity, str):
                    if entity in seen_values:
                        continue
                    if keyword and keyword.lower() not in entity.lower():
                        continue
                    seen_values.add(entity)
                    entities.append({"type": "unknown", "value": entity})
    except Exception as exc:
        logger.warning(f"Failed to get entities from cleaned table: {exc}")

    if len(entities) < limit:
        try:
            raw_stmt = (
                select(RawIntelligenceTable)
                .order_by(RawIntelligenceTable.collected_at.desc())
                .limit(max(limit * 2, 100))
            )
            raw_result = await db.execute(raw_stmt)
            raw_rows = raw_result.scalars().all()

            for row in raw_rows:
                if not row.content:
                    continue
                extracted = rule_extractor.extract_entities(row.content)
                for entity in extracted:
                    val = entity.get("value", "")
                    if val in seen_values:
                        continue
                    if type and entity.get("type") != type:
                        continue
                    if keyword and keyword.lower() not in str(val).lower():
                        continue
                    seen_values.add(val)
                    entities.append(entity)
                    if len(entities) >= limit:
                        break
                if len(entities) >= limit:
                    break
        except Exception as exc:
            logger.warning(f"Failed to extract entities from raw table: {exc}")

    return {"entities": entities, "total": len(entities)}


@pipeline_router.get("/{intelligence_id}")
async def get_pipeline_intelligence_detail(
    intelligence_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    vs = getattr(request.app.state, "vector_store", None)
    if vs:
        try:
            results = vs.search(intelligence_id, n_results=1)
            if results and isinstance(results, list) and len(results) > 0:
                for r in results:
                    if isinstance(r, dict) and r.get("id") == intelligence_id:
                        return {"status": "success", "data": r}
        except Exception:
            pass

    try:
        crud = IntelligenceCRUD(db)
        raw = await crud.get_raw(intelligence_id)
        if raw is not None:
            return {"type": "raw", "data": raw.model_dump()}
        cleaned = await crud.get_cleaned(intelligence_id)
        if cleaned is not None:
            return {"type": "cleaned", "data": cleaned.model_dump()}
        analyzed = await crud.get_analyzed(intelligence_id)
        if analyzed is not None:
            return {"type": "analyzed", "data": analyzed.model_dump()}
    except Exception as exc:
        logger.warning(f"Database lookup failed: {exc}")

    raise HTTPException(status_code=404, detail="Intelligence not found")


@pipeline_router.post("/batch-validate")
async def batch_validate_intelligence(
    limit: int = Query(default=50, ge=1, le=200),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    try:
        from app.db.tables import RawIntelligenceTable, CleanedIntelligenceTable
        from sqlalchemy import select, func
        import re

        ip_pat = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        url_pat = re.compile(r'https?://[^\s]+')
        phone_pat = re.compile(r'1[3-9]\d{9}')
        email_pat = re.compile(r'[\w.+-]+@[\w-]+\.[\w.]+')

        result = await db.execute(
            select(RawIntelligenceTable).order_by(RawIntelligenceTable.collected_at.desc()).limit(limit)
        )
        intels = result.scalars().all()

        results = []
        for intel in intels:
            content = intel.content or ""
            issues = []
            quality_score = 1.0

            if len(content) < 20:
                issues.append("内容过短")
                quality_score -= 0.3
            if len(content) > 5000:
                issues.append("内容过长，可能含噪声")
                quality_score -= 0.1

            iocs = ip_pat.findall(content) + url_pat.findall(content) + phone_pat.findall(content) + email_pat.findall(content)
            if not iocs:
                issues.append("无有效IoC指标")
                quality_score -= 0.2

            duplicate_chars = len(content) - len(set(content))
            if duplicate_chars / max(len(content), 1) > 0.5:
                issues.append("疑似重复内容")
                quality_score -= 0.3

            has_chinese = bool(re.search(r'[\u4e00-\u9fff]', content))
            if not has_chinese and not iocs:
                issues.append("非中文且无结构化指标")
                quality_score -= 0.1

            quality_score = max(0.0, min(1.0, quality_score))
            results.append({
                "id": intel.id,
                "source": intel.source,
                "content_preview": content[:80],
                "quality_score": round(quality_score, 2),
                "ioc_count": len(iocs),
                "issues": issues,
                "status": "pass" if quality_score >= 0.6 else "review" if quality_score >= 0.3 else "fail",
            })

        pass_count = sum(1 for r in results if r["status"] == "pass")
        review_count = sum(1 for r in results if r["status"] == "review")
        fail_count = sum(1 for r in results if r["status"] == "fail")

        return {
            "total": len(results),
            "pass": pass_count,
            "review": review_count,
            "fail": fail_count,
            "average_quality": round(sum(r["quality_score"] for r in results) / max(len(results), 1), 2),
            "results": results,
        }
    except Exception as exc:
        logger.error(f"Batch validation failed: {exc}")
        raise HTTPException(status_code=500, detail="批量验证失败，请稍后重试")
