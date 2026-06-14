import asyncio
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query, Request, UploadFile, File
from fastapi.responses import Response
from loguru import logger
from pydantic import BaseModel, Field, model_validator

from app.core.auth import User, get_current_user, require_role, Role
from app.core.exceptions import AppException, ValidationException, NotFoundException
from app.config import settings


def _safe_json(obj):
    return json.loads(json.dumps(obj, default=str, ensure_ascii=False))

router = APIRouter(prefix="/intel-pipeline", tags=["intel-pipeline"])

_VALID_SOURCE_TYPES = {"forum", "wechat", "telegram", "darkweb", "commercial", "manual"}
_VALID_PRIORITIES = {"critical", "high", "medium", "low"}
_VALID_STATUSES = {"active", "paused", "disabled", "error"}


class SingleAnalyzeRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=50000, description="情报文本内容")
    source: str = Field(default="manual", max_length=64, description="情报来源标识")
    use_llm: bool = Field(default=True, description="是否使用LLM增强分析")


class BatchAnalyzeRequest(BaseModel):
    items: List[Dict[str, Any]] = Field(..., min_length=1, max_length=500, description="情报列表，每项需含content字段")
    use_llm: bool = Field(default=True, description="是否使用LLM增强分析")
    max_concurrent: int = Field(default=5, ge=1, le=20, description="最大并发数")


class SourceCreateRequest(BaseModel):
    source_id: str = Field(..., min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")
    name: str = Field(..., min_length=1, max_length=256)
    source_type: str = Field(..., description="采集源类型: forum/wechat/telegram/darkweb/commercial/manual")
    priority: str = Field(default="medium", description="优先级: critical/high/medium/low")
    interval_minutes: int = Field(default=30, ge=0, description="采集间隔(分钟)，0表示仅手动触发")
    max_results_per_cycle: int = Field(default=50, ge=1, le=500)
    keywords: List[str] = Field(default_factory=list, max_length=100)
    config: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_enums(self):
        if self.source_type not in _VALID_SOURCE_TYPES:
            raise ValueError(f"无效采集源类型: {self.source_type}, 有效值: {sorted(_VALID_SOURCE_TYPES)}")
        if self.priority not in _VALID_PRIORITIES:
            raise ValueError(f"无效优先级: {self.priority}, 有效值: {sorted(_VALID_PRIORITIES)}")
        return self


class SourceUpdateRequest(BaseModel):
    name: Optional[str] = None
    priority: Optional[str] = None
    status: Optional[str] = None
    interval_minutes: Optional[int] = None
    max_results_per_cycle: Optional[int] = None
    keywords: Optional[List[str]] = None
    config: Optional[Dict[str, Any]] = None

    @model_validator(mode="after")
    def validate_enums(self):
        if self.priority is not None and self.priority not in _VALID_PRIORITIES:
            raise ValueError(f"无效优先级: {self.priority}, 有效值: {sorted(_VALID_PRIORITIES)}")
        if self.status is not None and self.status not in _VALID_STATUSES:
            raise ValueError(f"无效状态: {self.status}, 有效值: {sorted(_VALID_STATUSES)}")
        return self


@router.post("/analyze")
async def analyze_single(
    data: SingleAnalyzeRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    pipeline = getattr(request.app.state, "intel_pipeline", None)
    if not pipeline:
        raise AppException(detail="情报分析流水线未初始化", error_code="SERVICE_NOT_AVAILABLE", status_code=503)

    item = {
        "id": f"manual_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
        "source": data.source,
        "content": data.content,
    }

    try:
        result = await pipeline.process_single(item, use_llm=data.use_llm)
        body = json.dumps({"success": True, "data": result.to_dict()}, default=str, ensure_ascii=False)
        return Response(content=body, media_type="application/json")
    except Exception as exc:
        logger.error("Analyze failed: %s", str(exc)[:200], exc_info=True)
        raise AppException(detail="情报分析处理失败，请稍后重试", error_code="ANALYSIS_ERROR", status_code=500)


@router.post("/analyze/batch")
async def analyze_batch(
    data: BatchAnalyzeRequest,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    pipeline = getattr(request.app.state, "intel_pipeline", None)
    if not pipeline:
        raise AppException(detail="情报分析流水线未初始化", error_code="SERVICE_NOT_AVAILABLE", status_code=503)

    for i, item in enumerate(data.items):
        if "content" not in item:
            raise ValidationException(detail=f"第{i+1}条情报缺少content字段")
        item.setdefault("id", f"batch_{i}_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}")
        item.setdefault("source", "batch_import")

    result = await pipeline.process_batch(data.items, use_llm=data.use_llm, max_concurrent=data.max_concurrent)

    stored = await pipeline.store_results(result.item_results)

    body = json.dumps({
        "status": "success",
        "data": result.to_dict(),
        "stored_count": stored,
    }, default=str, ensure_ascii=False)
    return Response(content=body, media_type="application/json")


@router.post("/import")
async def import_intelligence(
    items: List[Dict[str, Any]],
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    scheduler = getattr(request.app.state, "source_scheduler", None)
    if not scheduler:
        raise AppException(detail="采集调度器未初始化", error_code="SERVICE_NOT_AVAILABLE", status_code=503)

    result = await scheduler.import_items(items, source_name="api_import")
    return {"status": "success", "data": result}


@router.post("/import/file")
async def import_from_file(
    file: UploadFile = File(...),
    request: Request = None,
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    import json

    scheduler = getattr(request.app.state, "source_scheduler", None)
    if not scheduler:
        raise AppException(detail="采集调度器未初始化", error_code="SERVICE_NOT_AVAILABLE", status_code=503)

    max_size = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
    content = await file.read()
    if len(content) > max_size:
        raise ValidationException(detail=f"文件大小超过限制({settings.MAX_UPLOAD_SIZE_MB}MB)")
    filename = file.filename or "unknown"

    try:
        if filename.endswith(".json"):
            items = json.loads(content.decode("utf-8"))
            if isinstance(items, dict):
                items = [items]
        elif filename.endswith(".jsonl"):
            items = []
            for line in content.decode("utf-8").strip().split("\n"):
                if line.strip():
                    items.append(json.loads(line))
        elif filename.endswith(".csv"):
            import csv
            from io import StringIO
            reader = csv.DictReader(StringIO(content.decode("utf-8")))
            items = [row for row in reader]
        elif filename.endswith(".txt"):
            items = []
            for line in content.decode("utf-8").strip().split("\n"):
                if line.strip():
                    items.append({"content": line.strip(), "source": "txt_import"})
        else:
            raise ValidationException(detail=f"不支持的文件格式: {filename}")
    except json.JSONDecodeError:
        raise ValidationException(detail="JSON解析失败")
    except UnicodeDecodeError:
        raise ValidationException(detail="文件编码错误，请使用UTF-8编码")

    if not items:
        raise ValidationException(detail="文件中无有效数据")

    result = await scheduler.import_items(items, source_name=f"file:{filename}")
    return {"status": "success", "data": result, "filename": filename}


@router.get("/pipeline/stats")
async def get_pipeline_stats(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    pipeline = getattr(request.app.state, "intel_pipeline", None)
    if not pipeline:
        raise AppException(detail="情报分析流水线未初始化", error_code="SERVICE_NOT_AVAILABLE", status_code=503)

    return {"status": "success", "data": pipeline.get_stats()}


@router.get("/scheduler/stats")
async def get_scheduler_stats(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    scheduler = getattr(request.app.state, "source_scheduler", None)
    if not scheduler:
        raise AppException(detail="采集调度器未初始化", error_code="SERVICE_NOT_AVAILABLE", status_code=503)

    return {"status": "success", "data": scheduler.get_stats()}


@router.get("/scheduler/sources")
async def list_sources(
    status: Optional[str] = None,
    request: Request = None,
    current_user: User = Depends(get_current_user),
):
    scheduler = getattr(request.app.state, "source_scheduler", None)
    if not scheduler:
        raise AppException(detail="采集调度器未初始化", error_code="SERVICE_NOT_AVAILABLE", status_code=503)

    sources = scheduler.list_sources(status=status)
    return {"status": "success", "data": sources, "total": len(sources)}


@router.get("/scheduler/sources/{source_id}")
async def get_source(
    source_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    scheduler = getattr(request.app.state, "source_scheduler", None)
    if not scheduler:
        raise AppException(detail="采集调度器未初始化", error_code="SERVICE_NOT_AVAILABLE", status_code=503)

    source = scheduler.get_source(source_id)
    if not source:
        raise NotFoundException(detail=f"采集源 {source_id} 不存在")

    return {"status": "success", "data": source}


@router.post("/scheduler/sources")
async def create_source(
    data: SourceCreateRequest,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN)),
):
    from app.core.source_scheduler import SourceConfig, SourcePriority

    scheduler = getattr(request.app.state, "source_scheduler", None)
    if not scheduler:
        raise AppException(detail="采集调度器未初始化", error_code="SERVICE_NOT_AVAILABLE", status_code=503)

    if scheduler.get_source(data.source_id):
        raise AppException(detail=f"采集源 {data.source_id} 已存在", error_code="CONFLICT", status_code=409)

    try:
        priority = SourcePriority(data.priority)
    except ValueError:
        raise ValidationException(detail=f"无效优先级: {data.priority}")

    config = SourceConfig(
        source_id=data.source_id,
        name=data.name,
        source_type=data.source_type,
        priority=priority,
        interval_minutes=data.interval_minutes,
        max_results_per_cycle=data.max_results_per_cycle,
        keywords=data.keywords,
        config=data.config,
    )

    scheduler.add_source(config)
    return {"status": "success", "data": config.to_dict()}


@router.patch("/scheduler/sources/{source_id}")
async def update_source(
    source_id: str,
    data: SourceUpdateRequest,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN)),
):
    scheduler = getattr(request.app.state, "source_scheduler", None)
    if not scheduler:
        raise AppException(detail="采集调度器未初始化", error_code="SERVICE_NOT_AVAILABLE", status_code=503)

    updates = {k: v for k, v in data.model_dump().items() if v is not None}
    if not updates:
        raise ValidationException(detail="无更新内容")

    success = scheduler.update_source(source_id, updates)
    if not success:
        raise NotFoundException(detail=f"采集源 {source_id} 不存在")

    return {"status": "success", "message": f"采集源 {source_id} 已更新"}


@router.delete("/scheduler/sources/{source_id}")
async def delete_source(
    source_id: str,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN)),
):
    scheduler = getattr(request.app.state, "source_scheduler", None)
    if not scheduler:
        raise AppException(detail="采集调度器未初始化", error_code="SERVICE_NOT_AVAILABLE", status_code=503)

    success = scheduler.remove_source(source_id)
    if not success:
        raise NotFoundException(detail=f"采集源 {source_id} 不存在")

    return {"status": "success", "message": f"采集源 {source_id} 已删除"}


@router.post("/scheduler/trigger/{source_id}")
async def trigger_source_collection(
    source_id: str,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    scheduler = getattr(request.app.state, "source_scheduler", None)
    if not scheduler:
        raise AppException(detail="采集调度器未初始化", error_code="SERVICE_NOT_AVAILABLE", status_code=503)

    result = await scheduler.trigger_source(source_id)
    return {"status": "success", "data": result}


@router.post("/scheduler/trigger-all")
async def trigger_all_sources(
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN)),
):
    scheduler = getattr(request.app.state, "source_scheduler", None)
    if not scheduler:
        raise AppException(detail="采集调度器未初始化", error_code="SERVICE_NOT_AVAILABLE", status_code=503)

    result = await scheduler.trigger_all()
    return {"status": "success", "data": result.to_dict()}


@router.get("/scheduler/history")
async def get_collection_history(
    limit: int = Query(20, ge=1, le=100),
    request: Request = None,
    current_user: User = Depends(get_current_user),
):
    scheduler = getattr(request.app.state, "source_scheduler", None)
    if not scheduler:
        raise AppException(detail="采集调度器未初始化", error_code="SERVICE_NOT_AVAILABLE", status_code=503)

    history = scheduler.get_cycle_history(limit=limit)
    return {"status": "success", "data": history, "total": len(history)}


@router.get("/cheating-scenarios")
async def get_cheating_scenarios(
    current_user: User = Depends(get_current_user),
):
    from app.core.intel_pipeline import CHEATING_SCENARIOS
    scenarios = []
    for key, info in CHEATING_SCENARIOS.items():
        scenarios.append({
            "scenario_id": key,
            "label": info["label"],
            "severity": info["severity"],
            "keyword_count": len(info["keywords"]),
            "keywords": info["keywords"],
        })
    return {"status": "success", "data": scenarios, "total": len(scenarios)}


@router.get("/intent-levels")
async def get_intent_levels(
    current_user: User = Depends(get_current_user),
):
    from app.core.intel_pipeline import IntentLevel, HIGH_RISK_INTENT_PATTERNS
    levels = [
        {"level": IntentLevel.BENIGN.value, "label": "正常", "description": "无恶意意图"},
        {"level": IntentLevel.SUSPICIOUS.value, "label": "可疑", "description": "存在可疑行为特征"},
        {"level": IntentLevel.MALICIOUS.value, "label": "恶意", "description": "具有明确恶意意图"},
        {"level": IntentLevel.CRITICAL.value, "label": "高危", "description": "高危意图，需立即处置"},
    ]
    patterns = []
    for key, info in HIGH_RISK_INTENT_PATTERNS.items():
        patterns.append({
            "pattern_id": key,
            "label": info["label"],
            "weight": info["weight"],
            "indicators": info["indicators"],
        })
    return {"status": "success", "data": {"levels": levels, "intent_patterns": patterns}}


@router.get("/slang-dictionary")
async def get_slang_dictionary(
    keyword: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    current_user: User = Depends(get_current_user),
):
    from app.core.intel_pipeline import SLANG_DICTIONARY_EXTENDED
    result = []
    for slang, meaning in SLANG_DICTIONARY_EXTENDED.items():
        if keyword and keyword.lower() not in slang.lower() and keyword.lower() not in meaning.lower():
            continue
        result.append({"slang": slang, "meaning": meaning})
        if len(result) >= limit:
            break
    return {"status": "success", "data": result, "total": len(result)}


class SlangAddRequest(BaseModel):
    slang: str = Field(..., min_length=1, max_length=64)
    meaning: str = Field(..., min_length=1, max_length=512)


class SlangUpdateRequest(BaseModel):
    meaning: str = Field(..., min_length=1, max_length=512)


class ConfigUpdateRequest(BaseModel):
    dedup_threshold: Optional[float] = Field(None, ge=0.0, le=1.0)
    risk_level_weights: Optional[Dict[str, float]] = None
    risk_intent_weights: Optional[Dict[str, float]] = None


class ExportRequest(BaseModel):
    format: str = Field(default="json", pattern=r"^(json|csv)$")
    intent_level: Optional[str] = None
    threat_level: Optional[str] = None
    source: Optional[str] = None
    date_from: Optional[str] = None
    date_to: Optional[str] = None
    min_risk_score: Optional[float] = None


class BatchDeleteRequest(BaseModel):
    before_date: Optional[str] = None
    intent_level: Optional[str] = None
    threat_level: Optional[str] = None


@router.get("/results")
async def query_results(
    intent_level: Optional[str] = None,
    threat_level: Optional[str] = None,
    source: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    min_risk_score: Optional[float] = None,
    sort_by: str = Query("analyzed_at", pattern=r"^(risk_score|analyzed_at)$"),
    sort_order: str = Query("desc", pattern=r"^(desc|asc)$"),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(get_current_user),
):
    from app.db.database import async_session_factory
    from app.db.tables import AnalyzedIntelligenceTable, CleanedIntelligenceTable, RawIntelligenceTable
    from sqlalchemy import select, func, desc, asc

    async with async_session_factory() as db:
        stmt = (
            select(AnalyzedIntelligenceTable, CleanedIntelligenceTable, RawIntelligenceTable)
            .join(CleanedIntelligenceTable, AnalyzedIntelligenceTable.cleaned_id == CleanedIntelligenceTable.id)
            .join(RawIntelligenceTable, CleanedIntelligenceTable.raw_id == RawIntelligenceTable.id)
        )
        count_stmt = (
            select(func.count())
            .select_from(AnalyzedIntelligenceTable)
            .join(CleanedIntelligenceTable, AnalyzedIntelligenceTable.cleaned_id == CleanedIntelligenceTable.id)
            .join(RawIntelligenceTable, CleanedIntelligenceTable.raw_id == RawIntelligenceTable.id)
        )

        if threat_level:
            stmt = stmt.where(AnalyzedIntelligenceTable.threat_level == threat_level)
            count_stmt = count_stmt.where(AnalyzedIntelligenceTable.threat_level == threat_level)

        if source:
            stmt = stmt.where(RawIntelligenceTable.source == source)
            count_stmt = count_stmt.where(RawIntelligenceTable.source == source)

        if intent_level:
            intent_cond = AnalyzedIntelligenceTable.evidence_refs_json.like(
                f'%"intent_level": "{intent_level}"%'
            )
            stmt = stmt.where(intent_cond)
            count_stmt = count_stmt.where(intent_cond)

        if date_from:
            try:
                dt_from = datetime.fromisoformat(date_from)
            except ValueError:
                raise ValidationException(detail="date_from 格式无效，请使用ISO格式")
            stmt = stmt.where(AnalyzedIntelligenceTable.analyzed_at >= dt_from)
            count_stmt = count_stmt.where(AnalyzedIntelligenceTable.analyzed_at >= dt_from)

        if date_to:
            try:
                dt_to = datetime.fromisoformat(date_to)
            except ValueError:
                raise ValidationException(detail="date_to 格式无效，请使用ISO格式")
            stmt = stmt.where(AnalyzedIntelligenceTable.analyzed_at <= dt_to)
            count_stmt = count_stmt.where(AnalyzedIntelligenceTable.analyzed_at <= dt_to)

        if min_risk_score is not None:
            stmt = stmt.where(AnalyzedIntelligenceTable.confidence_score >= min_risk_score)
            count_stmt = count_stmt.where(AnalyzedIntelligenceTable.confidence_score >= min_risk_score)

        total_result = await db.execute(count_stmt)
        total = total_result.scalar() or 0

        sort_col = (
            AnalyzedIntelligenceTable.confidence_score
            if sort_by == "risk_score"
            else AnalyzedIntelligenceTable.analyzed_at
        )
        stmt = stmt.order_by(desc(sort_col) if sort_order == "desc" else asc(sort_col))
        stmt = stmt.offset(offset).limit(limit)

        result = await db.execute(stmt)
        rows = result.all()

        items = []
        for analyzed, cleaned, raw in rows:
            evidence_refs = {}
            try:
                evidence_refs = json.loads(analyzed.evidence_refs_json) if analyzed.evidence_refs_json else {}
            except (json.JSONDecodeError, TypeError):
                pass

            items.append({
                "id": analyzed.id,
                "source": raw.source,
                "threat_level": analyzed.threat_level,
                "intent_level": evidence_refs.get("intent_level", "benign"),
                "risk_score": analyzed.confidence_score,
                "quality_score": evidence_refs.get("quality_score", 0.0),
                "analysis_summary": analyzed.analysis_summary,
                "analyzed_at": analyzed.analyzed_at.isoformat() if analyzed.analyzed_at else None,
                "collected_at": raw.collected_at.isoformat() if raw.collected_at else None,
            })

        body = json.dumps({
            "status": "success",
            "data": items,
            "total": total,
            "offset": offset,
            "limit": limit,
        }, default=str, ensure_ascii=False)
        return Response(content=body, media_type="application/json")


@router.post("/results/export")
async def export_results(
    data: ExportRequest,
    current_user: User = Depends(get_current_user),
):
    import csv
    from io import StringIO
    from app.db.database import async_session_factory
    from app.db.tables import AnalyzedIntelligenceTable, CleanedIntelligenceTable, RawIntelligenceTable
    from sqlalchemy import select, desc

    async with async_session_factory() as db:
        stmt = (
            select(AnalyzedIntelligenceTable, CleanedIntelligenceTable, RawIntelligenceTable)
            .join(CleanedIntelligenceTable, AnalyzedIntelligenceTable.cleaned_id == CleanedIntelligenceTable.id)
            .join(RawIntelligenceTable, CleanedIntelligenceTable.raw_id == RawIntelligenceTable.id)
        )

        if data.threat_level:
            stmt = stmt.where(AnalyzedIntelligenceTable.threat_level == data.threat_level)
        if data.source:
            stmt = stmt.where(RawIntelligenceTable.source == data.source)
        if data.intent_level:
            stmt = stmt.where(
                AnalyzedIntelligenceTable.evidence_refs_json.like(
                    f'%"intent_level": "{data.intent_level}"%'
                )
            )
        if data.date_from:
            try:
                dt_from = datetime.fromisoformat(data.date_from)
                stmt = stmt.where(AnalyzedIntelligenceTable.analyzed_at >= dt_from)
            except ValueError:
                raise ValidationException(detail="date_from 格式无效，请使用ISO格式")
        if data.date_to:
            try:
                dt_to = datetime.fromisoformat(data.date_to)
                stmt = stmt.where(AnalyzedIntelligenceTable.analyzed_at <= dt_to)
            except ValueError:
                raise ValidationException(detail="date_to 格式无效，请使用ISO格式")
        if data.min_risk_score is not None:
            stmt = stmt.where(AnalyzedIntelligenceTable.confidence_score >= data.min_risk_score)

        stmt = stmt.order_by(desc(AnalyzedIntelligenceTable.analyzed_at)).limit(5000)
        result = await db.execute(stmt)
        rows = result.all()

        items = []
        for analyzed, cleaned, raw in rows:
            evidence_refs = {}
            try:
                evidence_refs = json.loads(analyzed.evidence_refs_json) if analyzed.evidence_refs_json else {}
            except (json.JSONDecodeError, TypeError):
                pass

            items.append({
                "id": analyzed.id,
                "source": raw.source,
                "threat_level": analyzed.threat_level,
                "intent_level": evidence_refs.get("intent_level", "benign"),
                "risk_score": analyzed.confidence_score,
                "quality_score": evidence_refs.get("quality_score", 0.0),
                "analysis_summary": analyzed.analysis_summary,
                "content": cleaned.content[:500] if cleaned.content else "",
                "analyzed_at": analyzed.analyzed_at.isoformat() if analyzed.analyzed_at else None,
                "collected_at": raw.collected_at.isoformat() if raw.collected_at else None,
            })

    if data.format == "csv":
        output = StringIO()
        if items:
            writer = csv.DictWriter(output, fieldnames=items[0].keys())
            writer.writeheader()
            writer.writerows(items)
        content = "\ufeff" + output.getvalue()
        return Response(
            content=content,
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": "attachment; filename=intel_results.csv"},
        )

    content = json.dumps(items, default=str, ensure_ascii=False, indent=2)
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=intel_results.json"},
    )


@router.delete("/results/batch")
async def batch_delete_results(
    data: BatchDeleteRequest,
    current_user: User = Depends(require_role(Role.ADMIN)),
):
    from app.db.database import async_session_factory
    from app.db.tables import AnalyzedIntelligenceTable, CleanedIntelligenceTable, RawIntelligenceTable
    from sqlalchemy import select, delete

    if not data.before_date and not data.intent_level and not data.threat_level:
        raise ValidationException(detail="至少需要提供一个删除条件")

    async with async_session_factory() as db:
        stmt = select(AnalyzedIntelligenceTable)

        if data.threat_level:
            stmt = stmt.where(AnalyzedIntelligenceTable.threat_level == data.threat_level)
        if data.intent_level:
            safe_intent = data.intent_level.replace("%", "\\%").replace("_", "\\_")
            stmt = stmt.where(
                AnalyzedIntelligenceTable.evidence_refs_json.like(
                    f'%"intent_level": "{safe_intent}"%'
                )
            )
        if data.before_date:
            try:
                dt_before = datetime.fromisoformat(data.before_date)
                stmt = stmt.where(AnalyzedIntelligenceTable.analyzed_at < dt_before)
            except ValueError:
                raise ValidationException(detail="before_date 格式无效，请使用ISO格式")

        result = await db.execute(stmt)
        analyzed_rows = result.scalars().all()

        if not analyzed_rows:
            return {"status": "success", "deleted_count": 0}

        cleaned_ids = [row.cleaned_id for row in analyzed_rows]

        cleaned_stmt = select(CleanedIntelligenceTable).where(
            CleanedIntelligenceTable.id.in_(cleaned_ids)
        )
        cleaned_result = await db.execute(cleaned_stmt)
        cleaned_rows = cleaned_result.scalars().all()
        raw_ids = [row.raw_id for row in cleaned_rows]

        await db.execute(
            delete(AnalyzedIntelligenceTable).where(
                AnalyzedIntelligenceTable.cleaned_id.in_(cleaned_ids)
            )
        )
        await db.execute(
            delete(CleanedIntelligenceTable).where(
                CleanedIntelligenceTable.id.in_(cleaned_ids)
            )
        )
        await db.execute(
            delete(RawIntelligenceTable).where(
                RawIntelligenceTable.id.in_(raw_ids)
            )
        )
        await db.commit()

        return {"status": "success", "deleted_count": len(analyzed_rows)}


@router.get("/results/{result_id}")
async def get_result_detail(
    result_id: str,
    current_user: User = Depends(get_current_user),
):
    from app.db.database import async_session_factory
    from app.db.tables import AnalyzedIntelligenceTable, CleanedIntelligenceTable, RawIntelligenceTable
    from sqlalchemy import select

    async with async_session_factory() as db:
        stmt = (
            select(AnalyzedIntelligenceTable, CleanedIntelligenceTable, RawIntelligenceTable)
            .join(CleanedIntelligenceTable, AnalyzedIntelligenceTable.cleaned_id == CleanedIntelligenceTable.id)
            .join(RawIntelligenceTable, CleanedIntelligenceTable.raw_id == RawIntelligenceTable.id)
            .where(AnalyzedIntelligenceTable.id == result_id)
        )
        result = await db.execute(stmt)
        row = result.first()

        if not row:
            raise NotFoundException(detail=f"分析结果 {result_id} 不存在")

        analyzed, cleaned, raw = row

        evidence_refs = {}
        try:
            evidence_refs = json.loads(analyzed.evidence_refs_json) if analyzed.evidence_refs_json else {}
        except (json.JSONDecodeError, TypeError):
            pass

        entities = []
        try:
            entities = json.loads(cleaned.entities_json) if cleaned.entities_json else []
        except (json.JSONDecodeError, TypeError):
            pass

        blacktalk_terms = {}
        try:
            blacktalk_terms = json.loads(cleaned.blacktalk_terms_json) if cleaned.blacktalk_terms_json else {}
        except (json.JSONDecodeError, TypeError):
            pass

        threat_categories = []
        try:
            threat_categories = json.loads(analyzed.threat_categories_json) if analyzed.threat_categories_json else []
        except (json.JSONDecodeError, TypeError):
            pass

        attack_patterns = []
        try:
            attack_patterns = json.loads(analyzed.attack_patterns_json) if analyzed.attack_patterns_json else []
        except (json.JSONDecodeError, TypeError):
            pass

        technique_chain = []
        try:
            technique_chain = json.loads(analyzed.technique_chain_json) if analyzed.technique_chain_json else []
        except (json.JSONDecodeError, TypeError):
            pass

        metadata = {}
        try:
            metadata = json.loads(raw.metadata_json) if raw.metadata_json else {}
        except (json.JSONDecodeError, TypeError):
            pass

        data = {
            "id": analyzed.id,
            "raw": {
                "id": raw.id,
                "source": raw.source,
                "source_url": raw.source_url,
                "content": raw.content,
                "raw_content": raw.raw_content,
                "collected_at": raw.collected_at.isoformat() if raw.collected_at else None,
                "status": raw.status,
                "metadata": metadata,
            },
            "cleaned": {
                "id": cleaned.id,
                "content": cleaned.content,
                "decoded_content": cleaned.decoded_content,
                "blacktalk_terms": blacktalk_terms,
                "entities": entities,
                "threat_level": cleaned.threat_level,
                "cleaned_at": cleaned.cleaned_at.isoformat() if cleaned.cleaned_at else None,
            },
            "analyzed": {
                "id": analyzed.id,
                "threat_level": analyzed.threat_level,
                "threat_categories": threat_categories,
                "attack_patterns": attack_patterns,
                "technique_chain": technique_chain,
                "confidence_score": analyzed.confidence_score,
                "analysis_summary": analyzed.analysis_summary,
                "analyzed_at": analyzed.analyzed_at.isoformat() if analyzed.analyzed_at else None,
                "intent_level": evidence_refs.get("intent_level", "benign"),
                "intent_indicators": evidence_refs.get("intent_indicators", []),
                "cheating_scenarios": evidence_refs.get("cheating_scenarios", []),
                "quality_score": evidence_refs.get("quality_score", 0.0),
                "risk_score": analyzed.confidence_score,
            },
        }

        body = json.dumps({"status": "success", "data": data}, default=str, ensure_ascii=False)
        return Response(content=body, media_type="application/json")


@router.get("/config")
async def get_pipeline_config(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    pipeline = getattr(request.app.state, "intel_pipeline", None)
    if not pipeline:
        raise AppException(detail="情报分析流水线未初始化", error_code="SERVICE_NOT_AVAILABLE", status_code=503)

    from app.core.intel_pipeline import CHEATING_SCENARIOS, HIGH_RISK_INTENT_PATTERNS

    config = {
        "dedup_threshold": pipeline._deduplicator._similarity_threshold,
        "risk_level_weights": pipeline._risk_scorer._level_weights,
        "risk_intent_weights": pipeline._risk_scorer._intent_weights,
        "intent_patterns": {
            key: {
                "label": info["label"],
                "weight": info["weight"],
                "indicators": info["indicators"],
            }
            for key, info in HIGH_RISK_INTENT_PATTERNS.items()
        },
        "cheating_scenarios": {
            key: {
                "label": info["label"],
                "severity": info["severity"],
                "keywords": info["keywords"],
            }
            for key, info in CHEATING_SCENARIOS.items()
        },
    }

    body = json.dumps({"status": "success", "data": config}, default=str, ensure_ascii=False)
    return Response(content=body, media_type="application/json")


@router.put("/config")
async def update_pipeline_config(
    data: ConfigUpdateRequest,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN)),
):
    pipeline = getattr(request.app.state, "intel_pipeline", None)
    if not pipeline:
        raise AppException(detail="情报分析流水线未初始化", error_code="SERVICE_NOT_AVAILABLE", status_code=503)

    updates = {}
    if data.dedup_threshold is not None:
        pipeline._deduplicator._similarity_threshold = data.dedup_threshold
        updates["dedup_threshold"] = data.dedup_threshold

    if data.risk_level_weights is not None:
        pipeline._risk_scorer._level_weights.update(data.risk_level_weights)
        updates["risk_level_weights"] = pipeline._risk_scorer._level_weights

    if data.risk_intent_weights is not None:
        pipeline._risk_scorer._intent_weights.update(data.risk_intent_weights)
        updates["risk_intent_weights"] = pipeline._risk_scorer._intent_weights

    if not updates:
        raise ValidationException(detail="无更新内容")

    logger.info(
        "Pipeline config updated by %s: %s",
        current_user.username,
        list(updates.keys()),
    )

    body = json.dumps({"status": "success", "data": updates}, default=str, ensure_ascii=False)
    return Response(content=body, media_type="application/json")


@router.post("/slang-dictionary")
async def add_slang(
    data: SlangAddRequest,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    from app.core.intel_pipeline import SLANG_DICTIONARY_EXTENDED

    if data.slang in SLANG_DICTIONARY_EXTENDED:
        raise AppException(
            detail=f"黑话术语 '{data.slang}' 已存在",
            error_code="CONFLICT",
            status_code=409,
        )

    SLANG_DICTIONARY_EXTENDED[data.slang] = data.meaning

    pipeline = getattr(request.app.state, "intel_pipeline", None)
    if pipeline and hasattr(pipeline, "_extractor") and hasattr(pipeline._extractor, "_slang_dict"):
        pipeline._extractor._slang_dict[data.slang] = data.meaning

    return {"status": "success", "data": {"slang": data.slang, "meaning": data.meaning}}


@router.put("/slang-dictionary/{slang}")
async def update_slang(
    slang: str,
    data: SlangUpdateRequest,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    from app.core.intel_pipeline import SLANG_DICTIONARY_EXTENDED

    if slang not in SLANG_DICTIONARY_EXTENDED:
        raise NotFoundException(detail=f"黑话术语 '{slang}' 不存在")

    SLANG_DICTIONARY_EXTENDED[slang] = data.meaning

    pipeline = getattr(request.app.state, "intel_pipeline", None)
    if pipeline and hasattr(pipeline, "_extractor") and hasattr(pipeline._extractor, "_slang_dict"):
        pipeline._extractor._slang_dict[slang] = data.meaning

    return {"status": "success", "data": {"slang": slang, "meaning": data.meaning}}


@router.delete("/slang-dictionary/{slang}")
async def delete_slang(
    slang: str,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN)),
):
    from app.core.intel_pipeline import SLANG_DICTIONARY_EXTENDED

    if slang not in SLANG_DICTIONARY_EXTENDED:
        raise NotFoundException(detail=f"黑话术语 '{slang}' 不存在")

    del SLANG_DICTIONARY_EXTENDED[slang]

    pipeline = getattr(request.app.state, "intel_pipeline", None)
    if pipeline and hasattr(pipeline, "_extractor") and hasattr(pipeline._extractor, "_slang_dict"):
        pipeline._extractor._slang_dict.pop(slang, None)

    return {"status": "success", "message": f"黑话术语 '{slang}' 已删除"}


@router.get("/sources")
async def list_sources_alias(
    status: Optional[str] = None,
    request: Request = None,
    current_user: User = Depends(get_current_user),
):
    return await list_sources(status=status, request=request, current_user=current_user)
