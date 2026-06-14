import asyncio
import hashlib
import json
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from loguru import logger
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.auth import User, get_current_user, require_role, Role
from app.core.llm import LLMService, DEEPSEEK_THREAT_INTEL_SYSTEM
from app.db.database import async_session_factory, get_db
from app.db.tables import RawIntelligenceTable, CleanedIntelligenceTable, AnalysisResultTable

router = APIRouter(prefix="/deepseek", tags=["deepseek"])


class AnalyzeRequest(BaseModel):
    analysis_type: str = Field(
        default="classify",
        description="分析类型: classify/validate/summarize/full",
    )
    limit: int = Field(default=20, ge=1, le=50)
    source: Optional[str] = None
    threat_level: Optional[str] = None


class SingleAnalyzeRequest(BaseModel):
    content: str = Field(..., min_length=1)
    analysis_type: str = Field(
        default="full",
        description="分析类型: classify/validate/summarize/full",
    )


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1)
    context: Optional[str] = None
    enable_web_search: bool = Field(default=True, description="是否启用网络搜索获取实时信息")
    enable_intel_context: bool = Field(default=True, description="是否自动注入项目情报数据作为上下文")


class SwitchModelRequest(BaseModel):
    model_id: str = Field(..., min_length=1)


class CustomModelRequest(BaseModel):
    name: str = Field(..., min_length=1)
    provider: str = Field(default="openai_compatible")
    base_url: str = Field(..., min_length=1)
    api_key: str = Field(..., min_length=1)
    model_name: str = Field(..., min_length=1)
    temperature: float = Field(default=0.7, ge=0.0, le=2.0)
    max_tokens: int = Field(default=4096, ge=1, le=32768)


def _get_llm(request: Request) -> LLMService:
    llm = getattr(request.app.state, "llm", None)
    if llm is None:
        raise HTTPException(status_code=503, detail="DeepSeek LLM service not available")
    return llm


@router.get("/models")
async def list_models(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    llm = _get_llm(request)
    models = llm.list_models()
    return {"models": models, "total": len(models)}


@router.post("/models/switch")
async def switch_model(
    data: SwitchModelRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    llm = _get_llm(request)
    success = await llm.switch_model(data.model_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Model '{data.model_id}' not found")
    current = llm.get_current_model()
    return {"status": "success", "current_model": current}


@router.post("/models/custom")
async def add_custom_model(
    data: CustomModelRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    llm = _get_llm(request)
    config = {
        "name": data.name,
        "provider": data.provider,
        "base_url": data.base_url,
        "api_key": data.api_key,
        "model_name": data.model_name,
        "temperature": data.temperature,
        "max_tokens": data.max_tokens,
    }
    model_id = llm.add_custom_model(config)
    return {"status": "success", "model_id": model_id}


@router.delete("/models/custom/{model_id}")
async def remove_custom_model(
    model_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    llm = _get_llm(request)
    success = llm.remove_custom_model(model_id)
    if not success:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot remove model '{model_id}'. It may be a preset model, the current active model, or not exist.",
        )
    return {"status": "success", "removed": model_id}


@router.get("/models/current")
async def get_current_model(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    llm = _get_llm(request)
    current = llm.get_current_model()
    return current


async def _build_intel_context(request: Request, message: str, enable_web_search: bool = True, enable_intel_context: bool = True, db_session=None) -> str:
    context_parts = []

    if enable_intel_context:
        try:
            if db_session is not None:
                stmt = select(RawIntelligenceTable).order_by(
                    RawIntelligenceTable.collected_at.desc()
                ).limit(5)
                result = await db_session.execute(stmt)
                recent_items = result.scalars().all()
            else:
                async with async_session_factory() as db:
                    stmt = select(RawIntelligenceTable).order_by(
                        RawIntelligenceTable.collected_at.desc()
                    ).limit(5)
                    result = await db.execute(stmt)
                    recent_items = result.scalars().all()
            if recent_items:
                lines = ["【系统近期采集的情报数据】"]
                for i, item in enumerate(recent_items, 1):
                    content_preview = (item.content or "")[:150]
                    source = item.source or "未知来源"
                    threat = item.threat_level or "未评估"
                    collected = item.collected_at.strftime("%Y-%m-%d %H:%M") if item.collected_at else "未知时间"
                    lines.append(f"{i}. [{source}|{threat}|{collected}] {content_preview}")
                context_parts.append("\n".join(lines))
        except Exception as exc:
            logger.warning(f"Failed to fetch recent intelligence for chat context: {exc}")

        try:
            bt_engine = getattr(request.app.state, "blacktalk_engine", None)
            if bt_engine:
                all_terms = await bt_engine.get_all()
                if all_terms:
                    lines = ["【系统暗语/黑话库（最新更新）】"]
                    for t in all_terms[:10]:
                        lines.append(f"「{t.term}」= {t.meaning}")
                    context_parts.append("\n".join(lines))
        except Exception as exc:
            logger.warning(f"Failed to fetch blacktalk terms for chat context: {exc}")

        try:
            kg = getattr(request.app.state, "knowledge_graph", None)
            if kg:
                stats = await kg.get_statistics()
                if stats:
                    lines = [
                        "【知识图谱实时数据】",
                        f"实体总数: {stats.get('node_count', 0)}",
                        f"关系总数: {stats.get('edge_count', 0)}",
                    ]
                    entity_types = stats.get("entity_types", {})
                    if entity_types:
                        type_str = ", ".join(f"{k}:{v}" for k, v in list(entity_types.items())[:8])
                        lines.append(f"实体类型分布: {type_str}")
                    context_parts.append("\n".join(lines))
        except Exception as exc:
            logger.warning(f"Failed to fetch knowledge graph stats for chat context: {exc}")

    if enable_web_search:
        try:
            from app.core.web_search import web_search_service
            search_query = message
            if len(message) > 50:
                search_query = message[:50]
            results = await web_search_service.search(search_query, max_results=3)
            if results:
                search_context = web_search_service.format_results_for_context(results)
                context_parts.append(search_context)
        except Exception as exc:
            logger.warning(f"Web search failed for chat context: {exc}")

    return "\n\n".join(context_parts) if context_parts else ""


async def _persist_analysis(
    analysis_type: str,
    input_content: str,
    result: Any,
    user_id: Optional[str] = None,
    token_count: int = 0,
    db_session=None,
):
    try:
        if db_session is not None:
            content_hash = hashlib.sha256(input_content.encode()).hexdigest()[:16]
            record = AnalysisResultTable(
                id=f"ar_{content_hash}_{analysis_type}",
                analysis_type=analysis_type,
                input_content=input_content[:2000],
                result_json=json.dumps(result, ensure_ascii=False, default=str),
                model_name="deepseek-chat",
                token_count=token_count,
                user_id=user_id,
            )
            db_session.add(record)
            await db_session.commit()
        else:
            async with async_session_factory() as db:
                content_hash = hashlib.sha256(input_content.encode()).hexdigest()[:16]
                record = AnalysisResultTable(
                    id=f"ar_{content_hash}_{analysis_type}",
                    analysis_type=analysis_type,
                    input_content=input_content[:2000],
                    result_json=json.dumps(result, ensure_ascii=False, default=str),
                    model_name="deepseek-chat",
                    token_count=token_count,
                    user_id=user_id,
                )
                db.add(record)
                await db.commit()
    except Exception as exc:
        logger.warning(f"Failed to persist analysis result: {exc}")


@router.get("/analysis-history")
async def analysis_history(
    request: Request,
    current_user: User = Depends(get_current_user),
    analysis_type: Optional[str] = Query(None, description="筛选分析类型"),
    limit: int = Query(20, ge=1, le=50),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    try:
        stmt = select(AnalysisResultTable).order_by(AnalysisResultTable.created_at.desc())
        if analysis_type:
            stmt = stmt.where(AnalysisResultTable.analysis_type == analysis_type)
        stmt = stmt.offset(offset).limit(limit)
        result = await db.execute(stmt)
        rows = result.scalars().all()
        count_stmt = select(func.count(AnalysisResultTable.id))
        if analysis_type:
            count_stmt = count_stmt.where(AnalysisResultTable.analysis_type == analysis_type)
        total = (await db.execute(count_stmt)).scalar() or 0
        return {
            "items": [
                {
                    "id": r.id,
                    "analysis_type": r.analysis_type,
                    "input_content": (r.input_content or "")[:200],
                    "result_json": r.result_json,
                    "model_name": r.model_name,
                    "token_count": r.token_count,
                    "user_id": r.user_id,
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                }
                for r in rows
            ],
            "total": total,
            "offset": offset,
            "limit": limit,
        }
    except Exception as exc:
        logger.warning(f"Failed to query analysis history: {exc}")
        return {"items": [], "total": 0, "offset": offset, "limit": limit}


@router.get("/status")
async def deepseek_status(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    llm = _get_llm(request)
    stats = llm.usage_stats
    return {
        "status": "online" if llm.api_key and llm.api_key != "sk-your-api-key-here" else "not_configured",
        "model": stats["model"],
        "provider": stats["provider"],
        "request_count": stats["request_count"],
        "total_tokens": stats["total_tokens"],
    }


@router.post("/analyze")
async def analyze_intelligence(
    data: AnalyzeRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    llm = _get_llm(request)
    items = []

    try:
        stmt = select(RawIntelligenceTable)
        if data.source:
            stmt = stmt.where(RawIntelligenceTable.source == data.source)
        stmt = stmt.order_by(RawIntelligenceTable.collected_at.desc()).limit(data.limit)
        result = await db.execute(stmt)
        rows = result.scalars().all()

        for row in rows:
            items.append({
                "id": str(row.id),
                "content": row.content or "",
                "source": row.source,
                "collected_at": row.collected_at.isoformat() if row.collected_at else None,
            })

        if len(items) < data.limit:
            cleaned_stmt = (
                select(CleanedIntelligenceTable)
                .order_by(CleanedIntelligenceTable.cleaned_at.desc())
                .limit(data.limit - len(items))
            )
            cleaned_result = await db.execute(cleaned_stmt)
            cleaned_rows = cleaned_result.scalars().all()
            for row in cleaned_rows:
                items.append({
                    "id": str(row.id),
                    "content": row.content or "",
                    "source": "cleaned",
                    "collected_at": row.cleaned_at.isoformat() if row.cleaned_at else None,
                })
    except Exception as exc:
        logger.warning(f"Failed to load intelligence from DB: {exc}")

    if not items:
        raise HTTPException(status_code=404, detail="No intelligence data found for analysis")

    try:
        result = await asyncio.wait_for(
            llm.analyze_intelligence_batch(items, analysis_type=data.analysis_type),
            timeout=120.0,
        )
        await _persist_analysis(
            analysis_type=data.analysis_type,
            input_content=json.dumps([i["content"][:200] for i in items], ensure_ascii=False),
            result=result,
            user_id=current_user.id,
            db_session=db,
        )
        return result
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="DeepSeek analysis timed out (120s)")
    except Exception as exc:
        logger.error(f"DeepSeek analysis failed: {exc}")
        raise HTTPException(status_code=500, detail="操作失败")


@router.post("/analyze-single")
async def analyze_single(
    data: SingleAnalyzeRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    llm = _get_llm(request)
    items = [{"content": data.content}]

    try:
        result = await asyncio.wait_for(
            llm.analyze_intelligence_batch(items, analysis_type=data.analysis_type),
            timeout=60.0,
        )
        await _persist_analysis(
            analysis_type=f"single_{data.analysis_type}",
            input_content=data.content[:2000],
            result=result,
            user_id=current_user.id,
        )
        return result
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="DeepSeek analysis timed out")
    except Exception as exc:
        logger.error(f"DeepSeek single analysis failed: {exc}")
        raise HTTPException(status_code=500, detail="操作失败")


@router.post("/chat")
async def deepseek_chat(
    data: ChatRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    llm = _get_llm(request)

    auto_context = await _build_intel_context(
        request,
        data.message,
        enable_web_search=data.enable_web_search,
        enable_intel_context=data.enable_intel_context,
        db_session=db,
    )

    context_parts = []
    if auto_context:
        context_parts.append(auto_context)
    if data.context:
        context_parts.append(f"用户补充上下文：\n{data.context[:2000]}")

    context_str = ""
    if context_parts:
        context_str = "\n\n".join(context_parts)

    prompt = f"{data.message}"
    if context_str:
        prompt = f"{data.message}\n\n以下是为你提供的实时参考数据，请结合这些数据回答用户问题：\n{context_str}"

    system_msg = (
        DEEPSEEK_THREAT_INTEL_SYSTEM
        + "\n\n你现在拥有实时数据能力：\n"
        "1. 系统会自动为你提供最近采集的情报数据、暗语库、知识图谱统计等实时信息\n"
        "2. 系统会自动为你搜索网络获取最新信息\n"
        "3. 你必须优先使用这些实时数据来回答问题，而不是依赖自身训练数据\n"
        "4. 如果实时数据与你的训练知识有冲突，以实时数据为准\n"
        "5. 回答时请说明信息来源（如'根据系统最新情报'或'根据网络搜索结果'）\n\n"
        "回答要求：使用纯文本格式，不要使用Markdown语法（如##、**、-等），直接用中文标点和换行组织内容。回答要简洁明了，普通人也能看懂。"
    )

    data_sources = []
    if data.enable_intel_context:
        data_sources.append("项目情报")
    if data.enable_web_search:
        data_sources.append("网络搜索")

    try:
        response = await asyncio.wait_for(
            llm.generate(
                prompt=prompt,
                system_prompt=system_msg,
                temperature=settings.LLM_TEMPERATURE_CREATIVE,
                max_tokens=settings.LLM_MAX_TOKENS_LONG,
            ),
            timeout=60.0,
        )
        return {
            "status": "success",
            "response": response,
            "data_sources": data_sources,
            "context_used": bool(context_str),
        }
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="DeepSeek chat timed out")
    except Exception as exc:
        logger.error(f"DeepSeek chat failed: {exc}")
        raise HTTPException(status_code=500, detail="操作失败")


@router.post("/chat-stream")
async def deepseek_chat_stream(
    data: ChatRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    from fastapi.responses import StreamingResponse

    llm = _get_llm(request)

    auto_context = await _build_intel_context(
        request,
        data.message,
        enable_web_search=data.enable_web_search,
        enable_intel_context=data.enable_intel_context,
        db_session=db,
    )

    context_parts = []
    if auto_context:
        context_parts.append(auto_context)
    if data.context:
        context_parts.append(f"用户补充上下文：\n{data.context[:2000]}")

    context_str = ""
    if context_parts:
        context_str = "\n\n".join(context_parts)

    prompt = f"{data.message}"
    if context_str:
        prompt = f"{data.message}\n\n以下是为你提供的实时参考数据，请结合这些数据回答用户问题：\n{context_str}"

    system_msg = (
        DEEPSEEK_THREAT_INTEL_SYSTEM
        + "\n\n你现在拥有实时数据能力：\n"
        "1. 系统会自动为你提供最近采集的情报数据、暗语库、知识图谱统计等实时信息\n"
        "2. 系统会自动为你搜索网络获取最新信息\n"
        "3. 你必须优先使用这些实时数据来回答问题，而不是依赖自身训练数据\n"
        "4. 如果实时数据与你的训练知识有冲突，以实时数据为准\n"
        "5. 回答时请说明信息来源（如'根据系统最新情报'或'根据网络搜索结果'）\n\n"
        "回答要求：使用纯文本格式，不要使用Markdown语法（如##、**、-等），直接用中文标点和换行组织内容。回答要简洁明了，普通人也能看懂。"
    )

    async def generate():
        try:
            async for chunk in llm.generate_stream(
                prompt=prompt,
                system_prompt=system_msg,
                temperature=settings.LLM_TEMPERATURE_CREATIVE,
            ):
                yield f"data: {chunk}\n\n"
            yield "data: [DONE]\n\n"
        except Exception as stream_exc:
            logger.error(f"LLM stream error: {stream_exc}")
            try:
                yield f'data: {{"type": "error", "content": "生成中断: {str(stream_exc)}"}}\n\n'
            except Exception:
                pass

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/category-summary")
async def category_summary(
    request: Request,
    current_user: User = Depends(get_current_user),
    limit: int = Query(30, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
):
    llm = _get_llm(request)
    items = []

    try:
        stmt = (
            select(RawIntelligenceTable)
            .order_by(RawIntelligenceTable.collected_at.desc())
            .limit(limit)
        )
        result = await db.execute(stmt)
        rows = result.scalars().all()
        for row in rows:
            items.append({
                "content": (row.content or "")[:500],
                "source": row.source,
            })
    except Exception as exc:
        logger.warning(f"Failed to load data for category summary: {exc}")

    if not items:
        raise HTTPException(status_code=404, detail="暂无可用数据")

    try:
        result = await asyncio.wait_for(
            llm.analyze_intelligence_batch(items, analysis_type="classify"),
            timeout=120.0,
        )
        return result
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Category summary timed out")
    except Exception as exc:
        logger.error(f"Category summary failed: {exc}")
        raise HTTPException(status_code=500, detail="操作失败")


@router.get("/validate-data")
async def validate_data(
    request: Request,
    current_user: User = Depends(get_current_user),
    limit: int = Query(20, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
):
    llm = _get_llm(request)
    items = []

    try:
        stmt = (
            select(RawIntelligenceTable)
            .order_by(RawIntelligenceTable.collected_at.desc())
            .limit(limit)
        )
        result = await db.execute(stmt)
        rows = result.scalars().all()
        for row in rows:
            items.append({
                "content": (row.content or "")[:500],
                "source": row.source,
            })
    except Exception as exc:
        logger.warning(f"Failed to load data for validation: {exc}")

    if not items:
        raise HTTPException(status_code=404, detail="暂无可用数据")

    try:
        result = await asyncio.wait_for(
            llm.analyze_intelligence_batch(items, analysis_type="validate"),
            timeout=120.0,
        )
        return result
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Validation timed out")
    except Exception as exc:
        logger.error(f"Data validation failed: {exc}")
        raise HTTPException(status_code=500, detail="操作失败")


class TranslateRequest(BaseModel):
    text: str = Field(..., min_length=1)
    source_lang: str = Field(default="auto", description="源语言: auto/zh/en/ru")
    target_lang: str = Field(default="zh", description="目标语言: zh/en")


@router.post("/translate")
async def translate_blacktalk(
    data: TranslateRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    llm = _get_llm(request)
    bt = getattr(request.app.state, "blacktalk", None)
    glossary_context = ""
    if bt:
        try:
            terms = bt.terms if hasattr(bt, "terms") else []
            if terms:
                sample = terms[:30]
                glossary_lines = [f"「{t.term}」= {t.meaning}" for t in sample if hasattr(t, "term") and hasattr(t, "meaning")]
                if glossary_lines:
                    glossary_context = f"\n\n参考黑话术语库（共{len(terms)}个术语，以下为部分示例）：\n" + "\n".join(glossary_lines)
        except Exception:
            pass

    prompt = (
        f"请将以下文本中的黑灰产黑话/暗语翻译为标准语言，并解释其含义。\n"
        f"源语言: {data.source_lang}，目标语言: {data.target_lang}\n"
        f"如果文本中包含黑话，请：\n"
        f"1. 逐个识别黑话术语\n"
        f"2. 给出标准翻译\n"
        f"3. 解释黑话在黑灰产链条中的角色和用途\n\n"
        f"返回JSON：\n"
        f'{{"original_text": "...", "translated_text": "...", "terms": [{{"term": "...", "translation": "...", '
        f'"role_in_chain": "..."}}], "overall_meaning": "..."}}\n\n'
        f"待翻译文本：\n{data.text}{glossary_context}\n\n"
        f"重要：翻译结果使用纯文本格式，不要使用Markdown语法（如##、**、-等），直接用中文标点和换行组织内容。"
    )

    try:
        result = await asyncio.wait_for(
            llm.generate_json(prompt=prompt, system_prompt=DEEPSEEK_THREAT_INTEL_SYSTEM, temperature=settings.LLM_TEMPERATURE_ANALYSIS),
            timeout=60.0,
        )
        return {"status": "success", "data": result}
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Translation timed out")
    except Exception as exc:
        logger.error(f"Translation failed: {exc}")
        raise HTTPException(status_code=500, detail=str(exc))


class BriefRequest(BaseModel):
    limit: int = Field(default=20, ge=1, le=50)
    title: Optional[str] = None


@router.post("/generate-brief")
async def generate_brief(
    data: BriefRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    llm = _get_llm(request)
    items = []

    try:
        stmt = (
            select(RawIntelligenceTable)
            .order_by(RawIntelligenceTable.collected_at.desc())
            .limit(data.limit)
        )
        result = await db.execute(stmt)
        rows = result.scalars().all()
        for row in rows:
            items.append({
                "content": (row.content or "")[:500],
                "source": row.source,
                "collected_at": row.collected_at.isoformat() if row.collected_at else None,
            })
    except Exception as exc:
        logger.warning(f"Failed to load data for brief: {exc}")

    if not items:
        raise HTTPException(status_code=404, detail="No data available for brief generation")

    combined = "\n---\n".join(f"[情报{i+1}] {c['content']}" for i, c in enumerate(items))
    title = data.title or "黑灰产威胁情报简报"

    prompt = (
        f"请基于以下{len(items)}条情报数据，生成一份专业的威胁情报简报。\n\n"
        f"简报标题：{title}\n\n"
        f"简报要求：\n"
        f"1. 概述：当前威胁态势总体评估（100-200字）\n"
        f"2. 关键发现：列出3-5个最重要的发现\n"
        f"3. 威胁分类统计：各类威胁的数量和占比\n"
        f"4. 高危情报：标注可靠性≥0.7的高危条目\n"
        f"5. 攻击趋势：近期攻击手法和目标的变化趋势\n"
        f"6. 防御建议：针对当前威胁的3-5条防御建议\n"
        f"7. 可靠性评估：数据整体可信度评估\n\n"
        f"返回JSON：\n"
        f'{{"title": "...", "overview": "...", "key_findings": ["..."], '
        f'"threat_statistics": {{"fraud": 0, "hacking": 0}}, '
        f'"high_risk_items": [{{"index": 1, "threat": "...", "reliability": 0.0}}], '
        f'"attack_trends": ["..."], "defense_recommendations": ["..."], '
        f'"overall_reliability": 0.0-1.0, "generated_at": "..."}}\n\n'
        f"情报数据：\n{combined}\n\n"
        f"重要：所有文本内容使用纯文本格式，不要使用Markdown语法（如##、**、-等），直接用中文标点和换行组织内容。"
    )

    try:
        result = await asyncio.wait_for(
            llm.generate_json(prompt=prompt, system_prompt=DEEPSEEK_THREAT_INTEL_SYSTEM, temperature=settings.LLM_TEMPERATURE_DEFAULT),
            timeout=120.0,
        )
        return {"status": "success", "data": result}
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Brief generation timed out")
    except Exception as exc:
        logger.error(f"Brief generation failed: {exc}")
        raise HTTPException(status_code=500, detail="操作失败")


@router.get("/prompt-experiment")
async def prompt_experiment(
    request: Request,
    current_user: User = Depends(get_current_user),
    test_text: str = Query("某黑客组织声称攻击了银行数据库，获取500万用户信息"),
):
    llm = _get_llm(request)
    results = {}

    baseline_prompt = f"分析以下情报的威胁类别和等级：\n{test_text}"
    try:
        baseline = await asyncio.wait_for(
            llm.generate(prompt=baseline_prompt, system_prompt="", temperature=settings.LLM_TEMPERATURE_CREATIVE, max_tokens=settings.LLM_MAX_TOKENS_SHORT),
            timeout=30.0,
        )
        results["baseline"] = {"prompt_type": "通用prompt", "response": baseline[:500]}
    except Exception as exc:
        results["baseline"] = {"prompt_type": "通用prompt", "error": str(exc)}

    few_shot_prompt = (
        "以下是黑灰产情报分类的示例：\n"
        "示例1: 「某钓鱼网站仿冒银行登录页面」→ 类别: phishing, 等级: high\n"
        "示例2: 「暗网出售100万条个人信息，0.5BTC」→ 类别: data_theft, 等级: critical\n"
        "示例3: 「新型跑分平台利用虚拟货币洗钱」→ 类别: money_laundering, 等级: high\n\n"
        f"请按相同格式分析：\n{test_text}"
    )
    try:
        few_shot = await asyncio.wait_for(
            llm.generate(prompt=few_shot_prompt, system_prompt=DEEPSEEK_THREAT_INTEL_SYSTEM, temperature=settings.LLM_TEMPERATURE_ANALYSIS, max_tokens=settings.LLM_MAX_TOKENS_SHORT),
            timeout=30.0,
        )
        results["few_shot"] = {"prompt_type": "Few-shot黑产专属prompt", "response": few_shot[:500]}
    except Exception as exc:
        results["few_shot"] = {"prompt_type": "Few-shot黑产专属prompt", "error": str(exc)}

    cot_prompt = (
        f"请逐步分析以下情报：\n"
        f"步骤1: 识别情报中的关键实体和动作\n"
        f"步骤2: 判断威胁类别（fraud/gambling/hacking/money_laundering/data_theft/phishing/ransomware/other）\n"
        f"步骤3: 评估威胁等级（critical/high/medium/low/info）\n"
        f"步骤4: 评估信息可靠性（0-1）\n"
        f"步骤5: 给出最终结论\n\n"
        f"情报内容：{test_text}"
    )
    try:
        cot = await asyncio.wait_for(
            llm.generate(prompt=cot_prompt, system_prompt=DEEPSEEK_THREAT_INTEL_SYSTEM, temperature=settings.LLM_TEMPERATURE_ANALYSIS, max_tokens=settings.LLM_MAX_TOKENS_SHORT),
            timeout=30.0,
        )
        results["chain_of_thought"] = {"prompt_type": "CoT链式思维prompt", "response": cot[:500]}
    except Exception as exc:
        results["chain_of_thought"] = {"prompt_type": "CoT链式思维prompt", "error": str(exc)}

    return {
        "status": "success",
        "test_text": test_text,
        "experiment_results": results,
        "conclusion": "对比三种prompt策略：baseline(通用) vs few-shot(黑产示例) vs CoT(链式思维)",
    }
