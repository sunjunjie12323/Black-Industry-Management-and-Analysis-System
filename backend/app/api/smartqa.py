import json
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from loguru import logger
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.auth import User, get_current_user
from app.core.db_utils import db_write
from app.core.qa_engine import RAGEngine, DialogueManager, CitationTracker
from app.core.validators import validate_domain_object
from app.db.database import get_db
from app.db.tables import QAConversationTable

router = APIRouter(prefix="/smartqa", tags=["智能问答"])


class ConversationCreate(BaseModel):
    model_config = {"protected_namespaces": ()}
    title: str = Field(..., min_length=1, max_length=256)
    industry: Optional[str] = None
    rag_enabled: bool = True
    model_id: Optional[str] = None


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1)
    rag_enabled: Optional[bool] = None


class SwitchIndustryRequest(BaseModel):
    industry: str = Field(..., min_length=1)


def _row_to_dict(row: QAConversationTable) -> Dict:
    messages = []
    try:
        messages = json.loads(row.messages_json) if row.messages_json else []
    except (json.JSONDecodeError, TypeError):
        messages = []
    return {
        "id": row.id,
        "title": row.title,
        "messages": messages,
        "industry": row.industry,
        "rag_enabled": row.rag_enabled,
        "model_id": row.model_id,
        "conversation_type": getattr(row, "conversation_type", None),
        "is_active": getattr(row, "is_active", True),
        "description": getattr(row, "description", None),
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        "created_by": row.created_by,
    }


@router.get("/conversations")
async def list_conversations(
    industry: Optional[str] = None,
    conversation_type: Optional[str] = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = select(QAConversationTable)
    count_stmt = select(func.count()).select_from(QAConversationTable)

    if industry:
        stmt = stmt.where(QAConversationTable.industry == industry)
        count_stmt = count_stmt.where(QAConversationTable.industry == industry)

    if conversation_type:
        stmt = stmt.where(QAConversationTable.conversation_type == conversation_type)
        count_stmt = count_stmt.where(QAConversationTable.conversation_type == conversation_type)

    total_result = await db.execute(count_stmt)
    total = total_result.scalar() or 0

    stmt = stmt.order_by(QAConversationTable.updated_at.desc()).offset(offset).limit(limit)
    result = await db.execute(stmt)
    rows = result.scalars().all()

    items = []
    for r in rows:
        d = _row_to_dict(r)
        d["message_count"] = len(d["messages"])
        d.pop("messages", None)
        items.append(d)

    return {"items": items, "total": total, "offset": offset, "limit": limit}


@router.post("/conversations", status_code=201)
async def create_conversation(
    data: ConversationCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    conv_id = uuid.uuid4().hex

    validation = validate_domain_object("qa_conversation", data.model_dump())
    if not validation.is_valid:
        raise HTTPException(status_code=400, detail={"errors": validation.errors, "warnings": validation.warnings})

    row = QAConversationTable(
        id=conv_id,
        title=data.title,
        messages_json="[]",
        industry=data.industry,
        rag_enabled=data.rag_enabled,
        model_id=data.model_id,
        created_by=current_user.username if hasattr(current_user, "username") else "system",
    )
    async with db_write(db, operation="创建对话"):
        db.add(row)
    await db.refresh(row)
    return _row_to_dict(row)


@router.get("/conversations/{conv_id}")
async def get_conversation(
    conv_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(QAConversationTable).where(QAConversationTable.id == conv_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="对话不存在")
    return _row_to_dict(row)


@router.post("/conversations/{conv_id}/chat")
async def chat(
    request: Request,
    conv_id: str,
    data: ChatRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(QAConversationTable).where(QAConversationTable.id == conv_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="对话不存在")

    messages = []
    try:
        messages = json.loads(row.messages_json) if row.messages_json else []
    except (json.JSONDecodeError, TypeError):
        messages = []

    _MAX_MESSAGES_PER_CONVERSATION = 1000
    if len(messages) >= _MAX_MESSAGES_PER_CONVERSATION:
        raise HTTPException(status_code=400, detail="对话消息数量已达上限，请创建新对话")

    user_msg = {
        "role": "user",
        "content": data.message,
        "references": [],
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    messages.append(user_msg)

    rag_enabled = data.rag_enabled if data.rag_enabled is not None else row.rag_enabled

    llm = getattr(request.app.state, "llm", None)
    vector_store = getattr(request.app.state, "vector_store", None)

    rag_result = None
    rag_context = ""
    source_documents = []

    if rag_enabled:
        try:
            rag_engine = getattr(request.app.state, "qa_rag_engine", None)
            if rag_engine is None:
                rag_engine = RAGEngine(vector_store=vector_store, llm_service=llm)
            rag_result = await rag_engine.retrieve(query=data.message, top_k=5)
            rag_context = rag_result.context
            source_documents = rag_result.documents
        except Exception as exc:
            logger.warning(f"RAG检索失败: {exc}")

    dialogue_manager = getattr(request.app.state, "qa_dialogue_manager", None)
    if dialogue_manager is None:
        dialogue_manager = DialogueManager(llm_service=llm)
    llm_messages = dialogue_manager.build_messages(
        history=messages[:-1],
        current_query=data.message,
        rag_context=rag_context,
        industry=row.industry,
    )

    assistant_content = ""
    model_used = "none"
    tokens_used = 0

    if llm:
        try:
            response = await dialogue_manager.generate_response(
                messages=llm_messages,
                model_id=row.model_id,
                temperature=settings.LLM_TEMPERATURE_CREATIVE,
                max_tokens=settings.LLM_MAX_TOKENS_LONG,
            )
            assistant_content = response.get("content", "")
            model_used = response.get("model", "unknown")
            tokens_used = response.get("tokens_used", 0)
        except Exception as exc:
            logger.error(f"LLM生成失败: {exc}")
            assistant_content = "AI服务暂时不可用，请稍后重试"
    else:
        if rag_context:
            assistant_content = f"基于检索到的相关情报数据，针对您的问题「{data.message}」，以下是相关情报摘要：\n{rag_context[:500]}"
        else:
            assistant_content = "当前暂无可用的分析结果，请稍后重试或联系管理员"

    citation_tracker = getattr(request.app.state, "qa_citation_tracker", None)
    if citation_tracker is None:
        citation_tracker = CitationTracker()
    citations = await citation_tracker.track_citations(
        response_text=assistant_content,
        source_documents=source_documents,
    )

    references = []
    for c in citations:
        references.append(c.to_dict())

    confidence_score = 0.0
    if citations:
        confidence_score = sum(c.relevance_score for c in citations) / len(citations)

    citation_text = citation_tracker.format_citations(citations)
    if citation_text:
        assistant_content += citation_text

    assistant_msg = {
        "role": "assistant",
        "content": assistant_content,
        "references": references,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    messages.append(assistant_msg)

    row.messages_json = json.dumps(messages, ensure_ascii=False, default=str)
    row.updated_at = datetime.now(timezone.utc)
    async with db_write(db, operation="保存对话消息"):
        db.add(row)
    await db.refresh(row)

    return {
        "conversation_id": conv_id,
        "user_message": user_msg,
        "assistant_message": assistant_msg,
        "rag_enabled": rag_enabled,
        "reference_count": len(references),
        "citations": [c.to_dict() for c in citations],
        "confidence_score": round(confidence_score, 4),
        "model_used": model_used,
        "tokens_used": tokens_used,
        "retrieval_info": rag_result.to_dict() if rag_result else None,
    }


@router.get("/conversations/{conv_id}/citations")
async def get_conversation_citations(
    conv_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(QAConversationTable).where(QAConversationTable.id == conv_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="对话不存在")

    messages = []
    try:
        messages = json.loads(row.messages_json) if row.messages_json else []
    except (json.JSONDecodeError, TypeError):
        messages = []

    all_citations = []
    citation_tracker = getattr(request.app.state, "qa_citation_tracker", None)
    if citation_tracker is None:
        citation_tracker = CitationTracker()

    for msg in messages:
        if msg.get("role") != "assistant":
            continue
        refs = msg.get("references", [])
        if not refs:
            continue
        source_documents = []
        for ref in refs:
            source_documents.append({
                "id": ref.get("source_id", ref.get("id", "")),
                "content": ref.get("snippet", ""),
                "source": ref.get("source_type", ref.get("type", "unknown")),
                "relevance": ref.get("relevance_score", ref.get("confidence", 0.5)),
                "threat_level": ref.get("threat_level", ref.get("metadata", {}).get("threat_level", "")),
            })
        citations = await citation_tracker.track_citations(
            response_text=msg.get("content", ""),
            source_documents=source_documents,
        )
        for c in citations:
            citation_dict = c.to_dict()
            citation_dict["message_created_at"] = msg.get("created_at")
            all_citations.append(citation_dict)

    total_relevance = sum(c.get("relevance_score", 0) for c in all_citations)
    avg_confidence = round(total_relevance / len(all_citations), 4) if all_citations else 0.0

    return {
        "conversation_id": conv_id,
        "citations": all_citations,
        "total_citations": len(all_citations),
        "avg_confidence": avg_confidence,
    }


class BatchDeleteRequest(BaseModel):
    conversation_ids: List[str] = Field(..., min_length=1)


@router.delete("/conversations/batch", status_code=204)
async def batch_delete_conversations(
    data: BatchDeleteRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = select(QAConversationTable).where(
        QAConversationTable.id.in_(data.conversation_ids),
        QAConversationTable.conversation_type != "knowledge_base",
    )
    result = await db.execute(stmt)
    rows = result.scalars().all()

    found_ids = {r.id for r in rows}
    missing_ids = set(data.conversation_ids) - found_ids
    if missing_ids:
        raise HTTPException(status_code=404, detail=f"以下对话不存在: {', '.join(missing_ids)}")

    async with db_write(db, operation="批量删除对话"):
        for row in rows:
            await db.delete(row)


@router.delete("/conversations/{conv_id}", status_code=204)
async def delete_conversation(
    conv_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(QAConversationTable).where(QAConversationTable.id == conv_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="对话不存在")
    async with db_write(db, operation="删除对话"):
        await db.delete(row)


@router.get("/statistics")
async def get_statistics(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    total_stmt = select(func.count()).select_from(QAConversationTable).where(
        QAConversationTable.conversation_type != "knowledge_base"
    )
    total_result = await db.execute(total_stmt)
    total_conversations = total_result.scalar() or 0

    industry_stmt = (
        select(QAConversationTable.industry, func.count())
        .where(QAConversationTable.conversation_type != "knowledge_base")
        .group_by(QAConversationTable.industry)
    )
    industry_result = await db.execute(industry_stmt)
    by_industry = {row[0] or "未分类": row[1] for row in industry_result.all()}

    active_stmt = select(func.count()).select_from(QAConversationTable).where(
        QAConversationTable.conversation_type != "knowledge_base",
        QAConversationTable.is_active == True,
    )
    active_result = await db.execute(active_stmt)
    active_count = active_result.scalar() or 0
    inactive_count = total_conversations - active_count

    msg_stmt = select(QAConversationTable.messages_json).where(
        QAConversationTable.conversation_type != "knowledge_base"
    )
    msg_result = await db.execute(msg_stmt)
    total_messages = 0
    rag_enabled_count = 0
    for (messages_json,) in msg_result.all():
        msgs = []
        try:
            msgs = json.loads(messages_json) if messages_json else []
        except (json.JSONDecodeError, TypeError):
            msgs = []
        total_messages += len(msgs)

    rag_stmt = select(func.count()).select_from(QAConversationTable).where(
        QAConversationTable.conversation_type != "knowledge_base",
        QAConversationTable.rag_enabled == True,
    )
    rag_result = await db.execute(rag_stmt)
    rag_enabled_count = rag_result.scalar() or 0

    rag_ratio = round(rag_enabled_count / total_conversations, 4) if total_conversations > 0 else 0.0

    return {
        "total_conversations": total_conversations,
        "by_industry": by_industry,
        "active_count": active_count,
        "inactive_count": inactive_count,
        "active_ratio": round(active_count / total_conversations, 4) if total_conversations > 0 else 0.0,
        "total_messages": total_messages,
        "rag_enabled_count": rag_enabled_count,
        "rag_usage_ratio": rag_ratio,
    }


@router.get("/industries")
async def list_industries(
    current_user: User = Depends(get_current_user),
):
    from app.config import settings
    if settings.SMARTQA_INDUSTRIES_JSON:
        try:
            industries = json.loads(settings.SMARTQA_INDUSTRIES_JSON)
            return {"industries": industries, "total": len(industries)}
        except (json.JSONDecodeError, TypeError):
            pass
    from app.core.threat_intel_service import INDUSTRY_THREAT_MAPPING
    industries = [
        {"value": k.upper(), "label": v["name"], "description": v.get("description", "")}
        for k, v in INDUSTRY_THREAT_MAPPING.items()
    ]
    return {"industries": industries, "total": len(industries)}


@router.post("/conversations/{conv_id}/switch-industry")
async def switch_industry(
    conv_id: str,
    data: SwitchIndustryRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(QAConversationTable).where(QAConversationTable.id == conv_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="对话不存在")

    old_industry = row.industry
    row.industry = data.industry
    row.updated_at = datetime.now(timezone.utc)
    async with db_write(db, operation="切换行业"):
        db.add(row)
    await db.refresh(row)

    return {
        "conversation_id": conv_id,
        "old_industry": old_industry,
        "new_industry": data.industry,
    }


class KnowledgeBaseCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=256)
    description: str = ""
    industry: Optional[str] = None
    source_type: str = Field("manual", pattern=r"^(manual|file|api|crawl)$")
    config_json: str = Field("{}", pattern=r'^\{.*\}$')


class KnowledgeBaseUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    is_active: Optional[bool] = None


class KnowledgeBaseItemAdd(BaseModel):
    title: str = Field(..., min_length=1)
    content: str = Field(..., min_length=1)
    source: str = ""
    metadata_json: str = "{}"


@router.get("/knowledge-bases")
async def list_knowledge_bases(
    industry: Optional[str] = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = select(QAConversationTable).where(QAConversationTable.conversation_type == "knowledge_base")
    count_stmt = select(func.count()).select_from(QAConversationTable).where(
        QAConversationTable.conversation_type == "knowledge_base"
    )

    if industry:
        stmt = stmt.where(QAConversationTable.industry == industry)
        count_stmt = count_stmt.where(QAConversationTable.industry == industry)

    total_result = await db.execute(count_stmt)
    total = total_result.scalar() or 0

    stmt = stmt.order_by(QAConversationTable.created_at.desc()).offset(offset).limit(limit)
    result = await db.execute(stmt)
    rows = result.scalars().all()

    items = []
    for r in rows:
        items.append({
            "id": r.id,
            "name": r.title,
            "description": r.description or "",
            "industry": r.industry,
            "is_active": r.is_active,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "updated_at": r.updated_at.isoformat() if r.updated_at else None,
        })

    return {"items": items, "total": total, "offset": offset, "limit": limit}


@router.post("/knowledge-bases", status_code=201)
async def create_knowledge_base(
    data: KnowledgeBaseCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    kb_id = uuid.uuid4().hex

    try:
        json.loads(data.config_json)
    except (json.JSONDecodeError, TypeError):
        raise HTTPException(status_code=422, detail="config_json格式错误")

    row = QAConversationTable(
        id=kb_id,
        title=data.name,
        description=data.description,
        industry=data.industry,
        conversation_type="knowledge_base",
        is_active=True,
        created_by=current_user.username if hasattr(current_user, "username") else "system",
    )
    async with db_write(db, operation="创建知识库"):
        db.add(row)
    await db.refresh(row)

    return {
        "id": row.id,
        "name": row.title,
        "description": row.description,
        "industry": row.industry,
        "source_type": data.source_type,
        "is_active": row.is_active,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


@router.get("/knowledge-bases/{kb_id}")
async def get_knowledge_base(
    kb_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(QAConversationTable).where(
            QAConversationTable.id == kb_id,
            QAConversationTable.conversation_type == "knowledge_base",
        )
    )
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="知识库不存在")

    return {
        "id": row.id,
        "name": row.title,
        "description": row.description,
        "industry": row.industry,
        "is_active": row.is_active,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


@router.put("/knowledge-bases/{kb_id}")
async def update_knowledge_base(
    kb_id: str,
    data: KnowledgeBaseUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(QAConversationTable).where(
            QAConversationTable.id == kb_id,
            QAConversationTable.conversation_type == "knowledge_base",
        )
    )
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="知识库不存在")

    if data.name is not None:
        row.title = data.name
    if data.description is not None:
        row.description = data.description
    if data.is_active is not None:
        row.is_active = data.is_active
    row.updated_at = datetime.now(timezone.utc)

    async with db_write(db, operation="更新知识库"):
        db.add(row)
    await db.refresh(row)
    return {
        "id": row.id,
        "name": row.title,
        "description": row.description,
        "is_active": row.is_active,
    }


@router.delete("/knowledge-bases/{kb_id}", status_code=204)
async def delete_knowledge_base(
    kb_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(QAConversationTable).where(
            QAConversationTable.id == kb_id,
            QAConversationTable.conversation_type == "knowledge_base",
        )
    )
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="知识库不存在")
    async with db_write(db, operation="删除知识库"):
        await db.delete(row)


@router.post("/knowledge-bases/{kb_id}/items", status_code=201)
async def add_knowledge_base_item(
    kb_id: str,
    data: KnowledgeBaseItemAdd,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(QAConversationTable).where(
            QAConversationTable.id == kb_id,
            QAConversationTable.conversation_type == "knowledge_base",
        )
    )
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="知识库不存在")

    try:
        json.loads(data.metadata_json)
    except (json.JSONDecodeError, TypeError):
        raise HTTPException(status_code=422, detail="metadata_json格式错误")

    qa_engine = getattr(request.app.state, "qa_engine", None)
    if qa_engine and hasattr(qa_engine, "add_to_knowledge_base"):
        await qa_engine.add_to_knowledge_base(
            kb_id=kb_id,
            title=data.title,
            content=data.content,
            source=data.source,
            metadata=data.metadata_json,
        )

    return {
        "kb_id": kb_id,
        "item_title": data.title,
        "item_source": data.source,
        "added": True,
        "message": "知识条目已添加",
    }


@router.get("/knowledge-bases/{kb_id}/items")
async def list_knowledge_base_items(
    kb_id: str,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(QAConversationTable).where(
            QAConversationTable.id == kb_id,
            QAConversationTable.conversation_type == "knowledge_base",
        )
    )
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="知识库不存在")

    messages = []
    try:
        messages = json.loads(row.messages_json) if row.messages_json else []
    except (json.JSONDecodeError, TypeError):
        messages = []

    items = messages[offset:offset + limit]

    return {
        "kb_id": kb_id,
        "items": items,
        "total": len(messages),
        "offset": offset,
        "limit": limit,
    }


@router.get("/conversations/{conv_id}/summary")
async def get_conversation_summary(
    conv_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(QAConversationTable).where(QAConversationTable.id == conv_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="对话不存在")

    messages = []
    try:
        messages = json.loads(row.messages_json) if row.messages_json else []
    except (json.JSONDecodeError, TypeError):
        messages = []

    if not messages:
        return {
            "conversation_id": conv_id,
            "title": row.title,
            "summary": "对话为空，暂无摘要",
            "message_count": 0,
            "key_topics": [],
            "key_findings": [],
        }

    llm = getattr(request.app.state, "llm", None)

    if llm:
        conversation_text = "\n".join(
            f"{'用户' if m.get('role') == 'user' else '助手'}: {m.get('content', '')[:500]}"
            for m in messages
        )
        summary_prompt = (
            "请对以下威胁情报对话进行摘要总结，包括：\n"
            "1. 对话主要讨论的话题\n"
            "2. 关键结论和发现\n"
            "3. 涉及的威胁情报要点\n\n"
            '请以JSON格式返回：{"summary": "摘要内容", "key_topics": ["话题1", "话题2"], "key_findings": ["发现1", "发现2"]}\n\n'
            f"对话内容：\n{conversation_text[:4000]}"
        )

        dialogue_manager = getattr(request.app.state, "qa_dialogue_manager", None)
        if dialogue_manager is None:
            dialogue_manager = DialogueManager(llm_service=llm)
        try:
            response = await dialogue_manager.generate_response(
                messages=[{"role": "user", "content": summary_prompt}],
                temperature=settings.LLM_TEMPERATURE_CREATIVE,
                max_tokens=settings.LLM_MAX_TOKENS_MEDIUM,
            )
            summary_text = response.get("content", "")
            import re
            json_match = re.search(r'\{[\s\S]*\}', summary_text)
            if json_match:
                summary_data = json.loads(json_match.group())
            else:
                summary_data = {"summary": summary_text, "key_topics": [], "key_findings": []}
        except Exception as exc:
            logger.error(f"Conversation summary generation failed: {exc}")
            summary_data = {"summary": "摘要生成失败", "key_topics": [], "key_findings": []}
    else:
        user_msgs = [m for m in messages if m.get("role") == "user"]
        topics = [m.get("content", "")[:50] for m in user_msgs[:5]]
        summary_data = {
            "summary": f"共 {len(messages)} 条消息的对话，涉及 {len(user_msgs)} 个用户提问",
            "key_topics": topics,
            "key_findings": [],
        }

    return {
        "conversation_id": conv_id,
        "title": row.title,
        "message_count": len(messages),
        "summary": summary_data.get("summary", ""),
        "key_topics": summary_data.get("key_topics", []),
        "key_findings": summary_data.get("key_findings", []),
    }


@router.post("/conversations/{conv_id}/compress")
async def compress_conversation(
    conv_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(QAConversationTable).where(QAConversationTable.id == conv_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="对话不存在")

    messages = []
    try:
        messages = json.loads(row.messages_json) if row.messages_json else []
    except (json.JSONDecodeError, TypeError):
        messages = []

    if not messages:
        return {
            "conversation_id": conv_id,
            "original_count": 0,
            "compressed_count": 0,
            "messages": [],
        }

    llm = getattr(request.app.state, "llm", None)
    qa_dialogue_manager = getattr(request.app.state, "qa_dialogue_manager", None)
    if qa_dialogue_manager is None:
        qa_dialogue_manager = DialogueManager(llm_service=llm)

    original_count = len(messages)
    compressed = await qa_dialogue_manager.compress_history(messages)

    row.messages_json = json.dumps(compressed, ensure_ascii=False, default=str)
    row.updated_at = datetime.now(timezone.utc)
    async with db_write(db, operation="压缩对话"):
        db.add(row)
    await db.refresh(row)

    return {
        "conversation_id": conv_id,
        "original_count": original_count,
        "compressed_count": len(compressed),
        "messages": compressed,
    }


@router.post("/conversations/{conv_id}/intent")
async def track_conversation_intent(
    conv_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(QAConversationTable).where(QAConversationTable.id == conv_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="对话不存在")

    messages = []
    try:
        messages = json.loads(row.messages_json) if row.messages_json else []
    except (json.JSONDecodeError, TypeError):
        messages = []

    llm = getattr(request.app.state, "llm", None)
    qa_dialogue_manager = getattr(request.app.state, "qa_dialogue_manager", None)
    if qa_dialogue_manager is None:
        qa_dialogue_manager = DialogueManager(llm_service=llm)

    intent_result = qa_dialogue_manager.track_intent(messages)

    return {
        "conversation_id": conv_id,
        "intents": intent_result.get("intents", []),
        "intent_chain": intent_result.get("intent_chain", []),
        "dominant_intent": intent_result.get("dominant_intent"),
        "intent_transitions": intent_result.get("intent_transitions", 0),
    }


@router.post("/conversations/{conv_id}/evidence-chain")
async def generate_evidence_chain(
    conv_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(QAConversationTable).where(QAConversationTable.id == conv_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="对话不存在")

    messages = []
    try:
        messages = json.loads(row.messages_json) if row.messages_json else []
    except (json.JSONDecodeError, TypeError):
        messages = []

    assistant_msg = None
    for msg in reversed(messages):
        if msg.get("role") == "assistant":
            assistant_msg = msg
            break

    if not assistant_msg:
        return {
            "conversation_id": conv_id,
            "chain": [],
            "total_steps": 0,
            "confidence": 0.0,
        }

    response_text = assistant_msg.get("content", "")
    references = assistant_msg.get("references", [])

    source_documents = []
    for ref in references:
        source_documents.append({
            "id": ref.get("source_id", ref.get("id", "")),
            "content": ref.get("snippet", ""),
            "source": ref.get("source_type", ref.get("type", "unknown")),
            "relevance": ref.get("relevance_score", ref.get("confidence", 0.5)),
        })

    qa_citation_tracker = getattr(request.app.state, "qa_citation_tracker", None)
    if qa_citation_tracker is None:
        qa_citation_tracker = CitationTracker()
    citations = await qa_citation_tracker.track_citations(
        response_text=response_text,
        source_documents=source_documents,
    )

    evidence_chain = await qa_citation_tracker.generate_evidence_chain(response_text, citations)

    return {
        "conversation_id": conv_id,
        "chain": evidence_chain.get("chain", []),
        "total_steps": evidence_chain.get("total_steps", 0),
        "confidence": evidence_chain.get("confidence", 0.0),
    }


class RAGQueryRequest(BaseModel):
    model_config = {"protected_namespaces": ()}
    query: str = Field(..., min_length=1, max_length=2000)
    top_k: int = Field(5, ge=1, le=20)
    conversation_id: Optional[str] = None


@router.post("/rag-query")
async def rag_query(
    data: RAGQueryRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    dialogue_manager = getattr(request.app.state, "qa_dialogue_manager", None)
    if not dialogue_manager:
        llm = getattr(request.app.state, "llm", None)
        dialogue_manager = DialogueManager(llm_service=llm)

    result = await dialogue_manager.answer_with_citations(
        query=data.query,
        conversation_id=data.conversation_id,
        top_k=data.top_k,
    )
    return result


class MultiTurnRequest(BaseModel):
    model_config = {"protected_namespaces": ()}
    query: str = Field(..., min_length=1, max_length=2000)


@router.post("/conversations/{conv_id}/turn")
async def multi_turn_conversation(
    conv_id: str,
    data: MultiTurnRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    dialogue_manager = getattr(request.app.state, "qa_dialogue_manager", None)
    if not dialogue_manager:
        llm = getattr(request.app.state, "llm", None)
        dialogue_manager = DialogueManager(llm_service=llm)

    result = await dialogue_manager.multi_turn_query(
        conversation_id=conv_id,
        query=data.query,
        db_session=db,
    )
    return result
