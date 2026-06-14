import asyncio
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from loguru import logger
from pydantic import BaseModel, Field

from app.core.auth import User, get_current_user, require_role, Role
from app.core.blacktalk_engine import BlackTalkEngine
from app.core.llm import LLMService
from app.core.vector_store import VectorStore

router = APIRouter(prefix="/blacktalk", tags=["blacktalk"])


class BlackTalkTermCreate(BaseModel):
    term: str = Field(..., min_length=1, max_length=100)
    meaning: str = Field(..., min_length=1, max_length=500)
    context: str = Field(default="", max_length=1000)
    source: str = Field(default="manual")


class BlackTalkDecodeRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=10000)


def get_blacktalk_engine(request: Request) -> BlackTalkEngine | None:
    return getattr(request.app.state, "blacktalk_engine", None)


def get_llm(request: Request) -> LLMService | None:
    return getattr(request.app.state, "llm", None)


def get_vector_store(request: Request) -> VectorStore | None:
    return getattr(request.app.state, "vector_store", None)


@router.get("/terms")
async def list_terms(
    category: Optional[str] = None,
    search: Optional[str] = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    request: Request = None,
    current_user: User = Depends(get_current_user),
):
    engine = get_blacktalk_engine(request)
    if engine is None:
        return {"items": [], "total": 0, "offset": offset, "limit": limit}
    try:
        all_terms = await engine.get_all(category=category)
        if search:
            search_lower = search.lower()
            all_terms = [
                t for t in all_terms
                if search_lower in t.term.lower()
                or search_lower in t.meaning.lower()
            ]
        total = len(all_terms)
        paginated = all_terms[offset: offset + limit]
        return {
            "items": [t.to_dict() for t in paginated],
            "total": total,
            "offset": offset,
            "limit": limit,
        }
    except Exception as exc:
        logger.error(f"Failed to list blacktalk terms: {exc}")
        raise HTTPException(status_code=500, detail="获取黑话术语列表失败")


@router.get("/terms/{term_id}")
async def get_term(
    term_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    engine = get_blacktalk_engine(request)
    if engine is None:
        raise HTTPException(status_code=503, detail="BlackTalk engine not available")
    term = engine._dictionary.get(term_id)
    if term is None:
        raise HTTPException(status_code=404, detail="黑话术语未找到")
    return term.to_dict()


@router.post("/terms", status_code=201)
async def add_term(
    data: BlackTalkTermCreate,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    engine = get_blacktalk_engine(request)
    if engine is None:
        raise HTTPException(status_code=503, detail="BlackTalk engine not available")
    try:
        bt = await asyncio.wait_for(
            engine.learn(
                term=data.term,
                meaning=data.meaning,
                context=data.context,
                source=data.source,
            ),
            timeout=10.0,
        )
        return bt.to_dict()
    except asyncio.TimeoutError:
        bt_obj = None
        existing_id = engine._term_index.get(data.term)
        if existing_id and existing_id in engine._dictionary:
            bt_obj = engine._dictionary[existing_id]
        else:
            from uuid import uuid4
            from datetime import datetime
            from app.core.blacktalk_engine import BlackTalkTerm
            term_id = uuid4().hex
            bt_obj = BlackTalkTerm(
                id=term_id,
                term=data.term,
                meaning=data.meaning,
                category=engine._infer_category(data.meaning),
                context_examples=[data.context] if data.context else [],
                confidence=1.0 if data.source == "manual" else 0.5,
                source=data.source,
            )
            engine._dictionary[term_id] = bt_obj
            engine._term_index[data.term] = term_id
        return bt_obj.to_dict()
    except Exception as exc:
        logger.error(f"Failed to add blacktalk term: {exc}")
        raise HTTPException(status_code=500, detail="添加黑话术语失败")


@router.post("/decode")
async def decode_text(
    data: BlackTalkDecodeRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    if not data.text.strip():
        return {
            "original_text": data.text,
            "decoded_text": data.text,
            "decoded_terms": [],
            "terms_found": 0,
            "auto_learned": [],
        }

    engine = get_blacktalk_engine(request)
    if engine is None:
        return {
            "original_text": data.text,
            "decoded_text": data.text,
            "decoded_terms": [],
            "terms_found": 0,
            "auto_learned": [],
        }
    try:
        decoded_text, decoded_terms = await engine.decode(data.text)
        auto_learned = []
        if decoded_terms:
            try:
                learned = await engine.auto_learn(data.text, decoded_terms)
                auto_learned = [t.to_dict() for t in learned]
            except Exception as exc:
                logger.warning(f"Auto-learn during decode failed: {exc}")

        found_terms = []
        for dt in decoded_terms:
            if isinstance(dt, dict):
                found_terms.append(dt)
            else:
                found_terms.append({
                    "term": getattr(dt, "term", str(dt)),
                    "meaning": getattr(dt, "meaning", ""),
                    "position": getattr(dt, "position", [0, 0]),
                })

        return {
            "original_text": data.text,
            "decoded_text": decoded_text,
            "decoded_terms": decoded_terms,
            "terms_found": len(decoded_terms),
            "auto_learned": auto_learned,
            "found_terms": found_terms,
        }
    except Exception as exc:
        logger.error(f"Failed to decode text: {exc}")
        raise HTTPException(status_code=500, detail="黑话解码失败")


@router.get("/search")
async def search_blacktalk(
    q: str = Query(..., min_length=1),
    n: int = Query(10, ge=1, le=50),
    request: Request = None,
    current_user: User = Depends(get_current_user),
):
    engine = get_blacktalk_engine(request)
    if engine is None:
        return {"query": q, "results": [], "total": 0}
    try:
        terms = await asyncio.wait_for(engine.search(query=q, n=n), timeout=10.0)
        return {
            "query": q,
            "results": [t.to_dict() for t in terms],
            "total": len(terms),
        }
    except asyncio.TimeoutError:
        logger.warning("Blacktalk vector search timed out, falling back to dictionary search")
    except Exception as exc:
        logger.warning(f"Blacktalk search failed, falling back to dictionary: {exc}")

    q_lower = q.lower()
    fallback_results = []
    for bt in engine._dictionary.values():
        if q_lower in bt.term.lower() or q_lower in bt.meaning.lower():
            fallback_results.append(bt)
        if len(fallback_results) >= n:
            break
    return {
        "query": q,
        "results": [t.to_dict() for t in fallback_results],
        "total": len(fallback_results),
    }


@router.get("/stats")
async def get_stats(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    engine = get_blacktalk_engine(request)
    if engine is None:
        return {"total_terms": 0, "categories": {}, "sources": {}, "average_confidence": 0.0}
    try:
        all_terms = await engine.get_all()
        category_counts: Dict[str, int] = {}
        source_counts: Dict[str, int] = {}
        confidence_sum = 0.0
        for t in all_terms:
            category_counts[t.category] = category_counts.get(t.category, 0) + 1
            source_counts[t.source] = source_counts.get(t.source, 0) + 1
            confidence_sum += t.confidence
        avg_confidence = confidence_sum / len(all_terms) if all_terms else 0.0
        return {
            "total_terms": len(all_terms),
            "categories": category_counts,
            "sources": source_counts,
            "average_confidence": round(avg_confidence, 3),
        }
    except Exception as exc:
        logger.error(f"Failed to get blacktalk stats: {exc}")
        raise HTTPException(status_code=500, detail="获取黑话统计信息失败")
