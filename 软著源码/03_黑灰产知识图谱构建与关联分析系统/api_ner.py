from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from loguru import logger
from pydantic import BaseModel, Field

from app.core.auth import User, get_current_user

router = APIRouter(prefix="/ner", tags=["NER实体提取"])


class NERExtractRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=50000)
    use_llm: bool = Field(True)


class NERBatchExtractRequest(BaseModel):
    texts: List[str] = Field(..., min_length=1, max_length=50)
    use_llm: bool = Field(True)


def _get_ner_engine(request: Request):
    engine = getattr(request.app.state, "ner_engine", None)
    if engine is None:
        from app.core.ner_engine import ThreatNEREngine
        llm = getattr(request.app.state, "llm", None)
        engine = ThreatNEREngine(llm_service=llm)
        request.app.state.ner_engine = engine
    return engine


@router.post("/extract")
async def extract_entities(
    req: NERExtractRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    engine = _get_ner_engine(request)
    entities = await engine.extract(req.text, use_llm=req.use_llm)
    return {
        "success": True,
        "data": {
            "entities": [e.to_dict() for e in entities],
            "count": len(entities),
        },
    }


@router.post("/extract-batch")
async def extract_entities_batch(
    req: NERBatchExtractRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    engine = _get_ner_engine(request)
    results = await engine.extract_batch(req.texts, use_llm=req.use_llm)
    return {
        "success": True,
        "data": {
            "results": [
                {"entities": [e.to_dict() for e in entities], "count": len(entities)}
                for entities in results
            ],
            "total_texts": len(req.texts),
        },
    }


@router.post("/extract-sync")
async def extract_entities_sync(
    req: NERExtractRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    engine = _get_ner_engine(request)
    entities = engine.extract_sync(req.text)
    return {
        "success": True,
        "data": {
            "entities": entities,
            "count": len(entities),
        },
    }
