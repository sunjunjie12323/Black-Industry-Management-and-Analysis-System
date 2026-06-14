import asyncio
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from loguru import logger
from pydantic import BaseModel, Field

from app.core.auth import User, get_current_user, require_role, Role
from app.core.temporal_decay import TemporalDecay

router = APIRouter(tags=["temporal-decay"])


def get_temporal_decay(request: Request) -> TemporalDecay | None:
    return getattr(request.app.state, "temporal_decay", None)


@router.get("/intelligence/{intelligence_id}")
async def get_decay_status(
    intelligence_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    decay = get_temporal_decay(request)
    if decay is None:
        raise HTTPException(status_code=503, detail="Temporal decay engine not available")
    try:
        result = await asyncio.wait_for(
            decay.compute_current_confidence(intelligence_id),
            timeout=60,
        )
        return result.to_dict()
    except asyncio.TimeoutError:
        logger.error(f"Decay status computation timed out for intelligence '{intelligence_id}'")
        raise HTTPException(status_code=504, detail="Decay status computation timed out")
    except Exception as exc:
        logger.error(f"Decay status computation failed for intelligence '{intelligence_id}': {exc}")
        raise HTTPException(status_code=500, detail="操作失败")


@router.get("/curve/{intelligence_id}")
async def get_decay_curve(
    intelligence_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    decay = get_temporal_decay(request)
    if decay is None:
        raise HTTPException(status_code=503, detail="Temporal decay engine not available")
    try:
        curve = await asyncio.wait_for(
            decay.compute_decay_curve(intelligence_id),
            timeout=60,
        )
        return curve.to_dict()
    except asyncio.TimeoutError:
        logger.error(f"Decay curve computation timed out for intelligence '{intelligence_id}'")
        raise HTTPException(status_code=504, detail="Decay curve computation timed out")
    except Exception as exc:
        logger.error(f"Decay curve computation failed for intelligence '{intelligence_id}': {exc}")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/batch")
async def batch_decay_analysis(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    decay = get_temporal_decay(request)
    if decay is None:
        raise HTTPException(status_code=503, detail="Temporal decay engine not available")
    try:
        result = await asyncio.wait_for(
            decay.batch_decay_analysis(),
            timeout=60,
        )
        return result
    except asyncio.TimeoutError:
        logger.error("Batch decay analysis timed out")
        raise HTTPException(status_code=504, detail="Batch decay analysis timed out")
    except Exception as exc:
        logger.error(f"Batch decay analysis failed: {exc}")
        raise HTTPException(status_code=500, detail="操作失败")


@router.get("/models")
async def list_decay_models(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    decay = get_temporal_decay(request)
    if decay is None:
        return {"models": [], "total": 0, "message": "时效衰减引擎未初始化"}
    try:
        recommendations = await asyncio.wait_for(
            decay.recommend_refresh(),
            timeout=60,
        )
        items = recommendations if isinstance(recommendations, list) and (not recommendations or isinstance(recommendations[0], dict)) else [r.to_dict() if hasattr(r, 'to_dict') else r for r in recommendations]
        return {"models": items, "total": len(items)}
    except Exception:
        return {"models": [], "total": 0, "message": "获取衰减模型失败"}


@router.get("/recommendations")
async def get_refresh_recommendations(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    decay = get_temporal_decay(request)
    if decay is None:
        raise HTTPException(status_code=503, detail="Temporal decay engine not available")
    try:
        recommendations = await asyncio.wait_for(
            decay.recommend_refresh(),
            timeout=60,
        )
        return {
            "recommendations": recommendations if isinstance(recommendations, list) and (not recommendations or isinstance(recommendations[0], dict)) else [r.to_dict() if hasattr(r, 'to_dict') else r for r in recommendations],
            "total": len(recommendations),
        }
    except asyncio.TimeoutError:
        logger.error("Refresh recommendations computation timed out")
        raise HTTPException(status_code=504, detail="Refresh recommendations computation timed out")
    except Exception as exc:
        logger.error(f"Refresh recommendations computation failed: {exc}")
        raise HTTPException(status_code=500, detail="操作失败")
