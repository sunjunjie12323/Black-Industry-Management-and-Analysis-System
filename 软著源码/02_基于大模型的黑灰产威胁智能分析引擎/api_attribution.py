import asyncio
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from loguru import logger
from pydantic import BaseModel, Field

from app.core.auth import User, get_current_user, require_role, Role
from app.core.entity_attribution import EntityAttribution

router = APIRouter(prefix="/attribution", tags=["attribution"])


def get_entity_attribution(request: Request) -> EntityAttribution | None:
    return getattr(request.app.state, "entity_attribution", None)


@router.post("/fingerprint/{entity_id}")
async def compute_behavioral_fingerprint(
    entity_id: str,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    attribution = get_entity_attribution(request)
    if attribution is None:
        raise HTTPException(status_code=503, detail="Entity attribution not available")
    try:
        fingerprint = await asyncio.wait_for(
            attribution.compute_behavioral_fingerprint(entity_id),
            timeout=60,
        )
        return fingerprint.to_dict()
    except asyncio.TimeoutError:
        logger.error(f"Behavioral fingerprint computation timed out for entity '{entity_id}'")
        raise HTTPException(status_code=504, detail="Behavioral fingerprint computation timed out")
    except Exception as exc:
        logger.error(f"Behavioral fingerprint computation failed for entity '{entity_id}': {exc}")
        raise HTTPException(status_code=500, detail="操作失败")


@router.get("/find-same/{entity_id}")
async def find_same_entity(
    entity_id: str,
    threshold: float = Query(default=0.7, ge=0.0, le=1.0),
    request: Request = None,
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    attribution = get_entity_attribution(request)
    if attribution is None:
        raise HTTPException(status_code=503, detail="Entity attribution not available")
    try:
        matches = await asyncio.wait_for(
            attribution.find_same_entity(entity_id, threshold=threshold),
            timeout=60,
        )
        all_entity_ids = [
            eid for eid in attribution.knowledge_graph._entities
            if eid != entity_id
        ]
        return {
            "matches": [m.to_dict() for m in matches],
            "total_compared": len(all_entity_ids),
        }
    except asyncio.TimeoutError:
        logger.error(f"Same entity search timed out for entity '{entity_id}'")
        raise HTTPException(status_code=504, detail="Same entity search timed out")
    except Exception as exc:
        logger.error(f"Same entity search failed for entity '{entity_id}': {exc}")
        raise HTTPException(status_code=500, detail="操作失败")


@router.get("/find-same-by-name/{name}")
async def find_same_entity_by_name(
    name: str,
    threshold: float = Query(default=0.7, ge=0.0, le=1.0),
    request: Request = None,
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    kg = getattr(request.app.state, "knowledge_graph", None)
    if kg is None:
        raise HTTPException(status_code=503, detail="Knowledge graph not available")
    entity = None
    for e in kg._entities.values():
        if e.value.lower() == name.lower():
            entity = e
            break
    if not entity:
        results = await kg.search_entities(name, limit=1)
        if results:
            entity = results[0]
    if not entity:
        raise HTTPException(status_code=404, detail=f"Entity not found: {name}")
    entity_id = entity.id
    attribution = get_entity_attribution(request)
    try:
        matches = await asyncio.wait_for(
            attribution.find_same_entity(entity_id, threshold=threshold),
            timeout=60,
        )
        all_entity_ids = [
            eid for eid in attribution.knowledge_graph._entities
            if eid != entity_id
        ]
        return {
            "entity_id": entity_id,
            "entity_name": entity.value,
            "matches": [m.to_dict() for m in matches],
            "total_compared": len(all_entity_ids),
        }
    except asyncio.TimeoutError:
        logger.error(f"Same entity search timed out for name '{name}'")
        raise HTTPException(status_code=504, detail="Same entity search timed out")
    except Exception as exc:
        logger.error(f"Same entity search failed for name '{name}': {exc}")
        raise HTTPException(status_code=500, detail="操作失败")


@router.get("/report/{entity_id}")
async def generate_attribution_report(
    entity_id: str,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    attribution = get_entity_attribution(request)
    if attribution is None:
        raise HTTPException(status_code=503, detail="Entity attribution not available")
    try:
        report = await asyncio.wait_for(
            attribution.generate_attribution_report(entity_id),
            timeout=60,
        )
        return report
    except asyncio.TimeoutError:
        logger.error(f"Attribution report generation timed out for entity '{entity_id}'")
        raise HTTPException(status_code=504, detail="Attribution report generation timed out")
    except Exception as exc:
        logger.error(f"Attribution report generation failed for entity '{entity_id}': {exc}")
        raise HTTPException(status_code=500, detail="操作失败")


@router.get("/embeddings-2d")
async def get_embeddings_2d(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    from numpy.linalg import svd

    entity_attribution = get_entity_attribution(request)
    if entity_attribution is None:
        return {"points": [], "total": 0}

    if entity_attribution._model is None:
        return {"points": [], "total": 0}

    try:
        embeddings = entity_attribution._model.entity_embeddings
        idx2entity = entity_attribution._idx2entity

        if embeddings is None or len(embeddings) == 0 or not idx2entity:
            return {"points": [], "total": 0}

        n_entities = min(len(embeddings), 200)
        embeddings_subset = embeddings[:n_entities]

        mean = embeddings_subset.mean(axis=0)
        centered = embeddings_subset - mean
        try:
            U, S, Vt = svd(centered, full_matrices=False)
            coords = centered @ Vt[:2].T
        except Exception:
            coords = centered[:, :2]

        points = []
        for i in range(n_entities):
            entity_id = idx2entity.get(i, str(i))
            entity = None
            entity_type = "unknown"
            try:
                entity = await entity_attribution.knowledge_graph.get_entity(entity_id)
                if entity:
                    entity_type = entity.type.value if hasattr(entity.type, "value") else str(entity.type)
            except Exception:
                pass

            points.append({
                "id": entity_id,
                "name": entity.value if entity else entity_id,
                "x": round(float(coords[i, 0]), 4),
                "y": round(float(coords[i, 1]), 4),
                "type": entity_type,
            })

        return {"points": points, "total": len(points)}
    except Exception as exc:
        logger.error(f"Embeddings 2D projection failed: {exc}")
        raise HTTPException(status_code=500, detail="操作失败")


@router.get("/top-entities")
async def get_top_entities(
    request: Request,
    limit: int = Query(default=20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
):
    """获取top实体列表及其自动归因结果，页面打开即有数据"""
    attribution = get_entity_attribution(request)
    kg = getattr(request.app.state, "knowledge_graph", None)
    if kg is None:
        raise HTTPException(status_code=503, detail="Knowledge graph not available")

    entities = []
    for eid, entity in list(kg._entities.items())[:limit * 3]:
        degree = kg.graph.degree(eid) if eid in kg.graph else 0
        entities.append((eid, entity, degree))
    entities.sort(key=lambda x: x[2], reverse=True)
    top = entities[:limit]

    results = []
    for eid, entity, degree in top:
        entry = {
            "id": eid,
            "value": entity.value,
            "type": entity.type.value if hasattr(entity.type, "value") else str(entity.type),
            "confidence": entity.confidence,
            "degree": degree,
            "fingerprint": None,
            "same_entities": [],
        }
        if attribution is not None:
            try:
                fp = await asyncio.wait_for(attribution.compute_behavioral_fingerprint(eid), timeout=10)
                entry["fingerprint"] = fp.to_dict()
            except Exception:
                pass
            try:
                matches = await asyncio.wait_for(attribution.find_same_entity(eid, threshold=0.7), timeout=10)
                entry["same_entities"] = [{"id": m.entity_id, "similarity": m.similarity} for m in matches[:3]]
            except Exception:
                pass
        results.append(entry)

    return {"entities": results, "total": len(results)}


@router.get("/analyses")
async def get_analyses_alias(
    request: Request,
    limit: int = Query(default=20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
):
    attribution = get_entity_attribution(request)
    kg = getattr(request.app.state, "knowledge_graph", None)
    if kg is None:
        raise HTTPException(status_code=503, detail="Knowledge graph not available")

    entities = []
    for eid, entity in list(kg._entities.items())[:limit * 3]:
        degree = kg.graph.degree(eid) if eid in kg.graph else 0
        entities.append((eid, entity, degree))
    entities.sort(key=lambda x: x[2], reverse=True)
    top = entities[:limit]

    results = []
    for eid, entity, degree in top:
        results.append({
            "id": eid,
            "value": entity.value,
            "type": entity.type.value if hasattr(entity.type, "value") else str(entity.type),
            "confidence": entity.confidence,
            "degree": degree,
        })
    return {"analyses": results, "total": len(results)}
