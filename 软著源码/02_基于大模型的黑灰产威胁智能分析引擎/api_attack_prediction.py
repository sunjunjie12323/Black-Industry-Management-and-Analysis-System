import asyncio
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from loguru import logger
from pydantic import BaseModel, Field

from app.core.auth import User, get_current_user, require_role, Role
from app.core.attack_chain_predictor import AttackChainPredictor, MITRE_TECHNIQUES

router = APIRouter(prefix="/attack-prediction", tags=["attack-prediction"])


class PredictRequest(BaseModel):
    entity_id: str = Field(..., min_length=1)
    depth: int = Field(default=3, ge=1, le=10)


class SimulateRequest(BaseModel):
    entity_id: str = Field(..., min_length=1)
    steps: int = Field(default=5, ge=1, le=20)


class PredictByNameRequest(BaseModel):
    name: str = Field(..., min_length=1)
    depth: int = Field(default=3, ge=1, le=10)


class EarlyWarningRequest(BaseModel):
    entity_id: str = Field(..., min_length=1)


def get_attack_chain_predictor(request: Request) -> AttackChainPredictor | None:
    return getattr(request.app.state, "attack_chain_predictor", None)


@router.post("/predict")
async def predict_next_steps(
    data: PredictRequest,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    predictor = get_attack_chain_predictor(request)
    if predictor is None:
        raise HTTPException(status_code=503, detail="Attack chain predictor not available")
    try:
        result = await asyncio.wait_for(
            predictor.predict_next_steps(data.entity_id, depth=data.depth),
            timeout=60,
        )
        return result.to_dict()
    except asyncio.TimeoutError:
        logger.error(f"Attack prediction timed out for entity '{data.entity_id}'")
        raise HTTPException(status_code=504, detail="Attack prediction timed out")
    except Exception as exc:
        logger.error(f"Attack prediction failed for entity '{data.entity_id}': {exc}")
        raise HTTPException(status_code=500, detail="操作失败")


@router.post("/predict-by-name")
async def predict_by_name(
    data: PredictByNameRequest,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    kg = getattr(request.app.state, "knowledge_graph", None)
    if kg is None:
        raise HTTPException(status_code=503, detail="Knowledge graph not available")
    entity = None
    for e in kg._entities.values():
        if e.value.lower() == data.name.lower():
            entity = e
            break
    if not entity:
        results = await kg.search_entities(data.name, limit=1)
        if results:
            entity = results[0]
    if not entity:
        raise HTTPException(status_code=404, detail=f"Entity not found: {data.name}")
    entity_id = entity.id
    predictor = get_attack_chain_predictor(request)
    try:
        result = await asyncio.wait_for(
            predictor.predict_next_steps(entity_id, depth=data.depth),
            timeout=60,
        )
        return {
            "entity_id": entity_id,
            "entity_name": entity.value,
            "predictions": result.to_dict(),
        }
    except asyncio.TimeoutError:
        logger.error(f"Attack prediction timed out for entity '{entity_id}'")
        raise HTTPException(status_code=504, detail="Attack prediction timed out")
    except Exception as exc:
        logger.error(f"Attack prediction failed for entity '{entity_id}': {exc}")
        raise HTTPException(status_code=500, detail="操作失败")


@router.post("/simulate")
async def simulate_attack_chain(
    data: SimulateRequest,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    predictor = get_attack_chain_predictor(request)
    if predictor is None:
        raise HTTPException(status_code=503, detail="Attack chain predictor not available")
    try:
        result = await asyncio.wait_for(
            predictor.simulate_attack_chain(data.entity_id, steps=data.steps),
            timeout=60,
        )
        return result.to_dict()
    except asyncio.TimeoutError:
        logger.error(f"Attack chain simulation timed out for entity '{data.entity_id}'")
        raise HTTPException(status_code=504, detail="Attack chain simulation timed out")
    except Exception as exc:
        logger.error(f"Attack chain simulation failed for entity '{data.entity_id}': {exc}")
        raise HTTPException(status_code=500, detail="操作失败")


@router.post("/early-warning")
async def find_early_warning_signals(
    data: EarlyWarningRequest,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    predictor = get_attack_chain_predictor(request)
    if predictor is None:
        raise HTTPException(status_code=503, detail="Attack chain predictor not available")
    try:
        prediction = await asyncio.wait_for(
            predictor.predict_next_steps(data.entity_id, depth=3),
            timeout=60,
        )
        warnings = await asyncio.wait_for(
            predictor.find_early_warning_signals(prediction),
            timeout=60,
        )
        return {
            "warnings": [w.to_dict() for w in warnings],
            "total_signals": len(warnings),
        }
    except asyncio.TimeoutError:
        logger.error(f"Early warning analysis timed out for entity '{data.entity_id}'")
        raise HTTPException(status_code=504, detail="Early warning analysis timed out")
    except Exception as exc:
        logger.error(f"Early warning analysis failed for entity '{data.entity_id}': {exc}")
        raise HTTPException(status_code=500, detail="操作失败")


@router.get("/visualization")
async def get_visualization(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    predictor = get_attack_chain_predictor(request)
    knowledge_graph = getattr(request.app.state, "knowledge_graph", None)

    nodes = []
    edges = []
    tactics_set = set()

    for tech_id, tech_info in MITRE_TECHNIQUES.items():
        tactic = tech_info.get("tactic", "unknown")
        risk = tech_info.get("risk", "medium")
        tactics_set.add(tactic)
        nodes.append({
            "id": tech_id,
            "label": tech_info.get("name", tech_id),
            "type": "technique",
            "tactic": tactic,
            "risk": risk,
            "probability": 0.0,
        })

    if knowledge_graph is not None:
        try:
            for entity_id, entity in knowledge_graph._entities.items():
                entity_type = entity.type.value if hasattr(entity.type, "value") else str(entity.type)
                nodes.append({
                    "id": entity_id,
                    "label": entity.value,
                    "type": "entity",
                    "tactic": entity_type,
                    "risk": "medium",
                    "probability": 0.0,
                })
        except Exception as exc:
            logger.warning(f"Failed to read knowledge graph entities for visualization: {exc}")

    if predictor is not None:
        try:
            transition_counts = predictor._transition_counts
            for src_tactic, dst_map in transition_counts.items():
                total = sum(dst_map.values())
                if total == 0:
                    continue
                for dst_tactic, count in dst_map.items():
                    if count > 0:
                        prob = round(count / total, 4)
                        edges.append({
                            "source": src_tactic,
                            "target": dst_tactic,
                            "probability": prob,
                            "label": f"{prob:.2f}",
                        })
        except Exception as exc:
            logger.warning(f"Failed to read transition counts for visualization: {exc}")

    return {
        "nodes": nodes,
        "edges": edges,
        "tactics": sorted(tactics_set),
    }


@router.get("/top-predictions")
async def top_predictions(
    request: Request,
    limit: int = Query(default=10, ge=1, le=50),
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST, Role.VIEWER)),
):
    kg = request.app.state.knowledge_graph
    acp = request.app.state.attack_chain_predictor
    if kg is None or acp is None:
        raise HTTPException(status_code=503, detail="Services not available")
    try:
        entities = list(kg._entities.values())
        scored = []
        for e in entities:
            degree = kg.graph.degree(e.id) if e.id in kg.graph else 0
            scored.append((e, degree))
        scored.sort(key=lambda x: x[1], reverse=True)

        llm = getattr(request.app.state, "llm_service", None)
        llm_ok = llm is not None and hasattr(llm, "is_available") and llm.is_available

        sem = asyncio.Semaphore(3)
        results = []

        async def _predict_one(entity, degree):
            async with sem:
                try:
                    pred = await asyncio.wait_for(
                        acp.predict_next_steps(entity.id, depth=3),
                        timeout=30 if llm_ok else 10,
                    )
                    results.append({
                        "entity_id": entity.id,
                        "entity_type": entity.type.value,
                        "entity_value": entity.value,
                        "degree": degree,
                        "predictions": [{"technique": p.technique_id, "name": p.technique_name, "probability": p.probability} for p in pred.predictions[:5]],
                    })
                except asyncio.TimeoutError:
                    logger.warning(f"Prediction timed out for entity {entity.id}")
                except Exception as exc:
                    logger.warning(f"Prediction failed for entity {entity.id}: {exc}")

        tasks = [_predict_one(entity, degree) for entity, degree in scored[:limit]]
        await asyncio.gather(*tasks)
        return {"total": len(results), "predictions": results}
    except Exception as exc:
        raise HTTPException(status_code=500, detail="操作失败")


@router.get("/predictions")
async def get_predictions_alias(
    request: Request,
    limit: int = Query(default=10, ge=1, le=50),
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST, Role.VIEWER)),
):
    return await top_predictions(request, limit, current_user)


@router.get("/stats")
async def get_attack_prediction_stats(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    predictor = get_attack_chain_predictor(request)
    kg = getattr(request.app.state, "knowledge_graph", None)
    stats = {
        "total_entities": len(kg._entities) if kg else 0,
        "total_techniques": len(MITRE_TECHNIQUES),
        "total_transitions": predictor._total_transitions if predictor else 0,
        "predictor_available": predictor is not None,
        "knowledge_graph_available": kg is not None,
    }
    return stats
