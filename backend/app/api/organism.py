import asyncio

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from loguru import logger
from pydantic import BaseModel, Field
from typing import Dict, List, Optional

from app.core.auth import User, get_current_user, require_role, Role

router = APIRouter(prefix="/organism", tags=["organism"])


class SpawnRequest(BaseModel):
    intelligence_id: str
    species: str = Field(..., description="ip/phone/bankcard/domain/ttp/organization/slang/campaign")
    initial_data: Dict = Field(default_factory=dict)


class EvolveRequest(BaseModel):
    organism_id: str
    new_data: Dict = Field(default_factory=dict)
    trigger: str = "manual"


class RegisterPredictionRequest(BaseModel):
    entity_id: str
    predicted_steps: List[Dict]
    validation_window_hours: float = 168


class FindGeneMatchesRequest(BaseModel):
    new_intelligence_data: Dict = Field(default_factory=dict)


class InheritGenesRequest(BaseModel):
    new_organism_id: str
    parent_gene_ids: List[str]


@router.post("/spawn")
async def spawn_organism(
    data: SpawnRequest,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    engine = getattr(request.app.state, "intelligence_organism", None)
    if not engine:
        raise HTTPException(status_code=503, detail="Intelligence Organism Engine not available")
    try:
        organism = await asyncio.wait_for(
            engine.spawn_organism(data.intelligence_id, data.species, data.initial_data),
            timeout=30,
        )
        return organism.to_dict()
    except Exception as exc:
        logger.error(f"Failed to spawn organism: {exc}")
        raise HTTPException(status_code=500, detail="生成进化体失败")


@router.post("/evolve")
async def evolve_organism(
    data: EvolveRequest,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    engine = getattr(request.app.state, "intelligence_organism", None)
    if not engine:
        raise HTTPException(status_code=503, detail="Intelligence Organism Engine not available")
    try:
        organism = await asyncio.wait_for(
            engine.evolve(data.organism_id, data.new_data, data.trigger),
            timeout=30,
        )
        return organism.to_dict()
    except Exception as exc:
        logger.error(f"Failed to evolve organism: {exc}")
        raise HTTPException(status_code=500, detail="进化操作失败")


@router.get("/vitality/{organism_id}")
async def check_vitality(
    organism_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    engine = getattr(request.app.state, "intelligence_organism", None)
    if not engine:
        raise HTTPException(status_code=503, detail="Intelligence Organism Engine not available")
    try:
        report = await engine.check_vitality(organism_id)
        return report.to_dict() if hasattr(report, 'to_dict') else report
    except Exception as exc:
        logger.error(f"Failed to check vitality: {exc}")
        raise HTTPException(status_code=500, detail="检查活性失败")


@router.get("/timeline/{organism_id}")
async def get_timeline(
    organism_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    engine = getattr(request.app.state, "intelligence_organism", None)
    if not engine:
        raise HTTPException(status_code=503, detail="Intelligence Organism Engine not available")
    try:
        timeline = await engine.get_evolution_timeline(organism_id)
        return {"organism_id": organism_id, "events": [e.to_dict() if hasattr(e, 'to_dict') else e for e in timeline]}
    except Exception as exc:
        logger.error(f"Failed to get timeline: {exc}")
        raise HTTPException(status_code=500, detail="获取时间线失败")


@router.get("/offspring/{organism_id}")
async def find_offspring(
    organism_id: str,
    depth: int = Query(3, ge=1, le=10),
    request: Request = None,
    current_user: User = Depends(get_current_user),
):
    engine = getattr(request.app.state, "intelligence_organism", None)
    if not engine:
        raise HTTPException(status_code=503, detail="Intelligence Organism Engine not available")
    try:
        tree = await engine.find_offspring(organism_id, depth)
        return tree.to_dict() if hasattr(tree, 'to_dict') else tree
    except Exception as exc:
        logger.error(f"Failed to find offspring: {exc}")
        raise HTTPException(status_code=500, detail="查找后代失败")


@router.post("/prediction/register")
async def register_prediction(
    data: RegisterPredictionRequest,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    engine = getattr(request.app.state, "intelligence_organism", None)
    if not engine:
        raise HTTPException(status_code=503, detail="Intelligence Organism Engine not available")
    try:
        tracker = await engine.register_prediction(
            data.entity_id, data.predicted_steps, data.validation_window_hours
        )
        return tracker.to_dict()
    except Exception as exc:
        logger.error(f"Failed to register prediction: {exc}")
        raise HTTPException(status_code=500, detail="注册预测失败")


@router.post("/prediction/validate")
async def validate_predictions(
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    engine = getattr(request.app.state, "intelligence_organism", None)
    if not engine:
        raise HTTPException(status_code=503, detail="Intelligence Organism Engine not available")
    try:
        results = await asyncio.wait_for(engine.validate_predictions(), timeout=120)
        return {"validations": [r.to_dict() if hasattr(r, 'to_dict') else r for r in results]}
    except Exception as exc:
        logger.error(f"Failed to validate predictions: {exc}")
        raise HTTPException(status_code=500, detail="验证预测失败")


@router.get("/prediction/accuracy")
async def get_prediction_accuracy(
    entity_id: Optional[str] = None,
    request: Request = None,
    current_user: User = Depends(get_current_user),
):
    engine = getattr(request.app.state, "intelligence_organism", None)
    if not engine:
        raise HTTPException(status_code=503, detail="Intelligence Organism Engine not available")
    try:
        report = await engine.get_prediction_accuracy(entity_id)
        return report.to_dict() if hasattr(report, 'to_dict') else report
    except Exception as exc:
        logger.error(f"Failed to get accuracy: {exc}")
        raise HTTPException(status_code=500, detail="获取预测准确率失败")


@router.post("/prediction/calibrate")
async def calibrate_model(
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    engine = getattr(request.app.state, "intelligence_organism", None)
    if not engine:
        raise HTTPException(status_code=503, detail="Intelligence Organism Engine not available")
    try:
        result = await engine.calibrate_model()
        return result.to_dict() if hasattr(result, 'to_dict') else result
    except Exception as exc:
        logger.error(f"Failed to calibrate: {exc}")
        raise HTTPException(status_code=500, detail="模型校准失败")


@router.post("/gene/archive/{organism_id}")
async def archive_organism(
    organism_id: str,
    cause: str = "expired",
    request: Request = None,
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    engine = getattr(request.app.state, "intelligence_organism", None)
    if not engine:
        raise HTTPException(status_code=503, detail="Intelligence Organism Engine not available")
    try:
        gene = await engine.archive_organism(organism_id, cause)
        return gene.to_dict()
    except Exception as exc:
        logger.error(f"Failed to archive organism: {exc}")
        raise HTTPException(status_code=500, detail="归档进化体失败")


@router.post("/gene/match")
async def find_gene_matches(
    data: FindGeneMatchesRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    engine = getattr(request.app.state, "intelligence_organism", None)
    if not engine:
        raise HTTPException(status_code=503, detail="Intelligence Organism Engine not available")
    try:
        matches = await engine.find_gene_matches(data.new_intelligence_data)
        return {"matches": [m.to_dict() if hasattr(m, 'to_dict') else m for m in matches]}
    except Exception as exc:
        logger.error(f"Failed to find gene matches: {exc}")
        raise HTTPException(status_code=500, detail="基因匹配失败")


@router.post("/gene/inherit")
async def inherit_genes(
    data: InheritGenesRequest,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    engine = getattr(request.app.state, "intelligence_organism", None)
    if not engine:
        raise HTTPException(status_code=503, detail="Intelligence Organism Engine not available")
    try:
        result = await engine.inherit_genes(data.new_organism_id, data.parent_gene_ids)
        return result if isinstance(result, dict) else {"result": str(result)}
    except Exception as exc:
        logger.error(f"Failed to inherit genes: {exc}")
        raise HTTPException(status_code=500, detail="基因继承失败")


@router.get("/genealogy/{organism_id}")
async def get_genealogy(
    organism_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    engine = getattr(request.app.state, "intelligence_organism", None)
    if not engine:
        raise HTTPException(status_code=503, detail="Intelligence Organism Engine not available")
    try:
        tree = await engine.get_genealogy(organism_id)
        return tree.to_dict() if hasattr(tree, 'to_dict') else tree
    except Exception as exc:
        logger.error(f"Failed to get genealogy: {exc}")
        raise HTTPException(status_code=500, detail="获取谱系失败")


@router.post("/lifecycle-check")
async def run_lifecycle_check(
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    engine = getattr(request.app.state, "intelligence_organism", None)
    if not engine:
        raise HTTPException(status_code=503, detail="Intelligence Organism Engine not available")
    try:
        result = await asyncio.wait_for(engine.run_lifecycle_check(), timeout=120)
        return result if isinstance(result, dict) else {"result": str(result)}
    except Exception as exc:
        logger.error(f"Failed to run lifecycle check: {exc}")
        raise HTTPException(status_code=500, detail="生命周期检查失败")


@router.get("/organisms")
async def list_organisms(
    species: Optional[str] = None,
    alive_only: bool = True,
    limit: int = Query(50, ge=1, le=200),
    offset: int = 0,
    request: Request = None,
    current_user: User = Depends(get_current_user),
):
    engine = getattr(request.app.state, "intelligence_organism", None)
    if not engine:
        raise HTTPException(status_code=503, detail="Intelligence Organism Engine not available")
    limit = max(1, min(limit, 1000))
    offset = max(0, offset)
    organisms = list(engine.organisms.values())
    if species:
        organisms = [o for o in organisms if o.species == species]
    if alive_only:
        organisms = [o for o in organisms if o.is_alive]
    total = len(organisms)
    return {
        "total": total,
        "organisms": [o.to_dict() for o in organisms[offset:offset + limit]],
    }


@router.get("/genes")
async def list_genes(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    engine = getattr(request.app.state, "intelligence_organism", None)
    if not engine:
        raise HTTPException(status_code=503, detail="Intelligence Organism Engine not available")
    genes = list(engine.genes.values())
    return {
        "total": len(genes),
        "genes": [g.to_dict() for g in genes[:50]],
    }


@router.get("/status")
async def get_status_alias(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    engine = getattr(request.app.state, "intelligence_organism", None)
    if not engine:
        raise HTTPException(status_code=503, detail="Intelligence Organism Engine not available")
    organisms = list(engine.organisms.values())
    alive = [o for o in organisms if o.is_alive]
    species_counts = {}
    for o in organisms:
        species_counts[o.species] = species_counts.get(o.species, 0) + 1
    return {
        "total_organisms": len(organisms),
        "alive_organisms": len(alive),
        "total_genes": len(engine.genes),
        "species_distribution": species_counts,
    }
