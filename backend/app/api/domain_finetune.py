import json
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from loguru import logger
from pydantic import BaseModel, Field

from app.core.auth import User, get_current_user

router = APIRouter(prefix="/domain-finetune", tags=["领域微调"])


class AnnotationCreate(BaseModel):
    intelligence_id: str = Field(..., min_length=1, max_length=64)
    text: str = Field("", max_length=50000)
    entities: List[Dict] = Field(default_factory=list)
    categories: List[str] = Field(default_factory=list)
    annotator: str = Field("system", max_length=128)


class ExportRequest(BaseModel):
    format: str = Field("jsonl", pattern="^(jsonl|conll2003|csv)$")
    train_ratio: float = Field(0.8, ge=0.1, le=0.9)
    val_ratio: float = Field(0.1, ge=0.05, le=0.5)
    test_ratio: float = Field(0.1, ge=0.05, le=0.5)


class JobCreate(BaseModel):
    base_model: str = Field(..., min_length=1, max_length=256)
    dataset_id: str = Field(..., min_length=1, max_length=64)
    hyperparams: Dict = Field(default_factory=lambda: {
        "epochs": 3, "batch_size": 4, "learning_rate": 2e-4,
    })


class EvaluateNERRequest(BaseModel):
    predictions: List[Dict]
    ground_truth: List[Dict]


class EvaluateClassificationRequest(BaseModel):
    predictions: List[str]
    ground_truth: List[str]


class ActiveLearnRequest(BaseModel):
    predictions: List[Dict]
    count: int = Field(10, ge=1, le=100)
    strategy: str = Field("entropy", pattern="^(entropy|margin|least_confident)$")


def _get_training_data_manager(request: Request):
    mgr = getattr(request.app.state, "training_data_manager", None)
    if mgr is None:
        from app.core.domain_finetune import TrainingDataManager
        mgr = TrainingDataManager()
        request.app.state.training_data_manager = mgr
    return mgr


def _get_finetune_job_manager(request: Request):
    mgr = getattr(request.app.state, "finetune_job_manager", None)
    if mgr is None:
        from app.core.domain_finetune import FinetuneJobManager
        llm = getattr(request.app.state, "llm", None)
        mgr = FinetuneJobManager(llm_service=llm)
        request.app.state.finetune_job_manager = mgr
    return mgr


def _get_model_evaluator(request: Request):
    evaluator = getattr(request.app.state, "domain_model_evaluator", None)
    if evaluator is None:
        from app.core.domain_finetune import DomainModelEvaluator
        llm = getattr(request.app.state, "llm", None)
        evaluator = DomainModelEvaluator(llm_service=llm)
        request.app.state.domain_model_evaluator = evaluator
    return evaluator


@router.post("/annotations")
async def add_annotation(
    req: AnnotationCreate,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    mgr = _get_training_data_manager(request)
    ann = mgr.add_annotation(
        intelligence_id=req.intelligence_id,
        entities=req.entities,
        categories=req.categories,
        text=req.text,
        annotator=req.annotator,
    )
    return {"success": True, "data": ann.to_dict()}


@router.get("/annotations")
async def list_annotations(
    request: Request,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
):
    mgr = _get_training_data_manager(request)
    annotations = mgr.list_annotations(limit=limit, offset=offset)
    return {
        "success": True,
        "data": [ann.to_dict() for ann in annotations],
    }


@router.get("/annotations/stats")
async def get_annotation_stats(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    mgr = _get_training_data_manager(request)
    return {"success": True, "data": mgr.get_annotation_stats()}


@router.get("/annotations/validate")
async def validate_annotations(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    mgr = _get_training_data_manager(request)
    return {"success": True, "data": mgr.validate_annotations()}


@router.delete("/annotations/{intelligence_id}")
async def delete_annotation(
    intelligence_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    mgr = _get_training_data_manager(request)
    deleted = mgr.delete_annotation(intelligence_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Annotation not found")
    return {"success": True}


@router.post("/export")
async def export_training_set(
    req: ExportRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    mgr = _get_training_data_manager(request)
    result = mgr.export_training_set(
        format=req.format,
        split_ratio=(req.train_ratio, req.val_ratio, req.test_ratio),
    )
    return {"success": True, "data": result}


@router.get("/datasets")
async def list_datasets(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    mgr = _get_training_data_manager(request)
    return {"success": True, "data": mgr.list_datasets()}


@router.post("/jobs")
async def create_finetune_job(
    req: JobCreate,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    mgr = _get_finetune_job_manager(request)
    job_id = mgr.create_job(
        base_model=req.base_model,
        dataset_id=req.dataset_id,
        hyperparams=req.hyperparams,
    )
    return {"success": True, "data": {"job_id": job_id}}


@router.post("/jobs/{job_id}/start")
async def start_finetune_job(
    job_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    mgr = _get_finetune_job_manager(request)
    success = await mgr.start_job(job_id)
    if not success:
        raise HTTPException(status_code=400, detail="Failed to start job")
    return {"success": True}


@router.post("/jobs/{job_id}/cancel")
async def cancel_finetune_job(
    job_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    mgr = _get_finetune_job_manager(request)
    success = mgr.cancel_job(job_id)
    if not success:
        raise HTTPException(status_code=400, detail="Failed to cancel job")
    return {"success": True}


@router.get("/jobs/{job_id}")
async def get_finetune_job_status(
    job_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    mgr = _get_finetune_job_manager(request)
    status = mgr.get_job_status(job_id)
    if not status:
        raise HTTPException(status_code=404, detail="Job not found")
    return {"success": True, "data": status}


@router.get("/jobs")
async def list_finetune_jobs(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    mgr = _get_finetune_job_manager(request)
    return {"success": True, "data": mgr.list_jobs()}


@router.post("/jobs/{job_id}/deploy")
async def deploy_finetune_model(
    job_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    mgr = _get_finetune_job_manager(request)
    result = mgr.deploy_model(job_id)
    if not result:
        raise HTTPException(status_code=400, detail="Failed to deploy model")
    return {"success": True, "data": result}


@router.get("/deployed-models")
async def list_deployed_models(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    mgr = _get_finetune_job_manager(request)
    return {"success": True, "data": mgr.list_deployed_models()}


@router.post("/evaluate/ner")
async def evaluate_ner(
    req: EvaluateNERRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    evaluator = _get_model_evaluator(request)
    result = await evaluator.evaluate_ner(req.predictions, req.ground_truth)
    return {"success": True, "data": result}


@router.post("/evaluate/classification")
async def evaluate_classification(
    req: EvaluateClassificationRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    evaluator = _get_model_evaluator(request)
    result = await evaluator.evaluate_classification(req.predictions, req.ground_truth)
    return {"success": True, "data": result}


@router.post("/evaluate/compare")
async def compare_models(
    request: Request,
    model_a_results: Dict,
    model_b_results: Dict,
    current_user: User = Depends(get_current_user),
):
    evaluator = _get_model_evaluator(request)
    result = await evaluator.compare_models(model_a_results, model_b_results)
    return {"success": True, "data": result}


@router.post("/active-learn/select")
async def active_learn_select(
    req: ActiveLearnRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    from app.core.domain_finetune import ActiveLearner
    learner = ActiveLearner(strategy=req.strategy)
    samples = learner.select_uncertain_samples(req.predictions, req.count)
    return {"success": True, "data": {"samples": samples, "count": len(samples)}}
