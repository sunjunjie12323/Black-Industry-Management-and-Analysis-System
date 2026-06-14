import asyncio
import json
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from loguru import logger
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import User, get_current_user
from app.core.db_utils import db_write
from app.core.finetune_engine import FinetuneWorker, TrainingStatus
from app.core.validators import validate_domain_object
from app.db.database import get_db, async_session_factory
from app.db.tables import FinetuneTaskTable
from app.models.finetune_task import FinetuneMethod, FinetuneStatus, FinetuneTask

router = APIRouter(tags=["模型微调"])


class FinetuneTaskCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=256)
    method: FinetuneMethod
    base_model: str = Field(..., min_length=1, max_length=256)
    config_json: str = Field("{}", max_length=65536)
    dataset_ref: Optional[str] = Field(None, max_length=512)
    created_by: str = Field("system", max_length=128)


class CheckpointRequest(BaseModel):
    checkpoint_name: Optional[str] = Field(None, max_length=256)


class RestoreRequest(BaseModel):
    checkpoint_ref: str = Field(..., min_length=1, max_length=256)


class ExportModelRequest(BaseModel):
    export_format: str = Field(..., pattern="^(huggingface|onnx)$")


class EvaluateRequest(BaseModel):
    eval_dataset_ref: Optional[str] = Field(None, max_length=512)
    metrics: List[str] = Field(default_factory=lambda: ["accuracy", "f1", "loss"])


def _row_to_dict(row: FinetuneTaskTable) -> Dict:
    return {
        "id": row.id,
        "name": row.name,
        "method": row.method,
        "base_model": row.base_model,
        "status": row.status,
        "config_json": row.config_json,
        "dataset_ref": row.dataset_ref,
        "checkpoint_ref": row.checkpoint_ref,
        "output_model_ref": row.output_model_ref,
        "metrics_json": row.metrics_json,
        "version": row.version,
        "progress": row.progress,
        "error_message": row.error_message,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "started_at": row.started_at.isoformat() if row.started_at else None,
        "completed_at": row.completed_at.isoformat() if row.completed_at else None,
        "created_by": row.created_by,
        "parent_id": row.parent_id,
    }


def _get_finetune_worker(request: Request) -> FinetuneWorker:
    worker = getattr(request.app.state, "finetune_worker", None)
    if worker is None:
        llm = getattr(request.app.state, "llm", None)
        worker = FinetuneWorker(llm_service=llm)
        request.app.state.finetune_worker = worker
    return worker


@router.get("/statistics")
async def get_statistics(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    total_result = await db.execute(select(func.count()).select_from(FinetuneTaskTable))
    total = total_result.scalar() or 0

    method_counts = {}
    method_result = await db.execute(
        select(FinetuneTaskTable.method, func.count()).group_by(FinetuneTaskTable.method)
    )
    for method, count in method_result.all():
        method_counts[method] = count

    status_counts = {}
    status_result = await db.execute(
        select(FinetuneTaskTable.status, func.count()).group_by(FinetuneTaskTable.status)
    )
    for status_val, count in status_result.all():
        status_counts[status_val] = count

    completed = status_counts.get(FinetuneStatus.COMPLETED.value, 0)
    failed = status_counts.get(FinetuneStatus.FAILED.value, 0)
    finished = completed + failed
    success_rate = round(completed / finished * 100, 2) if finished > 0 else 0.0

    avg_progress_result = await db.execute(
        select(func.avg(FinetuneTaskTable.progress)).where(
            FinetuneTaskTable.status == FinetuneStatus.TRAINING.value
        )
    )
    avg_progress = round(avg_progress_result.scalar() or 0, 2)

    return {
        "total": total,
        "by_method": method_counts,
        "by_status": status_counts,
        "success_rate": success_rate,
        "avg_training_progress": avg_progress,
        "completed_models": completed,
    }


@router.get("/tasks")
async def list_tasks(
    method: Optional[str] = None,
    status: Optional[str] = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = select(FinetuneTaskTable)
    count_stmt = select(func.count()).select_from(FinetuneTaskTable)

    if method:
        stmt = stmt.where(FinetuneTaskTable.method == method)
        count_stmt = count_stmt.where(FinetuneTaskTable.method == method)
    if status:
        stmt = stmt.where(FinetuneTaskTable.status == status)
        count_stmt = count_stmt.where(FinetuneTaskTable.status == status)

    total_result = await db.execute(count_stmt)
    total = total_result.scalar() or 0

    stmt = stmt.order_by(FinetuneTaskTable.created_at.desc()).offset(offset).limit(limit)
    result = await db.execute(stmt)
    rows = result.scalars().all()

    return {"items": [_row_to_dict(r) for r in rows], "total": total, "offset": offset, "limit": limit}


@router.post("/tasks", status_code=201)
async def create_task(
    data: FinetuneTaskCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    task_id = uuid.uuid4().hex

    validation = validate_domain_object("finetune_task", data.model_dump())
    if not validation.is_valid:
        raise HTTPException(status_code=400, detail={"errors": validation.errors, "warnings": validation.warnings})

    dup_result = await db.execute(select(FinetuneTaskTable).where(FinetuneTaskTable.name == data.name))
    if dup_result.scalar_one_or_none() is not None:
        raise HTTPException(status_code=409, detail=f"微调任务名称 '{data.name}' 已存在")

    row = FinetuneTaskTable(
        id=task_id,
        name=data.name,
        method=data.method.value,
        base_model=data.base_model,
        status=FinetuneStatus.PENDING.value,
        config_json=data.config_json,
        dataset_ref=data.dataset_ref,
        created_by=data.created_by,
    )
    async with db_write(db, operation="创建微调任务"):
        db.add(row)
    await db.refresh(row)
    return _row_to_dict(row)


@router.get("/tasks/{task_id}")
async def get_task(
    task_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(FinetuneTaskTable).where(FinetuneTaskTable.id == task_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="微调任务不存在")
    return _row_to_dict(row)


@router.post("/tasks/{task_id}/start")
async def start_training(
    request: Request,
    task_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(FinetuneTaskTable).where(FinetuneTaskTable.id == task_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="微调任务不存在")
    if row.status not in (FinetuneStatus.PENDING.value, FinetuneStatus.PREPARING.value):
        raise HTTPException(status_code=400, detail=f"任务状态为 {row.status}，无法启动")

    async with db_write(db, operation="启动训练"):
        row.status = FinetuneStatus.TRAINING.value
        row.started_at = datetime.now(timezone.utc)
        row.progress = 0.0
    await db.refresh(row)

    worker = _get_finetune_worker(request)

    config = {}
    try:
        config = json.loads(row.config_json) if row.config_json else {}
    except (json.JSONDecodeError, TypeError):
        config = {}

    try:
        progress = await worker.start_training(
            task_id=task_id,
            method=row.method,
            base_model=row.base_model,
            config=config,
            dataset_ref=row.dataset_ref,
            checkpoint_ref=row.checkpoint_ref,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="请求参数错误")

    async def _monitor_and_update():
        while True:
            await asyncio.sleep(2)
            p = worker.get_progress(task_id)
            if p is None:
                break

            try:
                async with async_session_factory() as update_session:
                    update_result = await update_session.execute(
                        select(FinetuneTaskTable).where(FinetuneTaskTable.id == task_id)
                    )
                    update_row = update_result.scalar_one_or_none()
                    if update_row:
                        update_row.progress = p.progress
                        update_row.status = p.status.value
                        if p.status in (TrainingStatus.COMPLETED, TrainingStatus.FAILED, TrainingStatus.CANCELLED):
                            metrics = worker.get_model_versions(task_id)
                            if metrics:
                                update_row.metrics_json = json.dumps(
                                    metrics[-1].get("metrics", {}), ensure_ascii=False
                                )
                                update_row.output_model_ref = metrics[-1].get("model_path", "")
                            update_row.completed_at = datetime.now(timezone.utc)
                            await update_session.commit()
                            break
                        await update_session.commit()
            except Exception as exc:
                logger.warning(f"Monitor update failed for {task_id}: {exc}")

            if p.status in (TrainingStatus.COMPLETED, TrainingStatus.FAILED, TrainingStatus.CANCELLED):
                break

    async def _safe_monitor_task():
        try:
            await _monitor_and_update()
        except Exception as exc:
            logger.error(f"Deployment task failed: {exc}")

    asyncio.create_task(_safe_monitor_task())

    return {**_row_to_dict(row), "message": "训练已启动", "training_progress": progress.to_dict()}


@router.post("/tasks/{task_id}/cancel")
async def cancel_training(
    request: Request,
    task_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(FinetuneTaskTable).where(FinetuneTaskTable.id == task_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="微调任务不存在")
    if row.status not in (FinetuneStatus.PENDING.value, FinetuneStatus.PREPARING.value, FinetuneStatus.TRAINING.value):
        raise HTTPException(status_code=400, detail="当前状态无法取消")

    worker = _get_finetune_worker(request)
    worker.cancel_training(task_id)

    async with db_write(db, operation="取消训练"):
        row.status = FinetuneStatus.FAILED.value
        row.error_message = "训练已被用户主动取消（状态标记为失败）"
    await db.refresh(row)
    return _row_to_dict(row)


@router.post("/tasks/{task_id}/checkpoint")
async def save_checkpoint(
    request: Request,
    task_id: str,
    data: CheckpointRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(FinetuneTaskTable).where(FinetuneTaskTable.id == task_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="微调任务不存在")

    worker = _get_finetune_worker(request)
    progress = worker.get_progress(task_id)

    current_step = progress.current_step if progress else 0
    current_epoch = progress.current_epoch if progress else 0.0
    current_loss = progress.train_loss if progress else 0.0

    cp = worker.save_checkpoint_public(
        task_id=task_id,
        step=current_step,
        epoch=current_epoch,
        loss=current_loss,
        metrics={"train_loss": current_loss} if current_loss else {},
    )

    async with db_write(db, operation="保存检查点"):
        row.checkpoint_ref = cp.checkpoint_id
    await db.refresh(row)

    return {
        "checkpoint": cp.to_dict(),
        "task_id": task_id,
        "available_checkpoints": worker.get_checkpoints(task_id),
    }


@router.post("/tasks/{task_id}/restore")
async def restore_from_checkpoint(
    request: Request,
    task_id: str,
    data: RestoreRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(FinetuneTaskTable).where(FinetuneTaskTable.id == task_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="微调任务不存在")

    worker = _get_finetune_worker(request)

    checkpoint_info = None
    for cp in worker.list_checkpoints_public(task_id):
        if cp.checkpoint_id == data.checkpoint_ref:
            checkpoint_info = cp
            break

    if not checkpoint_info:
        raise HTTPException(status_code=400, detail="检查点不存在")

    restored = worker.restore_from_checkpoint(task_id, data.checkpoint_ref)

    if not restored:
        raise HTTPException(status_code=400, detail="检查点恢复失败")

    async with db_write(db, operation="恢复检查点"):
        row.checkpoint_ref = data.checkpoint_ref
        row.status = FinetuneStatus.PREPARING.value
        row.error_message = None
        row.progress = checkpoint_info.step
    await db.refresh(row)
    return {**_row_to_dict(row), "restored_checkpoint": checkpoint_info.to_dict()}


@router.get("/tasks/{task_id}/metrics")
async def get_training_metrics(
    request: Request,
    task_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(FinetuneTaskTable).where(FinetuneTaskTable.id == task_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="微调任务不存在")

    metrics = {}
    if row.metrics_json:
        try:
            metrics = json.loads(row.metrics_json)
        except (json.JSONDecodeError, TypeError):
            metrics = {}

    worker = _get_finetune_worker(request)
    progress = worker.get_progress(task_id)
    progress_data = progress.to_dict() if progress else None

    checkpoints = worker.get_checkpoints(task_id)
    model_versions = worker.get_model_versions(task_id)

    return {
        "task_id": task_id,
        "status": row.status,
        "progress": row.progress,
        "metrics": metrics,
        "base_model": row.base_model,
        "method": row.method,
        "realtime_progress": progress_data,
        "checkpoints": checkpoints,
        "model_versions": model_versions,
    }


@router.post("/tasks/{task_id}/evaluate")
async def evaluate_task(
    request: Request,
    task_id: str,
    data: EvaluateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(FinetuneTaskTable).where(FinetuneTaskTable.id == task_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="微调任务不存在")

    if row.status not in (FinetuneStatus.COMPLETED.value, FinetuneStatus.TRAINING.value):
        raise HTTPException(status_code=400, detail=f"任务状态为 {row.status}，无法进行评估，仅已完成或训练中的任务可评估")
    if not row.output_model_ref:
        raise HTTPException(status_code=400, detail="模型尚未训练完成，无法进行评估（缺少 output_model_ref）")

    row.status = FinetuneStatus.EVALUATING.value
    await db.commit()
    await db.refresh(row)

    worker = _get_finetune_worker(request)

    async def _run_evaluation():
        try:
            eval_result = await worker.evaluate_model(
                task_id=task_id,
                eval_data=None,
                model_path=row.output_model_ref,
                metrics=data.metrics,
            )

            async with async_session_factory() as update_session:
                update_result = await update_session.execute(
                    select(FinetuneTaskTable).where(FinetuneTaskTable.id == task_id)
                )
                update_row = update_result.scalar_one_or_none()
                if update_row:
                    update_row.status = FinetuneStatus.COMPLETED.value
                    existing_metrics = {}
                    if update_row.metrics_json:
                        try:
                            existing_metrics = json.loads(update_row.metrics_json)
                        except (json.JSONDecodeError, TypeError):
                            existing_metrics = {}
                    existing_metrics["evaluation"] = eval_result.to_dict()
                    update_row.metrics_json = json.dumps(existing_metrics, ensure_ascii=False)
                    await update_session.commit()
        except Exception as exc:
            logger.error(f"Evaluation failed for task {task_id}: {exc}")
            try:
                async with async_session_factory() as err_session:
                    err_result = await err_session.execute(
                        select(FinetuneTaskTable).where(FinetuneTaskTable.id == task_id)
                    )
                    err_row = err_result.scalar_one_or_none()
                    if err_row:
                        err_row.status = FinetuneStatus.FAILED.value
                        err_row.error_message = f"评估失败: {str(exc)[:300]}"
                        await err_session.commit()
            except Exception as exc:
                logger.debug(f"Failed to update error status after evaluation failure: {exc}")

    async def _safe_eval_task():
        try:
            await _run_evaluation()
        except Exception as exc:
            logger.error(f"Deployment task failed: {exc}")

    asyncio.create_task(_safe_eval_task())

    return {
        "task_id": task_id,
        "status": row.status,
        "eval_dataset_ref": data.eval_dataset_ref,
        "requested_metrics": data.metrics,
        "message": "评估已启动",
    }


@router.get("/tasks/{task_id}/logs")
async def get_training_logs(
    request: Request,
    task_id: str,
    limit: int = Query(100, ge=1, le=1000),
    current_user: User = Depends(get_current_user),
):
    worker = _get_finetune_worker(request)
    logs = worker.get_logs(task_id, limit)
    return {"task_id": task_id, "logs": logs, "total": len(logs)}


@router.get("/tasks/{task_id}/checkpoints")
async def get_checkpoints(
    request: Request,
    task_id: str,
    current_user: User = Depends(get_current_user),
):
    worker = _get_finetune_worker(request)
    checkpoints = worker.get_checkpoints(task_id)
    return {"task_id": task_id, "checkpoints": checkpoints, "total": len(checkpoints)}


@router.get("/tasks/{task_id}/model-versions")
async def get_model_versions(
    request: Request,
    task_id: str,
    current_user: User = Depends(get_current_user),
):
    worker = _get_finetune_worker(request)
    versions = worker.get_model_versions(task_id)
    return {"task_id": task_id, "versions": versions, "total": len(versions)}


@router.get("/tasks/{task_id}/compare-versions")
async def compare_model_versions(
    request: Request,
    task_id: str,
    version_a: int = Query(..., ge=1),
    version_b: int = Query(..., ge=1),
    current_user: User = Depends(get_current_user),
):
    worker = _get_finetune_worker(request)
    comparison = worker.compare_model_versions(task_id, version_a, version_b)
    return comparison


@router.get("/tasks/{task_id}/progress")
async def get_training_progress(
    request: Request,
    task_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(FinetuneTaskTable).where(FinetuneTaskTable.id == task_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="微调任务不存在")

    worker = _get_finetune_worker(request)
    progress = worker.get_progress(task_id)

    return {
        "task_id": task_id,
        "db_status": row.status,
        "db_progress": row.progress,
        "realtime_progress": progress.to_dict() if progress else None,
    }


@router.get("/tasks/{task_id}/versions")
async def get_task_versions_api(
    request: Request,
    task_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(FinetuneTaskTable).where(FinetuneTaskTable.id == task_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="微调任务不存在")

    worker = _get_finetune_worker(request)
    versions = worker.get_model_versions(task_id)

    version_ids = [task_id]
    current_id = task_id
    for _ in range(50):
        child_result = await db.execute(
            select(FinetuneTaskTable).where(FinetuneTaskTable.parent_id == current_id)
        )
        child = child_result.scalar_one_or_none()
        if not child:
            break
        version_ids.append(child.id)
        current_id = child.id

    stmt = select(FinetuneTaskTable).where(FinetuneTaskTable.id.in_(version_ids))
    db_result = await db.execute(stmt.order_by(FinetuneTaskTable.version.asc()))
    db_versions = [_row_to_dict(r) for r in db_result.scalars().all()]

    return {
        "task_id": task_id,
        "model_versions": versions,
        "db_versions": db_versions,
        "total_model_versions": len(versions),
        "total_db_versions": len(db_versions),
    }


@router.post("/tasks/{task_id}/cancel-training")
async def cancel_training_task(
    request: Request,
    task_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(FinetuneTaskTable).where(FinetuneTaskTable.id == task_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="微调任务不存在")
    if row.status not in (FinetuneStatus.PENDING.value, FinetuneStatus.PREPARING.value, FinetuneStatus.TRAINING.value):
        raise HTTPException(status_code=400, detail="当前状态无法取消训练")

    worker = _get_finetune_worker(request)
    worker.cancel_training(task_id)

    async with db_write(db, operation="取消训练"):
        row.status = FinetuneStatus.FAILED.value
        row.error_message = "训练已被用户主动取消（状态标记为失败）"
        row.completed_at = datetime.now(timezone.utc)
    await db.refresh(row)

    progress = worker.get_progress(task_id)
    return {
        **_row_to_dict(row),
        "training_progress": progress.to_dict() if progress else None,
        "message": "训练已取消",
    }


@router.get("/models")
async def list_available_models(
    current_user: User = Depends(get_current_user),
):
    models = [
        {"id": "deepseek-7b-chat", "name": "DeepSeek-LLM-7B-Chat", "type": "chat", "provider": "deepseek", "params": "7B", "recommended": True, "description": "通用对话模型，适合黑话识别、威胁分类"},
        {"id": "deepseek-r1-7b", "name": "DeepSeek-R1-Distill-Qwen-7B", "type": "reasoning", "provider": "deepseek", "params": "7B", "recommended": True, "description": "推理模型蒸馏版，适合攻击链路分析"},
        {"id": "deepseek-coder-6.7b", "name": "DeepSeek-Coder-6.7B-Instruct", "type": "code", "provider": "deepseek", "params": "6.7B", "recommended": True, "description": "代码模型，适合恶意脚本分析、IOC提取"},
        {"id": "deepseek-chat", "name": "DeepSeek Chat (API)", "type": "chat", "provider": "deepseek", "params": "67B", "description": "DeepSeek API调用，无需本地部署"},
        {"id": "qwen-7b", "name": "Qwen 7B", "type": "chat", "provider": "alibaba", "params": "7B"},
        {"id": "chatglm3-6b", "name": "ChatGLM3 6B", "type": "chat", "provider": "zhipu", "params": "6B"},
        {"id": "baichuan2-7b", "name": "Baichuan2 7B", "type": "chat", "provider": "baichuan", "params": "7B"},
        {"id": "yi-6b", "name": "Yi 6B", "type": "chat", "provider": "01ai", "params": "6B"},
    ]
    return {"models": models, "total": len(models)}


@router.get("/deepseek-presets")
async def get_deepseek_presets(
    current_user: User = Depends(get_current_user),
):
    from app.core.finetune_engine import FinetuneWorker
    presets = FinetuneWorker.DEEPSEEK_MODEL_PRESETS
    return {
        "presets": {k: {**v, "preset_id": k} for k, v in presets.items()},
        "total": len(presets),
        "description": "DeepSeek大模型微调预设配置，基于DeepSeek-LLM/DeepSeek-R1/DeepSeek-Coder系列",
    }


@router.get("/methods")
async def list_finetune_methods(
    current_user: User = Depends(get_current_user),
):
    methods = [
        {
            "value": "lora",
            "label": "LoRA微调",
            "description": "低秩适配微调，参数高效，适合资源受限场景",
            "default_config": {
                "lora_r": 16,
                "lora_alpha": 32,
                "lora_dropout": 0.05,
                "lora_target_modules": ["q_proj", "v_proj"],
                "learning_rate": 2e-4,
                "epochs": 3,
                "batch_size": 4,
            },
        },
        {
            "value": "full",
            "label": "全参微调",
            "description": "全参数微调，效果最好但资源消耗大",
            "default_config": {
                "learning_rate": 2e-5,
                "epochs": 3,
                "batch_size": 2,
                "gradient_accumulation_steps": 8,
                "warmup_steps": 100,
            },
        },
    ]
    return {"methods": methods, "total": len(methods)}


@router.get("/versions/{task_id}")
async def get_task_versions(
    task_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    version_ids = [task_id]
    current_id = task_id
    for _ in range(50):
        result = await db.execute(
            select(FinetuneTaskTable).where(FinetuneTaskTable.parent_id == current_id)
        )
        child = result.scalar_one_or_none()
        if not child:
            break
        version_ids.append(child.id)
        current_id = child.id

    stmt = select(FinetuneTaskTable).where(FinetuneTaskTable.id.in_(version_ids))
    result = await db.execute(stmt.order_by(FinetuneTaskTable.version.asc()))
    rows = result.scalars().all()
    return {"versions": [_row_to_dict(r) for r in rows], "total": len(rows)}


@router.post("/tasks/{task_id}/generate-script")
async def generate_training_script(
    request: Request,
    task_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(FinetuneTaskTable).where(FinetuneTaskTable.id == task_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="微调任务不存在")

    worker = _get_finetune_worker(request)
    script = worker.generate_training_script(task_id)
    return {"task_id": task_id, "script": script}


@router.post("/tasks/{task_id}/estimate-resources")
async def estimate_resources(
    request: Request,
    task_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(FinetuneTaskTable).where(FinetuneTaskTable.id == task_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="微调任务不存在")

    config = {}
    try:
        config = json.loads(row.config_json) if row.config_json else {}
    except (json.JSONDecodeError, TypeError):
        config = {}

    dataset_size = config.get("dataset_size", 0)

    worker = _get_finetune_worker(request)
    estimation = worker.estimate_resources(row.method, config, dataset_size)
    return {"task_id": task_id, "estimation": estimation}


@router.get("/tasks/{task_id}/evaluation-report")
async def generate_evaluation_report(
    request: Request,
    task_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(FinetuneTaskTable).where(FinetuneTaskTable.id == task_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="微调任务不存在")

    worker = _get_finetune_worker(request)
    report = await worker.generate_evaluation_report(task_id)
    return {"task_id": task_id, "report": report}


@router.post("/tasks/{task_id}/export-model")
async def export_model(
    request: Request,
    task_id: str,
    data: ExportModelRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(FinetuneTaskTable).where(FinetuneTaskTable.id == task_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="微调任务不存在")

    worker = _get_finetune_worker(request)
    export_result = worker.export_model(task_id, data.export_format)
    return {"task_id": task_id, "export_format": data.export_format, "result": export_result}
