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
from app.core.pipeline_engine import PipelineExecutor, StepStatus
from app.core.validators import validate_domain_object
from app.db.database import get_db, async_session_factory
from app.db.tables import PreprocessTaskTable
from app.models.preprocess_task import TaskStatus, TaskType, PipelineStep, PreprocessTask

router = APIRouter(prefix="/data-pipeline", tags=["data-pipeline"])

_task_pipeline_map: Dict[str, str] = {}
_task_pipeline_lock = asyncio.Lock()
_MAX_PIPELINE_MAP_SIZE = 1000


class PipelineStepSchema(BaseModel):
    step_type: TaskType
    config: Dict[str, Any] = Field(default_factory=dict)
    order: int = 0


class PreprocessTaskCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=256)
    task_type: TaskType
    config_json: str = "{}"
    pipeline_steps: List[PipelineStepSchema] = Field(default_factory=list)
    input_data_ref: Optional[str] = None
    created_by: Optional[str] = None


class PipelineRunRequest(BaseModel):
    steps: List[PipelineStepSchema] = Field(default_factory=list)
    input_data_ref: Optional[str] = None
    input_data: Optional[List[Dict[str, Any]]] = None
    config_json: str = "{}"


class DataImportRequest(BaseModel):
    source: str = Field(..., pattern=r"^(inline|csv|json|jsonl)$")
    content: str = Field("", max_length=10_000_000)
    field_mapping: Optional[Dict[str, str]] = None


class BatchDeleteRequest(BaseModel):
    task_ids: List[str] = Field(..., min_length=1, max_length=100)


def _row_to_dict(row: PreprocessTaskTable) -> Dict:
    pipeline_steps = []
    try:
        pipeline_steps = json.loads(row.pipeline_steps_json) if row.pipeline_steps_json else []
    except (json.JSONDecodeError, TypeError):
        pipeline_steps = []
    return {
        "id": row.id,
        "name": row.name,
        "task_type": row.task_type,
        "status": row.status,
        "config_json": row.config_json,
        "pipeline_steps": pipeline_steps,
        "input_data_ref": row.input_data_ref,
        "output_data_ref": row.output_data_ref,
        "progress": row.progress,
        "error_message": row.error_message,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "started_at": row.started_at.isoformat() if row.started_at else None,
        "completed_at": row.completed_at.isoformat() if row.completed_at else None,
        "created_by": row.created_by,
    }


def _get_pipeline_executor(request: Request) -> PipelineExecutor:
    executor = getattr(request.app.state, "pipeline_executor", None)
    if executor is None:
        llm = getattr(request.app.state, "llm", None)
        executor = PipelineExecutor(llm_service=llm)
        request.app.state.pipeline_executor = executor
    return executor


@router.get("/tasks")
async def list_tasks(
    task_type: Optional[str] = None,
    status: Optional[str] = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = select(PreprocessTaskTable)
    count_stmt = select(func.count()).select_from(PreprocessTaskTable)

    if task_type:
        stmt = stmt.where(PreprocessTaskTable.task_type == task_type)
        count_stmt = count_stmt.where(PreprocessTaskTable.task_type == task_type)
    if status:
        stmt = stmt.where(PreprocessTaskTable.status == status)
        count_stmt = count_stmt.where(PreprocessTaskTable.status == status)

    total_result = await db.execute(count_stmt)
    total = total_result.scalar() or 0

    stmt = stmt.order_by(PreprocessTaskTable.created_at.desc()).offset(offset).limit(limit)
    result = await db.execute(stmt)
    rows = result.scalars().all()

    return {"items": [_row_to_dict(r) for r in rows], "total": total, "offset": offset, "limit": limit}


@router.get("/statistics")
async def get_statistics(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    type_counts_stmt = (
        select(PreprocessTaskTable.task_type, func.count().label("count"))
        .group_by(PreprocessTaskTable.task_type)
    )
    type_result = await db.execute(type_counts_stmt)
    by_type = {row.task_type: row.count for row in type_result.all()}

    status_counts_stmt = (
        select(PreprocessTaskTable.status, func.count().label("count"))
        .group_by(PreprocessTaskTable.status)
    )
    status_result = await db.execute(status_counts_stmt)
    by_status = {row.status: row.count for row in status_result.all()}

    total_stmt = select(func.count()).select_from(PreprocessTaskTable)
    total_result = await db.execute(total_stmt)
    total = total_result.scalar() or 0

    completed = by_status.get(TaskStatus.COMPLETED.value, 0)
    failed = by_status.get(TaskStatus.FAILED.value, 0)
    finished = completed + failed
    success_rate = round(completed / finished, 4) if finished > 0 else 0.0

    return {
        "total": total,
        "by_type": by_type,
        "by_status": by_status,
        "success_rate": success_rate,
    }


@router.post("/tasks", status_code=201)
async def create_task(
    data: PreprocessTaskCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    task_id = uuid.uuid4().hex
    validation = validate_domain_object("preprocess_task", data.model_dump())
    if not validation.is_valid:
        raise HTTPException(status_code=400, detail={"errors": validation.errors, "warnings": validation.warnings})
    pipeline_steps_json = json.dumps([s.model_dump() for s in data.pipeline_steps], ensure_ascii=False)

    row = PreprocessTaskTable(
        id=task_id,
        name=data.name,
        task_type=data.task_type.value,
        status=TaskStatus.PENDING.value,
        config_json=data.config_json,
        pipeline_steps_json=pipeline_steps_json,
        input_data_ref=data.input_data_ref,
        created_by=current_user.username,
    )
    async with db_write(db, operation="创建预处理任务"):
        db.add(row)
    await db.refresh(row)
    return _row_to_dict(row)


@router.get("/tasks/{task_id}")
async def get_task(
    task_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(PreprocessTaskTable).where(PreprocessTaskTable.id == task_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Task not found")
    return _row_to_dict(row)


@router.post("/tasks/{task_id}/execute")
async def execute_task(
    request: Request,
    task_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(PreprocessTaskTable).where(PreprocessTaskTable.id == task_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Task not found")

    executor = _get_pipeline_executor(request)

    steps = []
    try:
        steps = json.loads(row.pipeline_steps_json) if row.pipeline_steps_json else []
    except (json.JSONDecodeError, TypeError):
        steps = []

    config = {}
    try:
        config = json.loads(row.config_json) if row.config_json else {}
    except (json.JSONDecodeError, TypeError):
        config = {}

    input_data = config.get("input_data", [])

    async with db_write(db, operation="执行预处理任务"):
        row.status = TaskStatus.RUNNING.value
        row.started_at = datetime.now(timezone.utc)

    async def _run_and_update():
        try:
            execution = await executor.execute_pipeline(
                task_id=task_id,
                steps=steps,
                input_data=input_data,
                config=config,
            )

            if execution is None:
                raise RuntimeError(f"Pipeline execution returned None for task {task_id}")

            _task_pipeline_map[task_id] = execution.pipeline_id

            async with async_session_factory() as update_session:
                update_result = await update_session.execute(
                    select(PreprocessTaskTable).where(PreprocessTaskTable.id == task_id)
                )
                update_row = update_result.scalar_one_or_none()
                if update_row:
                    if execution.status == StepStatus.COMPLETED:
                        update_row.status = TaskStatus.COMPLETED.value
                        update_row.progress = 1.0
                        output_ref = f"pipeline_output/{task_id}"
                        update_row.output_data_ref = output_ref
                    elif execution.status == StepStatus.FAILED:
                        update_row.status = TaskStatus.FAILED.value
                        update_row.error_message = execution.error_message
                    else:
                        update_row.status = TaskStatus.RUNNING.value
                    update_row.progress = execution.progress
                    update_row.completed_at = datetime.now(timezone.utc)
                    await update_session.commit()
        except Exception as exc:
            logger.error(f"Pipeline execution failed for task {task_id}: {exc}")
            try:
                async with async_session_factory() as err_session:
                    err_result = await err_session.execute(
                        select(PreprocessTaskTable).where(PreprocessTaskTable.id == task_id)
                    )
                    err_row = err_result.scalar_one_or_none()
                    if err_row:
                        err_row.status = TaskStatus.FAILED.value
                        err_row.error_message = "任务执行失败，请查看日志"
                        err_row.completed_at = datetime.now(timezone.utc)
                        await err_session.commit()
            except Exception:
                logger.error(f"Failed to update error status for task {task_id}")

    asyncio.create_task(_run_and_update())

    return {
        **_row_to_dict(row),
        "message": "操作已启动",
    }


@router.post("/tasks/{task_id}/cancel")
async def cancel_task(
    request: Request,
    task_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(PreprocessTaskTable).where(PreprocessTaskTable.id == task_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="任务不存在")

    executor = _get_pipeline_executor(request)
    pipeline_id = _task_pipeline_map.get(task_id)
    if pipeline_id:
        executor.cancel_execution(pipeline_id)

    async with db_write(db, operation="取消预处理任务"):
        row.status = TaskStatus.CANCELLED.value
    await db.refresh(row)
    return _row_to_dict(row)


@router.delete("/tasks/batch")
async def batch_delete_tasks(
    data: BatchDeleteRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = select(PreprocessTaskTable).where(PreprocessTaskTable.id.in_(data.task_ids))
    result = await db.execute(stmt)
    rows = result.scalars().all()

    found_ids = {row.id for row in rows}
    missing_ids = set(data.task_ids) - found_ids

    async with db_write(db, operation="批量删除任务"):
        for row in rows:
            await db.delete(row)

    return {
        "deleted_count": len(rows),
        "missing_ids": list(missing_ids),
    }


@router.delete("/tasks/{task_id}", status_code=204)
async def delete_task(
    task_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(PreprocessTaskTable).where(PreprocessTaskTable.id == task_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="任务不存在")
    async with db_write(db, operation="删除预处理任务"):
        await db.delete(row)


@router.get("/tasks/{task_id}/execution")
async def get_task_execution(
    task_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(PreprocessTaskTable).where(PreprocessTaskTable.id == task_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Task not found")

    steps = []
    if row.pipeline_steps_json:
        try:
            steps = json.loads(row.pipeline_steps_json)
        except (json.JSONDecodeError, TypeError):
            steps = []

    executor = _get_pipeline_executor(request)
    pipeline_id = _task_pipeline_map.get(task_id)
    execution = executor.get_execution(pipeline_id) if pipeline_id else None

    response = {
        "task_id": row.id,
        "task_name": row.name,
        "task_status": row.status,
        "progress": row.progress,
        "error_message": row.error_message,
        "started_at": row.started_at.isoformat() if row.started_at else None,
        "completed_at": row.completed_at.isoformat() if row.completed_at else None,
        "total_steps": len(steps),
        "pipeline_steps": steps,
    }

    if execution:
        response["execution"] = execution.to_dict()
    else:
        response["execution"] = None

    return response


@router.post("/tasks/{task_id}/cancel-execution")
async def cancel_task_execution(
    task_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(PreprocessTaskTable).where(PreprocessTaskTable.id == task_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="任务不存在")

    executor = _get_pipeline_executor(request)
    pipeline_id = _task_pipeline_map.get(task_id)
    cancelled = False
    if pipeline_id:
        cancelled = executor.cancel_execution(pipeline_id)

    async with db_write(db, operation="取消任务执行"):
        row.status = TaskStatus.CANCELLED.value
        row.completed_at = datetime.now(timezone.utc)
    await db.refresh(row)

    return {
        **_row_to_dict(row),
        "execution_cancelled": cancelled,
    }


@router.post("/pipeline/run", status_code=201)
async def run_pipeline(
    request: Request,
    data: PipelineRunRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    pipeline_id = uuid.uuid4().hex
    if not data.steps:
        raise HTTPException(status_code=400, detail="流水线步骤不能为空")
    _validate_step_dependencies([s.model_dump() for s in data.steps])
    steps_json = json.dumps([s.model_dump() for s in data.steps], ensure_ascii=False)

    row = PreprocessTaskTable(
        id=pipeline_id,
        name=f"流水线-{pipeline_id[:8]}",
        task_type=TaskType.FORMAT_CONVERT.value,
        status=TaskStatus.RUNNING.value,
        config_json=data.config_json,
        pipeline_steps_json=steps_json,
        input_data_ref=data.input_data_ref,
        started_at=datetime.now(timezone.utc),
        created_by=current_user.username if hasattr(current_user, "username") else "system",
    )
    async with db_write(db, operation="运行流水线"):
        db.add(row)
    await db.refresh(row)

    executor = _get_pipeline_executor(request)

    steps = [s.model_dump() for s in data.steps]
    config = {}
    try:
        config = json.loads(data.config_json) if data.config_json else {}
    except (json.JSONDecodeError, TypeError):
        config = {}

    input_data = data.input_data or config.get("input_data", [])

    async def _run_and_update():
        try:
            execution = await executor.execute_pipeline(
                task_id=pipeline_id,
                steps=steps,
                input_data=input_data,
                config=config,
            )

            if execution is None:
                raise RuntimeError(f"Pipeline execution returned None for pipeline {pipeline_id}")

            _task_pipeline_map[pipeline_id] = execution.pipeline_id
            if len(_task_pipeline_map) > _MAX_PIPELINE_MAP_SIZE:
                stale_keys = list(_task_pipeline_map.keys())[:_MAX_PIPELINE_MAP_SIZE // 2]
                for k in stale_keys:
                    del _task_pipeline_map[k]

            async with async_session_factory() as update_session:
                update_result = await update_session.execute(
                    select(PreprocessTaskTable).where(PreprocessTaskTable.id == pipeline_id)
                )
                update_row = update_result.scalar_one_or_none()
                if update_row:
                    if execution.status == StepStatus.COMPLETED:
                        update_row.status = TaskStatus.COMPLETED.value
                        update_row.progress = 1.0
                        update_row.output_data_ref = f"pipeline_output/{pipeline_id}"
                    elif execution.status == StepStatus.FAILED:
                        update_row.status = TaskStatus.FAILED.value
                        update_row.error_message = execution.error_message
                    update_row.progress = execution.progress
                    update_row.completed_at = datetime.now(timezone.utc)
                    await update_session.commit()
        except Exception as exc:
            logger.error(f"Pipeline run failed for {pipeline_id}: {exc}")
            try:
                async with async_session_factory() as err_session:
                    err_result = await err_session.execute(
                        select(PreprocessTaskTable).where(PreprocessTaskTable.id == pipeline_id)
                    )
                    err_row = err_result.scalar_one_or_none()
                    if err_row:
                        err_row.status = TaskStatus.FAILED.value
                        err_row.error_message = "流水线执行失败，请查看日志"
                        err_row.completed_at = datetime.now(timezone.utc)
                        await err_session.commit()
            except Exception:
                logger.error(f"Failed to update error status for pipeline {pipeline_id}")

    asyncio.create_task(_run_and_update())

    return {**_row_to_dict(row), "message": "操作已启动"}


@router.get("/pipeline/status/{pipeline_id}")
async def get_pipeline_status(
    request: Request,
    pipeline_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(PreprocessTaskTable).where(PreprocessTaskTable.id == pipeline_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Pipeline not found")

    steps = []
    if row.pipeline_steps_json:
        try:
            steps = json.loads(row.pipeline_steps_json)
        except (json.JSONDecodeError, TypeError):
            steps = []

    executor = _get_pipeline_executor(request)
    exec_pipeline_id = _task_pipeline_map.get(pipeline_id)
    execution = executor.get_execution(exec_pipeline_id) if exec_pipeline_id else None

    step_details = []
    if execution:
        exec_data = execution.to_dict()
        exec_step_results = exec_data.get("step_results", [])
        for i, s in enumerate(steps):
            step_name = s.get("step_type", s.get("name", ""))
            if i < len(exec_step_results):
                step_details.append({"name": step_name, "status": exec_step_results[i].get("status", "pending")})
            else:
                step_details.append({"name": step_name, "status": "pending"})
    else:
        task_status = row.status
        progress = row.progress or 0.0
        if steps:
            current_step_idx = min(int(progress * len(steps)), len(steps) - 1)
        else:
            current_step_idx = 0

        for i, s in enumerate(steps):
            step_name = s.get("step_type", s.get("name", ""))
            if task_status == TaskStatus.COMPLETED.value:
                step_details.append({"name": step_name, "status": "completed"})
            elif task_status == TaskStatus.FAILED.value:
                if i < current_step_idx:
                    step_details.append({"name": step_name, "status": "completed"})
                elif i == current_step_idx:
                    step_details.append({"name": step_name, "status": "failed"})
                else:
                    step_details.append({"name": step_name, "status": "pending"})
            elif task_status == TaskStatus.RUNNING.value:
                if i < current_step_idx:
                    step_details.append({"name": step_name, "status": "completed"})
                elif i == current_step_idx:
                    step_details.append({"name": step_name, "status": "running"})
                else:
                    step_details.append({"name": step_name, "status": "pending"})
            else:
                step_details.append({"name": step_name, "status": "pending"})

    return {
        "pipeline_id": row.id,
        "status": row.status,
        "progress": row.progress,
        "total_steps": len(steps),
        "step_details": step_details,
        "error_message": row.error_message,
        "started_at": row.started_at.isoformat() if row.started_at else None,
        "completed_at": row.completed_at.isoformat() if row.completed_at else None,
    }


@router.post("/import")
async def import_data(
    request: Request,
    data: DataImportRequest,
    current_user: User = Depends(get_current_user),
):
    if data.source == "json":
        try:
            json.loads(data.content)
        except (json.JSONDecodeError, TypeError) as e:
            raise HTTPException(status_code=400, detail="JSON格式错误，请检查输入数据")

    executor = _get_pipeline_executor(request)
    imported = await executor.execute_import(
        config={
            "source": data.source,
            "content": data.content,
            "field_mapping": data.field_mapping,
        },
        current_data=[],
    )

    return {
        "imported_count": len(imported),
        "source": data.source,
        "preview": imported[:5] if imported else [],
    }


@router.get("/step-types")
async def list_step_types(
    current_user: User = Depends(get_current_user),
):
    step_types = [
        {
            "value": "import",
            "label": "情报导入",
            "description": "从暗网/论坛/社交平台等情报源导入原始数据",
            "config_params": ["source", "content", "field_mapping"],
        },
        {
            "value": "clean",
            "label": "情报清洗",
            "description": "黑话解码、噪声过滤、MinHash去重、敏感信息脱敏",
            "config_params": ["deduplicate", "clean_text", "min_length", "decode_blacktalk"],
        },
        {
            "value": "label",
            "label": "威胁标注",
            "description": "高危意图分类标注（诈骗/洗钱/钓鱼/勒索等），支持规则和LLM辅助",
            "config_params": ["annotation_type", "categories", "auto_annotate"],
        },
        {
            "value": "augment",
            "label": "情报增强",
            "description": "同义改写、回译、实体替换等增强方法，扩充训练样本",
            "config_params": ["method", "count", "max_items"],
        },
        {
            "value": "format_convert",
            "label": "格式转换",
            "description": "转换为JSONL/CSV/Alpaca/STIX等情报或训练格式",
            "config_params": ["target_format", "field_mapping"],
        },
    ]
    return {"step_types": step_types, "total": len(step_types)}


_PIPELINE_TEMPLATES = {
    "threat_intel_full": {
        "id": "threat_intel_full",
        "name": "黑灰产情报全量分析流水线",
        "description": "情报导入 → 情报清洗 → 威胁标注 → 情报增强 → 格式转换",
        "steps": [
            {"step_type": "import", "config": {}, "order": 0},
            {"step_type": "clean", "config": {"decode_blacktalk": True}, "order": 1},
            {"step_type": "label", "config": {"categories": ["诈骗", "洗钱", "钓鱼", "勒索", "赌博", "黑客"]}, "order": 2},
            {"step_type": "augment", "config": {}, "order": 3},
            {"step_type": "format_convert", "config": {}, "order": 4},
        ],
    },
    "quick_triage": {
        "id": "quick_triage",
        "name": "快速情报初筛流水线",
        "description": "情报导入 → 情报清洗 → 格式转换（快速筛选与格式化）",
        "steps": [
            {"step_type": "import", "config": {}, "order": 0},
            {"step_type": "clean", "config": {"decode_blacktalk": True}, "order": 1},
            {"step_type": "format_convert", "config": {}, "order": 2},
        ],
    },
    "finetune_data": {
        "id": "finetune_data",
        "name": "微调训练数据流水线",
        "description": "情报导入 → 情报清洗 → 威胁标注 → 情报增强 → Alpaca格式转换",
        "steps": [
            {"step_type": "import", "config": {}, "order": 0},
            {"step_type": "clean", "config": {"decode_blacktalk": True}, "order": 1},
            {"step_type": "label", "config": {"categories": ["诈骗", "洗钱", "钓鱼", "勒索", "赌博", "黑客"]}, "order": 2},
            {"step_type": "augment", "config": {}, "order": 3},
            {"step_type": "format_convert", "config": {"target_format": "alpaca"}, "order": 4},
        ],
    },
    "ioc_extraction": {
        "id": "ioc_extraction",
        "name": "IoC指标提取流水线",
        "description": "情报导入 → 情报清洗 → 威胁标注 → STIX格式转换",
        "steps": [
            {"step_type": "import", "config": {}, "order": 0},
            {"step_type": "clean", "config": {"decode_blacktalk": True}, "order": 1},
            {"step_type": "label", "config": {"annotation_type": "ioc_extraction"}, "order": 2},
            {"step_type": "format_convert", "config": {"target_format": "stix"}, "order": 3},
        ],
    },
}

_STEP_ORDER = {"import": 0, "clean": 1, "label": 2, "augment": 3, "format_convert": 4}


def _validate_step_dependencies(steps: List[Dict[str, Any]]) -> None:
    step_types = [s.get("step_type", "") for s in steps]
    if "label" in step_types and "clean" not in step_types:
        raise HTTPException(status_code=400, detail="标注步骤依赖清洗步骤，请先添加清洗步骤")
    if "augment" in step_types and "label" not in step_types:
        raise HTTPException(status_code=400, detail="增强步骤依赖标注步骤，请先添加标注步骤")
    if "import" in step_types and step_types.index("import") != 0:
        raise HTTPException(status_code=400, detail="导入步骤必须是第一个步骤")
    for i in range(len(step_types) - 1):
        curr_rank = _STEP_ORDER.get(step_types[i], -1)
        next_rank = _STEP_ORDER.get(step_types[i + 1], -1)
        if curr_rank >= 0 and next_rank >= 0 and curr_rank > next_rank:
            raise HTTPException(
                status_code=400,
                detail=f"步骤顺序不合理: '{step_types[i]}' 不应在 '{step_types[i + 1]}' 之前",
            )


@router.get("/pipeline/templates")
async def list_pipeline_templates(
    current_user: User = Depends(get_current_user),
):
    templates = list(_PIPELINE_TEMPLATES.values())
    return {"templates": templates, "total": len(templates)}


class TemplateRunRequest(BaseModel):
    input_data_ref: Optional[str] = None
    input_data: Optional[List[Dict[str, Any]]] = None
    config_json: str = "{}"


@router.post("/pipeline/templates/{template_id}/run", status_code=201)
async def run_pipeline_template(
    request: Request,
    template_id: str,
    data: TemplateRunRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    template = _PIPELINE_TEMPLATES.get(template_id)
    if not template:
        raise HTTPException(status_code=404, detail=f"流水线模板'{template_id}'不存在")

    pipeline_id = uuid.uuid4().hex
    steps_json = json.dumps(template["steps"], ensure_ascii=False)

    row = PreprocessTaskTable(
        id=pipeline_id,
        name=template["name"],
        task_type=TaskType.FORMAT_CONVERT.value,
        status=TaskStatus.RUNNING.value,
        config_json=data.config_json,
        pipeline_steps_json=steps_json,
        input_data_ref=data.input_data_ref,
        started_at=datetime.now(timezone.utc),
        created_by=current_user.username if hasattr(current_user, "username") else "system",
    )
    async with db_write(db, operation="运行流水线模板"):
        db.add(row)
    await db.refresh(row)

    executor = _get_pipeline_executor(request)

    config = {}
    try:
        config = json.loads(data.config_json) if data.config_json else {}
    except (json.JSONDecodeError, TypeError):
        config = {}

    input_data = data.input_data or config.get("input_data", [])

    async def _run_and_update():
        try:
            execution = await executor.execute_pipeline(
                task_id=pipeline_id,
                steps=template["steps"],
                input_data=input_data,
                config=config,
            )

            if execution is None:
                raise RuntimeError(f"Pipeline execution returned None for template pipeline {pipeline_id}")

            _task_pipeline_map[pipeline_id] = execution.pipeline_id

            async with async_session_factory() as update_session:
                update_result = await update_session.execute(
                    select(PreprocessTaskTable).where(PreprocessTaskTable.id == pipeline_id)
                )
                update_row = update_result.scalar_one_or_none()
                if update_row:
                    if execution.status == StepStatus.COMPLETED:
                        update_row.status = TaskStatus.COMPLETED.value
                        update_row.progress = 1.0
                        update_row.output_data_ref = f"pipeline_output/{pipeline_id}"
                    elif execution.status == StepStatus.FAILED:
                        update_row.status = TaskStatus.FAILED.value
                        update_row.error_message = execution.error_message
                    update_row.progress = execution.progress
                    update_row.completed_at = datetime.now(timezone.utc)
                    await update_session.commit()
        except Exception as exc:
            logger.error(f"Template pipeline run failed for {pipeline_id}: {exc}")
            try:
                async with async_session_factory() as err_session:
                    err_result = await err_session.execute(
                        select(PreprocessTaskTable).where(PreprocessTaskTable.id == pipeline_id)
                    )
                    err_row = err_result.scalar_one_or_none()
                    if err_row:
                        err_row.status = TaskStatus.FAILED.value
                        err_row.error_message = "模板流水线执行失败，请查看日志"
                        err_row.completed_at = datetime.now(timezone.utc)
                        await err_session.commit()
            except Exception:
                logger.error(f"Failed to update error status for template pipeline {pipeline_id}")

    asyncio.create_task(_run_and_update())

    return {**_row_to_dict(row), "template_id": template_id, "message": "操作已启动"}

