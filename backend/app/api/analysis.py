import asyncio
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Literal, Optional

from fastapi import APIRouter, Depends, Query, Request
from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import User, get_current_user, require_role, Role
from app.core.exceptions import RateLimitExceededException
from app.db.analysis_crud import AnalysisResultCRUD
from app.db.database import get_db, async_session_factory
from app.schemas.analysis import (
    AnalysisResultListResponse,
    AnalysisResultResponse,
    AnalysisStatsResponse,
    AnalysisTypeStatsResponse,
    DeepAnalysisRequest,
    DeepAnalysisResponse,
    SchedulerStatusResponse,
    TriggerAnalysisRequest,
    TriggerAnalysisResponse,
)

router = APIRouter(prefix="/analysis", tags=["analysis"])

_pending_tasks: Dict[str, Dict[str, Any]] = {}
_pending_tasks_lock = asyncio.Lock()
_MAX_PENDING_TASKS = 1000
_TASK_TTL_SECONDS = 3600
_MAX_CONCURRENT_TRIGGERS = 5
_active_triggers = 0


async def _add_pending_task(task_id: str, task_info: Dict[str, Any]):
    async with _pending_tasks_lock:
        _cleanup_expired_tasks_unlocked()
        if len(_pending_tasks) >= _MAX_PENDING_TASKS:
            raise RateLimitExceededException(detail="待处理任务过多，请稍后重试")
        _pending_tasks[task_id] = task_info


async def _update_pending_task(task_id: str, task_info: Dict[str, Any]):
    async with _pending_tasks_lock:
        _pending_tasks[task_id] = task_info


async def _get_pending_task(task_id: str) -> Optional[Dict[str, Any]]:
    async with _pending_tasks_lock:
        return _pending_tasks.get(task_id)


def _cleanup_expired_tasks_unlocked():
    now = datetime.now(timezone.utc)
    expired = []
    for tid, t in _pending_tasks.items():
        started = t.get("started_at")
        if started:
            try:
                started_dt = datetime.fromisoformat(started)
                if (now - started_dt).total_seconds() > _TASK_TTL_SECONDS:
                    expired.append(tid)
            except (ValueError, TypeError):
                expired.append(tid)
    for tid in expired:
        del _pending_tasks[tid]


def _get_scheduler(request: Request):
    return getattr(request.app.state, "analysis_scheduler", None)


def _get_engine(request: Request):
    return getattr(request.app.state, "analysis_engine", None)


@router.get("/results", response_model=AnalysisResultListResponse)
async def get_results(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0, le=10000),
    analysis_type: Optional[str] = Query(None, max_length=100),
    status: Optional[str] = Query(None, max_length=100),
    target_id: Optional[str] = Query(None, max_length=100),
    sort_by: Literal["analyzed_at", "created_at", "confidence"] = Query("analyzed_at"),
    sort_order: Literal["asc", "desc"] = Query("desc"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    rows, total = await AnalysisResultCRUD.list_all(
        db, limit=limit, offset=offset,
        analysis_type=analysis_type, status=status,
        target_id=target_id, sort_by=sort_by, sort_order=sort_order,
    )
    items = [AnalysisResultResponse(**AnalysisResultCRUD.to_response_dict(r)) for r in rows]
    return AnalysisResultListResponse(items=items, total=total, limit=limit, offset=offset)


@router.get("/results/{result_id}", response_model=AnalysisResultResponse)
async def get_result_detail(result_id: str, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    row = await AnalysisResultCRUD.get_by_id(db, result_id)
    if not row:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="分析结果未找到")
    return AnalysisResultResponse(**AnalysisResultCRUD.to_response_dict(row))


@router.get("/stats", response_model=AnalysisStatsResponse)
async def get_stats(request: Request, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    stats = await AnalysisResultCRUD.get_stats(db)
    scheduler = _get_scheduler(request)
    scheduler_status = None
    if scheduler:
        try:
            scheduler_status = scheduler.get_status()
        except Exception as exc:
            logger.debug(f"Failed to get scheduler status: {exc}")
    return AnalysisStatsResponse(
        total_count=stats["total_count"],
        by_type=stats["by_type"],
        by_status=stats["by_status"],
        avg_confidence=stats["avg_confidence"],
        scheduler_status=scheduler_status,
    )


@router.get("/stats/{analysis_type}", response_model=AnalysisTypeStatsResponse)
async def get_type_stats(analysis_type: str, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    stats = await AnalysisResultCRUD.get_type_stats(db, analysis_type)
    return AnalysisTypeStatsResponse(**stats)


async def _safe_run_task(coro, task_id, task_type):
    global _active_triggers
    try:
        await coro
    except Exception as exc:
        await _update_pending_task(task_id, {"status": "failed", "type": task_type, "error": "任务执行失败"})
        logger.error(f"Task {task_id} ({task_type}) failed: {exc}")
    finally:
        _active_triggers -= 1


@router.post("/trigger", response_model=TriggerAnalysisResponse)
async def trigger_analysis(
    body: TriggerAnalysisRequest,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    global _active_triggers
    if _active_triggers >= _MAX_CONCURRENT_TRIGGERS:
        raise RateLimitExceededException(detail="当前分析任务过多，请稍后重试")

    task_id = uuid.uuid4().hex[:16]
    engine = _get_engine(request)
    scheduler = _get_scheduler(request)

    if body.deep_analysis:
        _active_triggers += 1
        await _add_pending_task(task_id, {"status": "running", "type": "deep_analysis", "started_at": datetime.now(timezone.utc).isoformat()})

        async def _run_deep():
            try:
                from app.engine.deep_analysis import DeepAnalysisService
                from app.engine.web_search import web_search_service
                deep_service = DeepAnalysisService(
                    llm_client=request.app.state.llm,
                    web_search_service=web_search_service,
                    db_session_factory=async_session_factory,
                    knowledge_graph=request.app.state.knowledge_graph,
                )
                result = await deep_service.deep_analyze(body.deep_analysis)
                await _update_pending_task(task_id, {"status": "completed", "type": "deep_analysis", "result": result.model_dump()})
            except Exception as exc:
                await _update_pending_task(task_id, {"status": "failed", "type": "deep_analysis", "error": "深度分析执行失败"})
                logger.error(f"Deep analysis task {task_id} failed: {exc}")

        asyncio.create_task(_safe_run_task(_run_deep(), task_id, "deep_analysis"))
        return TriggerAnalysisResponse(task_id=task_id, status="running", message="深度分析已触发")

    if scheduler:
        _active_triggers += 1
        await _add_pending_task(task_id, {"status": "running", "type": "full_cycle", "started_at": datetime.now(timezone.utc).isoformat()})

        async def _run_cycle():
            try:
                result = await scheduler.trigger_now()
                await _update_pending_task(task_id, {"status": "completed", "type": "full_cycle", "result": result})
            except Exception as exc:
                await _update_pending_task(task_id, {"status": "failed", "type": "full_cycle", "error": "全量分析执行失败"})

        asyncio.create_task(_safe_run_task(_run_cycle(), task_id, "full_cycle"))
        return TriggerAnalysisResponse(task_id=task_id, status="running", message="全量分析已触发")

    if body.analysis_type and body.target_id and engine:
        _active_triggers += 1
        await _add_pending_task(task_id, {"status": "running", "type": "single", "started_at": datetime.now(timezone.utc).isoformat()})

        async def _run_single():
            try:
                result = await engine.run_single_analysis(body.target_id, "intelligence", body.analysis_type)
                await _update_pending_task(task_id, {"status": "completed", "type": "single", "result": result})
            except Exception as exc:
                await _update_pending_task(task_id, {"status": "failed", "type": "single", "error": "分析执行失败"})

        asyncio.create_task(_safe_run_task(_run_single(), task_id, "single"))
        return TriggerAnalysisResponse(task_id=task_id, status="running", message=f"{body.analysis_type}分析已触发")

    return TriggerAnalysisResponse(task_id=task_id, status="failed", message="缺少必要参数")


@router.get("/tasks/{task_id}")
async def get_task_status(task_id: str, current_user: User = Depends(get_current_user)):
    task = await _get_pending_task(task_id)
    if not task:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="任务未找到")
    return task


@router.get("/scheduler/status", response_model=SchedulerStatusResponse)
async def get_scheduler_status(request: Request, current_user: User = Depends(get_current_user)):
    scheduler = _get_scheduler(request)
    if not scheduler:
        return SchedulerStatusResponse()
    status = scheduler.get_status()
    return SchedulerStatusResponse(
        is_running=status.get("is_running", False),
        last_run_time=status.get("last_run_time"),
        next_run_time=status.get("next_run_time"),
        total_runs=status.get("total_runs", 0),
        last_run_duration_seconds=status.get("last_run_duration_seconds"),
        last_run_items_processed=status.get("last_run_items_processed", 0),
        enabled_analysis_types=status.get("enabled_analysis_types", []),
        schedule_interval_hours=status.get("schedule_interval_hours", 6.0),
    )
