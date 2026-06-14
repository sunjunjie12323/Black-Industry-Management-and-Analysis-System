from typing import List, Optional, Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from app.core.auth import User, get_current_user, require_role, Role
from app.core.exceptions import NotFoundException, ValidationException
from app.core.task_queue import TaskStatus, task_queue

router = APIRouter(prefix="/tasks", tags=["tasks"])


class TaskResponse(BaseModel):
    id: str
    type: str
    status: str
    params: dict
    result: Optional[Any] = None
    error: Optional[str] = None
    progress: float
    created_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None

    class Config:
        arbitrary_types_allowed = True


class TaskListResponse(BaseModel):
    items: List[TaskResponse]
    total: int
    offset: int
    limit: int


def _safe_serialize(obj: Any) -> Any:
    if obj is None:
        return None
    if isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, dict):
        return {str(k): _safe_serialize(v) for k, v in obj.items() if not k.startswith("_")}
    if isinstance(obj, (list, tuple)):
        return [_safe_serialize(item) for item in obj]
    if hasattr(obj, "model_dump"):
        return _safe_serialize(obj.model_dump())
    if hasattr(obj, "__dict__"):
        return _safe_serialize({k: v for k, v in obj.__dict__.items() if not k.startswith("_")})
    return str(obj)


def _task_to_response(task) -> TaskResponse:
    return TaskResponse(
        id=task.id,
        type=task.type,
        status=task.status.value if isinstance(task.status, TaskStatus) else task.status,
        params=_safe_serialize(task.params) if task.params else {},
        result=_safe_serialize(task.result) if task.result else None,
        error=task.error,
        progress=task.progress,
        created_at=task.created_at.isoformat() if task.created_at else "",
        started_at=task.started_at.isoformat() if task.started_at else None,
        completed_at=task.completed_at.isoformat() if task.completed_at else None,
    )


@router.get("", response_model=TaskListResponse)
async def list_tasks(
    status: Optional[str] = Query(None),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(get_current_user),
):
    task_status = None
    if status:
        try:
            task_status = TaskStatus(status)
        except ValueError:
            raise ValidationException(
                detail=f"Invalid status: {status}. Valid values: {[s.value for s in TaskStatus]}"
            )
    tasks = task_queue.list_tasks(status=task_status, limit=limit, offset=offset)
    all_tasks = task_queue.list_tasks(status=task_status, limit=10000, offset=0)
    return TaskListResponse(
        items=[_task_to_response(t) for t in tasks],
        total=len(all_tasks),
        offset=offset,
        limit=limit,
    )


@router.get("/{task_id}", response_model=TaskResponse)
async def get_task(
    task_id: str,
    current_user: User = Depends(get_current_user),
):
    task = task_queue.get_task(task_id)
    if task is None:
        raise NotFoundException(detail=f"Task {task_id} not found")
    return _task_to_response(task)


@router.post("/{task_id}/cancel")
async def cancel_task(
    task_id: str,
    current_user: User = Depends(get_current_user),
):
    task = task_queue.get_task(task_id)
    if task is None:
        raise NotFoundException(detail=f"Task {task_id} not found")
    cancelled = await task_queue.cancel_task(task_id)
    if not cancelled:
        raise ValidationException(
            detail=f"Task {task_id} cannot be cancelled (current status: {task.status.value if isinstance(task.status, TaskStatus) else task.status})"
        )
    return {"task_id": task_id, "status": "cancelled"}


@router.get("/{task_id}/result")
async def get_task_result(
    task_id: str,
    current_user: User = Depends(get_current_user),
):
    task = task_queue.get_task(task_id)
    if task is None:
        raise NotFoundException(detail=f"Task {task_id} not found")
    if task.status != TaskStatus.COMPLETED:
        raise ValidationException(
            detail=f"Task {task_id} is not completed (current status: {task.status.value if isinstance(task.status, TaskStatus) else task.status})"
        )
    return {
        "task_id": task_id,
        "type": task.type,
        "result": task.result,
        "completed_at": task.completed_at.isoformat() if task.completed_at else None,
    }
