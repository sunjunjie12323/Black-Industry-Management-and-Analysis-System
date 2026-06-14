from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from loguru import logger
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import User, get_current_user, require_role, Role
from app.db.crud import PIRCRUD
from app.db.database import get_db
from app.models.intelligence import IntelligenceSource
from app.models.pir import PIR, PIRPriority, PIRStatus, PIRTask, PIRTaskStatus

router = APIRouter(prefix="/pirs", tags=["pirs"])


class PIRCreateRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=256)
    description: str = Field(default="", max_length=2000)
    priority: PIRPriority = PIRPriority.MEDIUM
    keywords: List[str] = Field(default_factory=list)
    target_sources: List[str] = Field(default_factory=list)


class PIRUpdateRequest(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    priority: Optional[PIRPriority] = None
    status: Optional[PIRStatus] = None
    keywords: Optional[List[str]] = None
    target_sources: Optional[List[str]] = None
    results_summary: Optional[str] = None


class PIRTaskCreateRequest(BaseModel):
    agent_type: str = Field(..., min_length=1)
    task_description: str = Field(default="")


class PIRTaskUpdateRequest(BaseModel):
    status: Optional[PIRTaskStatus] = None
    result: Optional[dict] = None


@router.post("", status_code=201)
async def create_pir(
    data: PIRCreateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    crud = PIRCRUD(db)
    target_sources = []
    for s in data.target_sources:
        try:
            target_sources.append(IntelligenceSource(s))
        except ValueError:
            pass
    pir = PIR(
        title=data.title,
        description=data.description,
        priority=data.priority,
        keywords=data.keywords,
        target_sources=target_sources,
    )
    result = await crud.create_pir(pir)
    await db.commit()
    return result.model_dump()


@router.get("")
async def list_pirs(
    status: PIRStatus | None = None,
    priority: PIRPriority | None = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    crud = PIRCRUD(db)
    items, total = await crud.list_pirs(status=status, priority=priority, offset=offset, limit=limit)
    result_items = []
    for item in items:
        pir_dict = item.model_dump()
        pir_dict["fulfillment_score"] = 0
        pir_dict["tasks"] = []
        pir_dict["generated_reports"] = []
        pir_dict["target_entities"] = []
        if pir_dict.get("status") == "fulfilled":
            pir_dict["fulfillment_score"] = 100
        result_items.append(pir_dict)
    return {"items": result_items, "total": total, "offset": offset, "limit": limit}


@router.get("/active")
async def get_active_pirs_alias(
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    crud = PIRCRUD(db)
    items, total = await crud.list_pirs(status=PIRStatus.ACTIVE, offset=offset, limit=limit)
    result_items = []
    for item in items:
        pir_dict = item.model_dump()
        pir_dict["fulfillment_score"] = 0
        pir_dict["tasks"] = []
        pir_dict["generated_reports"] = []
        pir_dict["target_entities"] = []
        result_items.append(pir_dict)
    return {"items": result_items, "total": total, "offset": offset, "limit": limit}


@router.get("/{pir_id}")
async def get_pir(
    pir_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    crud = PIRCRUD(db)
    result = await crud.get_pir(pir_id)
    if result is None:
        raise HTTPException(status_code=404, detail="PIR未找到")
    pir_dict = result.model_dump()
    pir_tasks = await crud.list_pir_tasks(pir_id)
    pir_dict["tasks"] = [t.model_dump() for t in pir_tasks]
    pir_dict["fulfillment_score"] = 0
    pir_dict["generated_reports"] = []
    pir_dict["target_entities"] = []
    if pir_dict.get("status") == "fulfilled":
        pir_dict["fulfillment_score"] = 100
    elif pir_tasks:
        completed = sum(1 for t in pir_tasks if t.status == PIRTaskStatus.COMPLETED)
        pir_dict["fulfillment_score"] = int((completed / len(pir_tasks)) * 100) if pir_tasks else 0
    return pir_dict


@router.patch("/{pir_id}")
async def update_pir(
    pir_id: str,
    data: PIRUpdateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    crud = PIRCRUD(db)
    updates = data.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(status_code=400, detail="没有需要更新的字段")
    result = await crud.update_pir(pir_id, **updates)
    if result is None:
        raise HTTPException(status_code=404, detail="PIR未找到")
    await db.commit()
    return result.model_dump()


@router.delete("/{pir_id}", status_code=204)
async def delete_pir(
    pir_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    crud = PIRCRUD(db)
    deleted = await crud.delete_pir(pir_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="PIR未找到")
    await db.commit()


@router.post("/{pir_id}/tasks", status_code=201)
async def create_pir_task(
    pir_id: str,
    data: PIRTaskCreateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    crud = PIRCRUD(db)
    pir = await crud.get_pir(pir_id)
    if pir is None:
        raise HTTPException(status_code=404, detail="PIR未找到")
    task = PIRTask(
        pir_id=pir_id,
        agent_type=data.agent_type,
        task_description=data.task_description,
    )
    result = await crud.create_pir_task(task)
    await db.commit()
    return result.model_dump()


@router.get("/{pir_id}/tasks")
async def list_pir_tasks(
    pir_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    crud = PIRCRUD(db)
    pir = await crud.get_pir(pir_id)
    if pir is None:
        raise HTTPException(status_code=404, detail="PIR未找到")
    tasks = await crud.list_pir_tasks(pir_id)
    return [t.model_dump() for t in tasks]


@router.patch("/tasks/{task_id}")
async def update_pir_task(
    task_id: str,
    data: PIRTaskUpdateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    crud = PIRCRUD(db)
    updates = data.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(status_code=400, detail="没有需要更新的字段")
    result = await crud.update_pir_task(task_id, **updates)
    if result is None:
        raise HTTPException(status_code=404, detail="PIR任务未找到")
    await db.commit()
    return result.model_dump()


@router.post("/{pir_id}/decompose")
async def decompose_pir(
    pir_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    crud = PIRCRUD(db)
    pir = await crud.get_pir(pir_id)
    if pir is None:
        raise HTTPException(status_code=404, detail="PIR未找到")

    pir_engine = getattr(request.app.state, "pir_engine", None)
    if not pir_engine:
        raise HTTPException(status_code=503, detail="PIR引擎未初始化")
    tasks = await pir_engine.decompose_pir(pir)

    await crud.update_pir(pir_id, status=PIRStatus.ACTIVE)
    await db.commit()
    return {"pir_id": pir_id, "tasks": [t.model_dump() for t in tasks], "task_count": len(tasks)}


@router.post("/{pir_id}/execute")
async def execute_pir(
    pir_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    crud = PIRCRUD(db)
    pir = await crud.get_pir(pir_id)
    if pir is None:
        raise HTTPException(status_code=404, detail="PIR未找到")

    from app.core.task_queue import task_queue
    task_id = await task_queue.submit("query", {
        "query": f"执行PIR: {pir.title} - {pir.description}",
        "context": {"pir_id": pir_id, "keywords": pir.keywords},
    })

    await crud.update_pir(pir_id, status=PIRStatus.ACTIVE)
    await db.commit()
    return {"task_id": task_id, "pir_id": pir_id, "status": "pending"}
