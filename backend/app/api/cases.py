from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from loguru import logger
from pydantic import BaseModel, Field

from app.core.api_key_auth import require_permission
from app.core.api_key_manager import ApiKey, ApiPermission
from app.core.case_manager import case_manager, CaseStatus, CaseEventType


cases_router = APIRouter(prefix="/cases", tags=["Case Management"])


class CaseCreateRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=500)
    description: str = Field(..., min_length=1)
    severity: str = Field(default="medium", pattern="^(low|medium|high|critical)$")


class CaseUpdateRequest(BaseModel):
    title: Optional[str] = Field(None, min_length=1, max_length=500)
    description: Optional[str] = None
    severity: Optional[str] = Field(None, pattern="^(low|medium|high|critical)$")
    assignee: Optional[str] = None


class IntelligenceLinkRequest(BaseModel):
    intelligence_id: str = Field(..., min_length=1)


class EntityLinkRequest(BaseModel):
    entity_id: str = Field(..., min_length=1)


class CommentRequest(BaseModel):
    comment: str = Field(..., min_length=1)
    operator: str = Field(default="system")


class EscalateRequest(BaseModel):
    assignee: str = Field(..., min_length=1)
    reason: str = Field(..., min_length=1)


class ResolveRequest(BaseModel):
    resolution: str = Field(..., min_length=1)
    operator: str = Field(default="system")


@cases_router.post("/")
async def create_case(
    data: CaseCreateRequest,
    api_key: ApiKey = Depends(require_permission("intel:write")),
):
    case = await case_manager.create_case(
        title=data.title,
        description=data.description,
        severity=data.severity,
    )
    return {
        "case_id": case.case_id,
        "title": case.title,
        "status": case.status.value,
        "severity": case.severity,
        "created_at": case.created_at.isoformat(),
    }


@cases_router.get("/")
async def search_cases(
    query: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    assignee: Optional[str] = Query(None),
    api_key: ApiKey = Depends(require_permission("intel:read")),
):
    filters = {}
    if status:
        filters["status"] = status
    if severity:
        filters["severity"] = severity
    if assignee:
        filters["assignee"] = assignee

    cases = await case_manager.search_cases(query=query or "", filters=filters or None)
    return {
        "items": [
            {
                "case_id": c.case_id,
                "title": c.title,
                "status": c.status.value,
                "severity": c.severity,
                "assignee": c.assignee,
                "created_at": c.created_at.isoformat() if c.created_at else None,
                "updated_at": c.updated_at.isoformat() if c.updated_at else None,
            }
            for c in cases
        ],
        "total": len(cases),
    }


@cases_router.get("/{case_id}")
async def get_case(
    case_id: str,
    api_key: ApiKey = Depends(require_permission("intel:read")),
):
    case = await case_manager.get_case(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return {
        "case_id": case.case_id,
        "title": case.title,
        "description": case.description,
        "status": case.status.value,
        "severity": case.severity,
        "assignee": case.assignee,
        "related_intelligence_ids": case.related_intelligence_ids,
        "related_entity_ids": case.related_entity_ids,
        "timeline": [
            {
                "event_id": e.event_id,
                "event_type": e.event_type.value,
                "description": e.description,
                "operator": e.operator,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            }
            for e in case.timeline
        ],
        "created_at": case.created_at.isoformat() if case.created_at else None,
        "updated_at": case.updated_at.isoformat() if case.updated_at else None,
        "resolved_at": case.resolved_at.isoformat() if case.resolved_at else None,
    }


@cases_router.put("/{case_id}")
async def update_case(
    case_id: str,
    data: CaseUpdateRequest,
    api_key: ApiKey = Depends(require_permission("intel:write")),
):
    updates = {}
    if data.title is not None:
        updates["title"] = data.title
    if data.description is not None:
        updates["description"] = data.description
    if data.severity is not None:
        updates["severity"] = data.severity
    if data.assignee is not None:
        updates["assignee"] = data.assignee

    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    ok = await case_manager.update_case(case_id, **updates)
    if not ok:
        raise HTTPException(status_code=404, detail="Case not found")
    return {"case_id": case_id, "status": "updated"}


@cases_router.post("/{case_id}/intelligence")
async def link_intelligence(
    case_id: str,
    data: IntelligenceLinkRequest,
    api_key: ApiKey = Depends(require_permission("intel:write")),
):
    ok = await case_manager.add_intelligence_to_case(case_id, data.intelligence_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Case not found")
    return {"case_id": case_id, "intelligence_id": data.intelligence_id, "status": "linked"}


@cases_router.post("/{case_id}/entities")
async def link_entity(
    case_id: str,
    data: EntityLinkRequest,
    api_key: ApiKey = Depends(require_permission("intel:write")),
):
    ok = await case_manager.add_entity_to_case(case_id, data.entity_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Case not found")
    return {"case_id": case_id, "entity_id": data.entity_id, "status": "linked"}


@cases_router.post("/{case_id}/comments")
async def add_comment(
    case_id: str,
    data: CommentRequest,
    api_key: ApiKey = Depends(require_permission("intel:write")),
):
    case = await case_manager.get_case(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    await case_manager.add_comment(case_id, data.comment, data.operator)
    return {"case_id": case_id, "status": "comment_added"}


@cases_router.post("/{case_id}/escalate")
async def escalate_case(
    case_id: str,
    data: EscalateRequest,
    api_key: ApiKey = Depends(require_permission("intel:write")),
):
    ok = await case_manager.escalate(case_id, data.assignee, data.reason)
    if not ok:
        raise HTTPException(status_code=404, detail="Case not found")
    return {"case_id": case_id, "status": "escalated", "assignee": data.assignee}


@cases_router.post("/{case_id}/resolve")
async def resolve_case(
    case_id: str,
    data: ResolveRequest,
    api_key: ApiKey = Depends(require_permission("intel:write")),
):
    ok = await case_manager.resolve(case_id, data.resolution, data.operator)
    if not ok:
        raise HTTPException(status_code=404, detail="Case not found")
    return {"case_id": case_id, "status": "resolved"}


@cases_router.get("/{case_id}/timeline")
async def get_case_timeline(
    case_id: str,
    api_key: ApiKey = Depends(require_permission("intel:read")),
):
    events = await case_manager.get_case_timeline(case_id)
    return {
        "case_id": case_id,
        "events": [
            {
                "event_id": e.event_id,
                "event_type": e.event_type.value,
                "description": e.description,
                "operator": e.operator,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            }
            for e in events
        ],
        "total": len(events),
    }
