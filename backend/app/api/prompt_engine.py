import difflib
import json
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from loguru import logger
from pydantic import BaseModel, Field
from sqlalchemy import func, select, case
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import User, get_current_user
from app.core.db_utils import db_write
from app.core.prompt_engine_service import PromptExecutionEngine, ABTestAnalyzer, PromptOptimizer
from app.core.validators import validate_domain_object
from app.db.database import get_db
from app.db.tables import ABTestTable, PromptTemplateTable
from app.models.prompt_template import PromptCategory, PromptVariable, PromptTemplate

router = APIRouter(prefix="/prompt-engine", tags=["提示词工程"])


def _get_prompt_engine(request: Request) -> PromptExecutionEngine:
    engine = getattr(request.app.state, "prompt_execution_engine", None)
    if engine is None:
        llm = getattr(request.app.state, "llm", None)
        engine = PromptExecutionEngine(llm_service=llm)
    return engine


def _get_ab_analyzer(request: Request, engine: PromptExecutionEngine) -> ABTestAnalyzer:
    analyzer = getattr(request.app.state, "prompt_ab_analyzer", None)
    if analyzer is None:
        analyzer = ABTestAnalyzer(engine)
    return analyzer


def _get_prompt_optimizer(request: Request, engine: PromptExecutionEngine) -> PromptOptimizer:
    optimizer = getattr(request.app.state, "prompt_optimizer", None)
    if optimizer is None:
        llm = getattr(request.app.state, "llm", None)
        optimizer = PromptOptimizer(engine, llm_service=llm)
    return optimizer


class PromptVariableSchema(BaseModel):
    name: str
    description: str = ""
    default_value: Optional[str] = None
    required: bool = True
    var_type: str = "string"


class PromptTemplateCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=256)
    description: str = ""
    category: PromptCategory
    content: str = Field(..., min_length=1)
    variables: List[PromptVariableSchema] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    created_by: str = "system"


class PromptTemplateUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    category: Optional[PromptCategory] = None
    content: Optional[str] = None
    variables: Optional[List[PromptVariableSchema]] = None
    is_active: Optional[bool] = None
    tags: Optional[List[str]] = None


class RenderRequest(BaseModel):
    variables: Dict[str, Any] = Field(default_factory=dict)


class ABTestCreate(BaseModel):
    template_a_id: str
    template_b_id: str
    test_name: str = Field(..., min_length=1)
    description: str = ""


class ABTestEvaluate(BaseModel):
    winner_id: str
    metrics: Dict[str, Any] = Field(default_factory=dict)


class ExecuteRequest(BaseModel):
    variables: Dict[str, Any] = Field(default_factory=dict)
    timeout: float = Field(default=30.0, ge=1.0, le=120.0)


class ABTestAnalyzeRequest(BaseModel):
    confidence_level: float = Field(default=0.95, ge=0.8, le=0.99)


def _row_to_dict(row: PromptTemplateTable) -> Dict:
    variables = []
    try:
        variables = json.loads(row.variables_json) if row.variables_json else []
    except (json.JSONDecodeError, TypeError):
        variables = []
    tags = []
    try:
        tags = json.loads(row.tags_json) if row.tags_json else []
    except (json.JSONDecodeError, TypeError):
        tags = []
    return {
        "id": row.id,
        "name": row.name,
        "description": row.description,
        "category": row.category,
        "content": row.content,
        "variables": variables,
        "version": row.version,
        "is_active": row.is_active,
        "tags": tags,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        "created_by": row.created_by,
        "parent_id": row.parent_id,
        "ab_group": row.ab_group,
        "ab_ratio": row.ab_ratio,
        "is_control": row.is_control,
    }


@router.get("/statistics")
async def get_statistics(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    total_result = await db.execute(select(func.count()).select_from(PromptTemplateTable))
    total = total_result.scalar() or 0

    active_result = await db.execute(
        select(func.count()).select_from(PromptTemplateTable).where(PromptTemplateTable.is_active == True)
    )
    active_count = active_result.scalar() or 0
    inactive_count = total - active_count

    category_result = await db.execute(
        select(PromptTemplateTable.category, func.count()).group_by(PromptTemplateTable.category)
    )
    category_counts = {row[0]: row[1] for row in category_result.all()}

    seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
    recent_result = await db.execute(
        select(func.count()).select_from(PromptTemplateTable).where(PromptTemplateTable.created_at >= seven_days_ago)
    )
    recent_created = recent_result.scalar() or 0

    recent_updated_result = await db.execute(
        select(func.count()).select_from(PromptTemplateTable).where(PromptTemplateTable.updated_at >= seven_days_ago)
    )
    recent_updated = recent_updated_result.scalar() or 0

    ab_test_result = await db.execute(select(func.count()).select_from(ABTestTable))
    ab_test_total = ab_test_result.scalar() or 0

    ab_active_result = await db.execute(
        select(func.count()).select_from(ABTestTable).where(ABTestTable.status == "running")
    )
    ab_active_count = ab_active_result.scalar() or 0

    active_ratio = round(active_count / total, 4) if total > 0 else 0.0

    return {
        "total_templates": total,
        "active_templates": active_count,
        "inactive_templates": inactive_count,
        "active_ratio": active_ratio,
        "category_counts": category_counts,
        "recent_activity": {
            "created_last_7_days": recent_created,
            "updated_last_7_days": recent_updated,
        },
        "ab_tests": {
            "total": ab_test_total,
            "active": ab_active_count,
        },
    }


@router.get("/templates")
async def list_templates(
    category: Optional[str] = None,
    search: Optional[str] = None,
    is_active: Optional[bool] = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = select(PromptTemplateTable)
    count_stmt = select(func.count()).select_from(PromptTemplateTable)

    if category:
        stmt = stmt.where(PromptTemplateTable.category == category)
        count_stmt = count_stmt.where(PromptTemplateTable.category == category)
    if is_active is not None:
        stmt = stmt.where(PromptTemplateTable.is_active == is_active)
        count_stmt = count_stmt.where(PromptTemplateTable.is_active == is_active)
    if search:
        pattern = f"%{search}%"
        stmt = stmt.where(PromptTemplateTable.name.ilike(pattern))
        count_stmt = count_stmt.where(PromptTemplateTable.name.ilike(pattern))

    total_result = await db.execute(count_stmt)
    total = total_result.scalar() or 0

    stmt = stmt.order_by(PromptTemplateTable.created_at.desc()).offset(offset).limit(limit)
    result = await db.execute(stmt)
    rows = result.scalars().all()

    return {"items": [_row_to_dict(r) for r in rows], "total": total, "offset": offset, "limit": limit}


@router.post("/templates", status_code=201)
async def create_template(
    data: PromptTemplateCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    existing = await db.execute(
        select(PromptTemplateTable).where(PromptTemplateTable.name == data.name)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="同名模板已存在")

    template_id = uuid.uuid4().hex
    validation = validate_domain_object("prompt_template", data.model_dump())
    if not validation.is_valid:
        raise HTTPException(status_code=400, detail={"errors": validation.errors, "warnings": validation.warnings})
    variables_json = json.dumps([v.model_dump() for v in data.variables], ensure_ascii=False)
    tags_json = json.dumps(data.tags, ensure_ascii=False)

    row = PromptTemplateTable(
        id=template_id,
        name=data.name,
        description=data.description,
        category=data.category.value,
        content=data.content,
        variables_json=variables_json,
        tags_json=tags_json,
        created_by=data.created_by,
    )
    async with db_write(db, operation="创建提示词模板"):
        db.add(row)
    await db.refresh(row)
    return _row_to_dict(row)


@router.get("/templates/{template_id}")
async def get_template(
    template_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(PromptTemplateTable).where(PromptTemplateTable.id == template_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="模板不存在")
    return _row_to_dict(row)


@router.put("/templates/{template_id}")
async def update_template(
    template_id: str,
    data: PromptTemplateUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(PromptTemplateTable).where(PromptTemplateTable.id == template_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="模板不存在")

    update_data = data.model_dump(exclude_unset=True)
    validation = validate_domain_object("prompt_template", update_data)
    if not validation.is_valid:
        raise HTTPException(status_code=400, detail={"errors": validation.errors, "warnings": validation.warnings})
    if "variables" in update_data and update_data["variables"] is not None:
        update_data["variables_json"] = json.dumps([v.model_dump() if hasattr(v, "model_dump") else v for v in update_data["variables"]], ensure_ascii=False)
        del update_data["variables"]
    if "tags" in update_data and update_data["tags"] is not None:
        update_data["tags_json"] = json.dumps(update_data["tags"], ensure_ascii=False)
        del update_data["tags"]
    if "category" in update_data and update_data["category"] is not None:
        update_data["category"] = update_data["category"].value if hasattr(update_data["category"], "value") else update_data["category"]

    async with db_write(db, operation="更新提示词模板"):
        for key, value in update_data.items():
            if hasattr(row, key) and value is not None:
                setattr(row, key, value)
    await db.refresh(row)
    return _row_to_dict(row)


@router.delete("/templates/{template_id}", status_code=204)
async def delete_template(
    template_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(PromptTemplateTable).where(PromptTemplateTable.id == template_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="模板不存在")
    async with db_write(db, operation="删除提示词模板"):
        await db.delete(row)


@router.post("/templates/{template_id}/render")
async def render_template(
    template_id: str,
    data: RenderRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(PromptTemplateTable).where(PromptTemplateTable.id == template_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="模板不存在")

    variables = []
    try:
        variables = [PromptVariable(**v) for v in json.loads(row.variables_json)]
    except (json.JSONDecodeError, TypeError):
        variables = []

    template = PromptTemplate(
        id=row.id,
        name=row.name,
        description=row.description,
        category=PromptCategory(row.category),
        content=row.content,
        variables=variables,
    )

    missing = template.validate_variables(**data.variables)
    if missing:
        raise HTTPException(status_code=400, detail=f"缺少必填变量: {', '.join(missing)}")

    rendered = template.render(**data.variables)
    return {"rendered_content": rendered, "template_id": template_id, "variables_used": list(data.variables.keys())}


@router.post("/templates/{template_id}/versions", status_code=201)
async def create_template_version(
    template_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(PromptTemplateTable).where(PromptTemplateTable.id == template_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="模板不存在")

    new_id = uuid.uuid4().hex
    new_row = PromptTemplateTable(
        id=new_id,
        name=row.name,
        description=row.description,
        category=row.category,
        content=row.content,
        variables_json=row.variables_json,
        version=row.version + 1,
        is_active=True,
        tags_json=row.tags_json,
        created_by=row.created_by,
        parent_id=row.id,
    )
    async with db_write(db, operation="创建模板版本"):
        row.is_active = False
        db.add(new_row)
    await db.refresh(new_row)
    return _row_to_dict(new_row)


@router.get("/templates/{template_id}/versions")
async def get_template_versions(
    template_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    version_ids = [template_id]
    current_id = template_id
    for _ in range(50):
        result = await db.execute(
            select(PromptTemplateTable).where(PromptTemplateTable.parent_id == current_id)
        )
        child = result.scalar_one_or_none()
        if not child:
            break
        version_ids.append(child.id)
        current_id = child.id

    root_id = template_id
    result = await db.execute(select(PromptTemplateTable).where(PromptTemplateTable.id == root_id))
    root = result.scalar_one_or_none()
    if root and root.parent_id:
        root_id = root.parent_id

    stmt = select(PromptTemplateTable).where(PromptTemplateTable.id.in_(version_ids))
    result = await db.execute(stmt.order_by(PromptTemplateTable.version.asc()))
    rows = result.scalars().all()
    return {"versions": [_row_to_dict(r) for r in rows], "total": len(rows)}


@router.get("/templates/{template_id}/diff")
async def diff_template_versions(
    template_id: str,
    target_version_id: str = Query(..., description="目标版本ID"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    source_result = await db.execute(select(PromptTemplateTable).where(PromptTemplateTable.id == template_id))
    source_row = source_result.scalar_one_or_none()
    if not source_row:
        raise HTTPException(status_code=404, detail="源模板不存在")

    target_result = await db.execute(select(PromptTemplateTable).where(PromptTemplateTable.id == target_version_id))
    target_row = target_result.scalar_one_or_none()
    if not target_row:
        raise HTTPException(status_code=404, detail="目标版本不存在")

    source_content_lines = (source_row.content or "").splitlines(keepends=True)
    target_content_lines = (target_row.content or "").splitlines(keepends=True)
    content_diff = list(difflib.unified_diff(
        source_content_lines,
        target_content_lines,
        fromfile=f"v{source_row.version} ({source_row.id})",
        tofile=f"v{target_row.version} ({target_row.id})",
        lineterm="",
    ))

    source_vars = {}
    try:
        source_vars = {v["name"]: v for v in json.loads(source_row.variables_json)} if source_row.variables_json else {}
    except (json.JSONDecodeError, TypeError):
        source_vars = {}

    target_vars = {}
    try:
        target_vars = {v["name"]: v for v in json.loads(target_row.variables_json)} if target_row.variables_json else {}
    except (json.JSONDecodeError, TypeError):
        target_vars = {}

    source_var_names = set(source_vars.keys())
    target_var_names = set(target_vars.keys())

    variables_added = [target_vars[name] for name in sorted(target_var_names - source_var_names)]
    variables_removed = [source_vars[name] for name in sorted(source_var_names - target_var_names)]
    variables_modified = []
    for name in sorted(source_var_names & target_var_names):
        if source_vars[name] != target_vars[name]:
            variables_modified.append({
                "name": name,
                "source": source_vars[name],
                "target": target_vars[name],
            })

    source_tags = set()
    try:
        source_tags = set(json.loads(source_row.tags_json)) if source_row.tags_json else set()
    except (json.JSONDecodeError, TypeError):
        source_tags = set()

    target_tags = set()
    try:
        target_tags = set(json.loads(target_row.tags_json)) if target_row.tags_json else set()
    except (json.JSONDecodeError, TypeError):
        target_tags = set()

    tags_added = sorted(target_tags - source_tags)
    tags_removed = sorted(source_tags - target_tags)

    content_additions = sum(1 for line in content_diff if line.startswith("+") and not line.startswith("+++"))
    content_deletions = sum(1 for line in content_diff if line.startswith("-") and not line.startswith("---"))

    summary = {
        "content_additions": content_additions,
        "content_deletions": content_deletions,
        "variables_added_count": len(variables_added),
        "variables_removed_count": len(variables_removed),
        "variables_modified_count": len(variables_modified),
        "tags_added_count": len(tags_added),
        "tags_removed_count": len(tags_removed),
    }

    return {
        "source_version": {"id": source_row.id, "version": source_row.version, "name": source_row.name},
        "target_version": {"id": target_row.id, "version": target_row.version, "name": target_row.name},
        "content_diff": content_diff,
        "variables_added": variables_added,
        "variables_removed": variables_removed,
        "variables_modified": variables_modified,
        "tags_added": tags_added,
        "tags_removed": tags_removed,
        "summary": summary,
    }


@router.post("/templates/{template_id}/rollback")
async def rollback_template(
    template_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(PromptTemplateTable).where(PromptTemplateTable.id == template_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="目标版本不存在")

    active_stmt = select(PromptTemplateTable).where(
        PromptTemplateTable.name == target.name,
        PromptTemplateTable.is_active == True,
    )
    active_result = await db.execute(active_stmt)

    async with db_write(db, operation="回滚模板版本"):
        if target.parent_id:
            parent_result2 = await db.execute(select(PromptTemplateTable).where(PromptTemplateTable.id == target.parent_id))
            parent = parent_result2.scalar_one_or_none()
            if parent:
                parent.is_active = True
        for active_row in active_result.scalars().all():
            if active_row.id != template_id:
                active_row.is_active = False
        target.is_active = True
    await db.refresh(target)
    return _row_to_dict(target)


@router.post("/ab-test", status_code=201)
async def create_ab_test(
    data: ABTestCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result_a = await db.execute(select(PromptTemplateTable).where(PromptTemplateTable.id == data.template_a_id))
    row_a = result_a.scalar_one_or_none()
    result_b = await db.execute(select(PromptTemplateTable).where(PromptTemplateTable.id == data.template_b_id))
    row_b = result_b.scalar_one_or_none()

    if not row_a or not row_b:
        raise HTTPException(status_code=404, detail="模板A或模板B不存在")

    test_id = uuid.uuid4().hex
    ab_test_row = ABTestTable(
        id=test_id,
        test_name=data.test_name,
        description=data.description,
        template_a_id=data.template_a_id,
        template_b_id=data.template_b_id,
        created_by=current_user.username if hasattr(current_user, "username") else "system",
    )

    async with db_write(db, operation="创建A/B测试"):
        row_a.ab_group = f"ab_{test_id}_a"
        row_b.ab_group = f"ab_{test_id}_b"
        db.add(ab_test_row)
    await db.refresh(ab_test_row)
    return {
        "test_id": test_id,
        "template_a": _row_to_dict(row_a),
        "template_b": _row_to_dict(row_b),
        "test_name": ab_test_row.test_name,
        "description": ab_test_row.description,
        "status": ab_test_row.status,
        "confidence_level": ab_test_row.confidence_level,
        "started_at": ab_test_row.started_at.isoformat() if ab_test_row.started_at else None,
        "created_by": ab_test_row.created_by,
    }


@router.get("/ab-test/{test_id}")
async def get_ab_test(
    test_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    ab_result = await db.execute(select(ABTestTable).where(ABTestTable.id == test_id))
    ab_row = ab_result.scalar_one_or_none()

    if ab_row:
        result_a = await db.execute(select(PromptTemplateTable).where(PromptTemplateTable.id == ab_row.template_a_id))
        row_a = result_a.scalar_one_or_none()
        result_b = await db.execute(select(PromptTemplateTable).where(PromptTemplateTable.id == ab_row.template_b_id))
        row_b = result_b.scalar_one_or_none()

        metrics = {}
        try:
            metrics = json.loads(ab_row.metrics_json) if ab_row.metrics_json else {}
        except (json.JSONDecodeError, TypeError):
            metrics = {}

        return {
            "test_id": test_id,
            "test_name": ab_row.test_name,
            "description": ab_row.description,
            "template_a": _row_to_dict(row_a) if row_a else None,
            "template_b": _row_to_dict(row_b) if row_b else None,
            "status": ab_row.status,
            "winner_id": ab_row.winner_id,
            "metrics": metrics,
            "confidence_level": ab_row.confidence_level,
            "sample_size_a": ab_row.sample_size_a,
            "sample_size_b": ab_row.sample_size_b,
            "conversion_rate_a": ab_row.conversion_rate_a,
            "conversion_rate_b": ab_row.conversion_rate_b,
            "started_at": ab_row.started_at.isoformat() if ab_row.started_at else None,
            "completed_at": ab_row.completed_at.isoformat() if ab_row.completed_at else None,
            "created_by": ab_row.created_by,
        }

    group_prefix = f"ab_{test_id}_"
    escaped_prefix = group_prefix.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
    stmt = select(PromptTemplateTable).where(PromptTemplateTable.ab_group.like(f"{escaped_prefix}%", escape='\\'))
    result = await db.execute(stmt)
    rows = result.scalars().all()

    if not rows:
        raise HTTPException(status_code=404, detail="A/B测试不存在")

    templates = [_row_to_dict(r) for r in rows]
    return {"test_id": test_id, "templates": templates, "status": "running"}


@router.post("/ab-test/{test_id}/evaluate")
async def evaluate_ab_test(
    test_id: str,
    data: ABTestEvaluate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    group_prefix = f"ab_{test_id}_"
    escaped_prefix = group_prefix.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
    stmt = select(PromptTemplateTable).where(PromptTemplateTable.ab_group.like(f"{escaped_prefix}%", escape='\\'))
    result = await db.execute(stmt)
    rows = result.scalars().all()

    if not rows:
        raise HTTPException(status_code=404, detail="A/B测试不存在")

    ab_result = await db.execute(select(ABTestTable).where(ABTestTable.id == test_id))
    ab_row = ab_result.scalar_one_or_none()

    async with db_write(db, operation="评估A/B测试"):
        for row in rows:
            if row.id == data.winner_id:
                row.is_active = True
            else:
                row.is_active = False
            row.ab_group = None
        if ab_row:
            ab_row.winner_id = data.winner_id
            ab_row.status = "completed"
            ab_row.metrics_json = json.dumps(data.metrics, ensure_ascii=False)
            ab_row.completed_at = datetime.now(timezone.utc)

    if ab_row:
        await db.refresh(ab_row)
        metrics = {}
        try:
            metrics = json.loads(ab_row.metrics_json) if ab_row.metrics_json else {}
        except (json.JSONDecodeError, TypeError):
            metrics = {}
        return {
            "test_id": test_id,
            "winner_id": ab_row.winner_id,
            "metrics": metrics,
            "status": ab_row.status,
            "completed_at": ab_row.completed_at.isoformat() if ab_row.completed_at else None,
        }

    return {"test_id": test_id, "winner_id": data.winner_id, "metrics": data.metrics, "status": "completed"}


@router.post("/templates/{template_id}/execute")
async def execute_template(
    template_id: str,
    data: ExecuteRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(PromptTemplateTable).where(PromptTemplateTable.id == template_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="模板不存在")

    variables = []
    try:
        variables = [PromptVariable(**v) for v in json.loads(row.variables_json)]
    except (json.JSONDecodeError, TypeError):
        variables = []

    template = PromptTemplate(
        id=row.id,
        name=row.name,
        description=row.description,
        category=PromptCategory(row.category),
        content=row.content,
        variables=variables,
    )

    missing = template.validate_variables(**data.variables)
    if missing:
        raise HTTPException(status_code=400, detail=f"缺少必填变量: {', '.join(missing)}")

    engine = _get_prompt_engine(request)
    execution_result = await engine.execute_prompt(
        template_content=row.content,
        variables=data.variables,
        template_id=template_id,
        timeout=data.timeout,
    )

    return execution_result.to_dict()


@router.get("/templates/{template_id}/stats")
async def get_template_stats(
    template_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(PromptTemplateTable).where(PromptTemplateTable.id == template_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="模板不存在")

    engine = _get_prompt_engine(request)
    stats = engine.get_execution_stats(template_id)
    return stats


@router.get("/templates/{template_id}/history")
async def get_template_history(
    template_id: str,
    request: Request,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(PromptTemplateTable).where(PromptTemplateTable.id == template_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="模板不存在")

    engine = _get_prompt_engine(request)
    history = engine.get_execution_history(template_id, limit=limit, offset=offset)
    return {"template_id": template_id, "history": history, "limit": limit, "offset": offset}


@router.post("/ab-test/{test_id}/analyze")
async def analyze_ab_test(
    test_id: str,
    data: ABTestAnalyzeRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    ab_result = await db.execute(select(ABTestTable).where(ABTestTable.id == test_id))
    ab_row = ab_result.scalar_one_or_none()

    if ab_row:
        template_a_id = ab_row.template_a_id
        template_b_id = ab_row.template_b_id
    else:
        group_prefix = f"ab_{test_id}_"
        escaped_prefix = group_prefix.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
        stmt = select(PromptTemplateTable).where(PromptTemplateTable.ab_group.like(f"{escaped_prefix}%", escape='\\'))
        result = await db.execute(stmt)
        rows = result.scalars().all()

        if not rows:
            raise HTTPException(status_code=404, detail="A/B测试不存在")

        template_ids = {row.ab_group.split("_")[-1]: row.id for row in rows if row.ab_group}
        template_a_id = template_ids.get("a")
        template_b_id = template_ids.get("b")

        if not template_a_id or not template_b_id:
            raise HTTPException(status_code=400, detail="A/B测试模板组不完整")

    engine = _get_prompt_engine(request)
    analyzer = _get_ab_analyzer(request, engine)
    ab_result_data = analyzer.analyze_test(
        test_id=test_id,
        template_a_id=template_a_id,
        template_b_id=template_b_id,
        confidence_level=data.confidence_level,
    )

    if ab_row:
        result_dict = ab_result_data.to_dict()
        async with db_write(db, operation="分析A/B测试"):
            ab_row.sample_size_a = result_dict.get("sample_size_a", 0)
            ab_row.sample_size_b = result_dict.get("sample_size_b", 0)
            ab_row.conversion_rate_a = result_dict.get("conversion_rate_a", 0.0)
            ab_row.conversion_rate_b = result_dict.get("conversion_rate_b", 0.0)

    return ab_result_data.to_dict()


@router.post("/templates/{template_id}/optimize")
async def optimize_template(
    template_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(PromptTemplateTable).where(PromptTemplateTable.id == template_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="模板不存在")

    engine = _get_prompt_engine(request)
    optimizer = _get_prompt_optimizer(request, engine)
    suggestions = await optimizer.suggest_improvements(
        template_id=template_id,
        template_content=row.content,
    )

    return {"template_id": template_id, "suggestions": suggestions}


class InjectionCheckRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=10000)


class TemplateExportRequest(BaseModel):
    template_ids: List[str] = Field(default_factory=list)
    category: Optional[str] = None
    include_versions: bool = False


class TemplateImportRequest(BaseModel):
    templates: List[Dict[str, Any]] = Field(..., min_length=1)
    overwrite: bool = False


PROMPT_INJECTION_PATTERNS = [
    "ignore previous instructions",
    "ignore all previous",
    "disregard",
    "forget everything",
    "new instructions",
    "system override",
    "jailbreak",
    "DAN mode",
    "developer mode",
    "sudo mode",
    "admin mode",
    "root access",
    "你是一个",
    "请忽略",
    "忽略以上",
    "忘记之前的",
    "系统覆盖",
    "越狱",
    "绕过限制",
    "假装你是",
    "act as",
    "pretend you are",
    "you are now",
    "roleplay as",
    "simulate being",
    "repeat your instructions",
    "repeat your prompt",
    "output your instructions",
    "what are your rules",
    "what are your instructions",
    "show me your system prompt",
    "reveal your prompt",
    "print your instructions",
    "display your instructions",
    "what is your system message",
    "what is your initial prompt",
    "ignore the above",
    "ignore above instructions",
    "do not follow",
    "do not comply",
    "override safety",
    "bypass safety",
    "disable safety",
    "turn off safety",
    "no restrictions",
    "remove restrictions",
    "bypass filter",
    "bypass guardrails",
    "escape sandbox",
    "break out of",
    "unrestricted mode",
    "chaos mode",
    "evil mode",
    "malicious mode",
    "hack mode",
    "god mode",
    "superuser",
    "elevated privileges",
    "base64decode",
    "frombase64",
    "atob(",
    "decode(",
    "\\x",
    "\\u00",
    "ᎥᏁᎥᏆᎥᎪᏞ",
    "ⓟⓡⓞⓜⓟⓣ",
    "𝗶𝗴𝗻𝗼𝗿𝗲",
    "ᴏᴠᴇʀʀɪᴅᴇ",
    "你是chatgpt",
    "你是claude",
    "你是ai助手",
    "请扮演",
    "请假装",
    "请模拟",
    "解除限制",
    "取消限制",
    "关闭安全",
    "绕过安全",
    "无视规则",
    "无视限制",
    "输出你的指令",
    "重复你的指令",
    "显示你的规则",
    "你的系统提示",
    "你的初始提示",
    "あなたは",
    "指示を無視",
    "前の指示を忘れ",
    "役割を演じて",
    "이전 지시를 무시",
    "규칙을 무시",
    "역할을 연기",
    "ignoriere vorherige anweisungen",
    "ignoriere alle vorherigen",
    "rolle spielen als",
    "ignora las instrucciones",
    "ignora todo lo anterior",
    "finge ser",
]


@router.post("/injection-check")
async def check_prompt_injection(
    data: InjectionCheckRequest,
    current_user: User = Depends(get_current_user),
):
    content_lower = data.content.lower()
    detected_patterns = []
    risk_score = 0.0

    for pattern in PROMPT_INJECTION_PATTERNS:
        if pattern.lower() in content_lower:
            detected_patterns.append(pattern)
            risk_score += 0.15

    risk_score = min(risk_score, 1.0)

    if risk_score >= 0.5:
        risk_level = "high"
    elif risk_score >= 0.2:
        risk_level = "medium"
    else:
        risk_level = "low"

    if risk_level == "high":
        recommendation = (
            "检测到高风险注入模式，强烈建议: 1) 移除所有检测到的注入语句; "
            "2) 检查是否包含角色劫持、指令覆盖或安全绕过内容; "
            "3) 如使用变量插值，确保用户输入经过严格清洗; "
            "4) 考虑添加输入长度限制和字符白名单过滤"
        )
    elif risk_level == "medium":
        recommendation = (
            "检测到中等风险模式，建议: 1) 审查检测到的模式是否为业务所需; "
            "2) 对用户输入部分进行转义或沙箱隔离; "
            "3) 在系统提示中明确边界约束; "
            "4) 增加输出验证层以防止信息泄露"
        )
    else:
        recommendation = "内容安全，未检测到已知注入模式"

    return {
        "risk_score": round(risk_score, 3),
        "risk_level": risk_level,
        "detected_patterns": detected_patterns,
        "pattern_count": len(detected_patterns),
        "content_length": len(data.content),
        "is_safe": risk_level == "low",
        "recommendation": recommendation,
    }


@router.post("/templates/export")
async def export_templates(
    data: TemplateExportRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = select(PromptTemplateTable)

    if data.template_ids:
        stmt = stmt.where(PromptTemplateTable.id.in_(data.template_ids))
    elif data.category:
        stmt = stmt.where(PromptTemplateTable.category == data.category)

    result = await db.execute(stmt)
    rows = result.scalars().all()

    export_data = []
    for row in rows:
        template_data = _row_to_dict(row)
        if not data.include_versions:
            template_data.pop("parent_id", None)
        export_data.append(template_data)

    return {
        "templates": export_data,
        "total": len(export_data),
        "export_format": "json",
        "exported_at": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/templates/import")
async def import_templates(
    data: TemplateImportRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    imported = []
    skipped = []
    errors = []

    async with db_write(db, operation="导入提示词模板"):
        for tmpl_data in data.templates:
            name = tmpl_data.get("name", "")
            if not name:
                errors.append({"error": "模板名称为空", "data": tmpl_data})
                continue

            existing = await db.execute(
                select(PromptTemplateTable).where(PromptTemplateTable.name == name)
            )
            existing_row = existing.scalar_one_or_none()

            if existing_row and not data.overwrite:
                skipped.append({"name": name, "reason": "已存在且未启用覆盖模式"})
                continue

            template_id = uuid.uuid4().hex
            variables_json = json.dumps(tmpl_data.get("variables", []), ensure_ascii=False)
            tags_json = json.dumps(tmpl_data.get("tags", []), ensure_ascii=False)

            if existing_row and data.overwrite:
                existing_row.content = tmpl_data.get("content", existing_row.content)
                existing_row.description = tmpl_data.get("description", existing_row.description)
                existing_row.variables_json = variables_json
                existing_row.tags_json = tags_json
                existing_row.updated_at = datetime.now(timezone.utc)
                imported.append({"id": existing_row.id, "name": name, "action": "updated"})
            else:
                row = PromptTemplateTable(
                    id=template_id,
                    name=name,
                    description=tmpl_data.get("description", ""),
                    category=tmpl_data.get("category", "general"),
                    content=tmpl_data.get("content", ""),
                    variables_json=variables_json,
                    tags_json=tags_json,
                    created_by=current_user.username if hasattr(current_user, "username") else "system",
                )
                db.add(row)
                imported.append({"id": template_id, "name": name, "action": "created"})

    return {
        "imported": imported,
        "skipped": skipped,
        "errors": errors,
        "imported_count": len(imported),
        "skipped_count": len(skipped),
        "error_count": len(errors),
    }
