import json
import re
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Optional, List, Dict

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from loguru import logger
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.auth import User, get_current_user
from app.core.content_engine import ContentGenerator, ReviewWorkflow
from app.core.db_utils import db_write
from app.core.qa_engine import DialogueManager
from app.core.validators import validate_domain_object
from app.db.database import get_db, async_session_factory
from app.db.tables import GeneratedContentTable, CleanedIntelligenceTable, PromptTemplateTable
from app.models.generated_content import ContentType, ReviewStatus

router = APIRouter(prefix="/content-gen", tags=["内容生成"])


def _get_content_generator(request: Request) -> ContentGenerator:
    generator = getattr(request.app.state, "content_generator", None)
    if generator is None:
        llm = getattr(request.app.state, "llm", None)
        generator = ContentGenerator(llm_service=llm)
    return generator


def _get_review_workflow(request: Request) -> ReviewWorkflow:
    workflow = getattr(request.app.state, "review_workflow", None)
    if workflow is None:
        workflow = ReviewWorkflow()
    return workflow


class GenerateContentRequest(BaseModel):
    model_config = {"protected_namespaces": ()}
    title: str = Field(..., min_length=1, max_length=256)
    content_type: ContentType
    source_refs: List[str] = Field(default_factory=list)
    model_id: Optional[str] = None
    prompt_template_id: Optional[str] = None
    context: Optional[str] = None
    created_by: str = "system"


class ReviewRequest(BaseModel):
    action: str = Field(..., pattern=r"^(approve|reject)$")
    reviewer: str = Field(..., min_length=1)
    reviewer_role: str = "expert"
    comment: str = ""


class GenerateWithSourcesRequest(BaseModel):
    model_config = {"protected_namespaces": ()}
    title: str = Field(..., min_length=1, max_length=256)
    content_type: ContentType
    source_ids: List[str] = Field(..., min_length=1)
    model_id: Optional[str] = None
    custom_instructions: Optional[str] = None
    created_by: str = "system"


class ContentUpdate(BaseModel):
    title: Optional[str] = None
    content: Optional[str] = None
    source_refs: Optional[List[str]] = None


class BatchGenerateRequest(BaseModel):
    model_config = {"protected_namespaces": ()}
    items: List[GenerateContentRequest] = Field(..., min_length=1, max_length=50)
    auto_review: bool = True


class ContentScoreRequest(BaseModel):
    dimensions: List[str] = Field(default_factory=lambda: ["relevance", "accuracy", "completeness", "clarity"])


class BatchReviewRequest(BaseModel):
    content_ids: List[str] = Field(..., min_length=1)
    review_status: str = Field(
        ...,
        pattern=r"^(approved|rejected|auto_checked|expert_review|supervisor_approved|pending|revised)$",
    )
    review_comment: str = ""


def _row_to_dict(row: GeneratedContentTable) -> Dict:
    source_refs = []
    try:
        source_refs = json.loads(row.source_refs_json) if row.source_refs_json else []
    except (json.JSONDecodeError, TypeError):
        source_refs = []
    return {
        "id": row.id,
        "title": row.title,
        "content_type": row.content_type,
        "content": row.content,
        "review_status": row.review_status,
        "reviewer": row.reviewer,
        "review_comment": row.review_comment,
        "source_refs": source_refs,
        "model_id": row.model_id,
        "prompt_template_id": row.prompt_template_id,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "reviewed_at": row.reviewed_at.isoformat() if row.reviewed_at else None,
        "created_by": row.created_by,
        "parent_id": getattr(row, "parent_id", None),
    }


async def _collect_source_intelligence(source_refs: List[str]) -> str:
    if not source_refs:
        try:
            async with async_session_factory() as session:
                stmt = select(CleanedIntelligenceTable).where(
                    CleanedIntelligenceTable.threat_level.in_(["critical", "high"])
                ).order_by(CleanedIntelligenceTable.cleaned_at.desc()).limit(10)
                result = await session.execute(stmt)
                rows = result.scalars().all()
                if rows:
                    return "\n".join(f"[情报{i+1}] {r.content[:300]}" for i, r in enumerate(rows) if r.content)
        except Exception as exc:
            logger.warning(f"Collect source intelligence failed: {exc}")
        return ""

    try:
        async with async_session_factory() as session:
            stmt = select(CleanedIntelligenceTable).where(
                CleanedIntelligenceTable.id.in_(source_refs)
            ).limit(20)
            result = await session.execute(stmt)
            rows = result.scalars().all()
            if rows:
                return "\n".join(f"[情报{i+1}] {r.content[:300]}" for i, r in enumerate(rows) if r.content)
    except Exception as exc:
        logger.warning(f"Collect source intelligence by refs failed: {exc}")
    return ""


@router.get("/statistics")
async def get_statistics(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    type_counts_result = await db.execute(
        select(GeneratedContentTable.content_type, func.count())
        .group_by(GeneratedContentTable.content_type)
    )
    by_type = {row[0]: row[1] for row in type_counts_result.all()}

    status_counts_result = await db.execute(
        select(GeneratedContentTable.review_status, func.count())
        .group_by(GeneratedContentTable.review_status)
    )
    by_review_status = {row[0]: row[1] for row in status_counts_result.all()}

    seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
    recent_count_result = await db.execute(
        select(func.count())
        .select_from(GeneratedContentTable)
        .where(GeneratedContentTable.created_at >= seven_days_ago)
    )
    recent_7d_count = recent_count_result.scalar() or 0

    total_result = await db.execute(
        select(func.count()).select_from(GeneratedContentTable)
    )
    total = total_result.scalar() or 0

    return {
        "total": total,
        "by_type": by_type,
        "by_review_status": by_review_status,
        "recent_7d_count": recent_7d_count,
    }


@router.get("/contents")
async def list_contents(
    content_type: Optional[str] = None,
    review_status: Optional[str] = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = select(GeneratedContentTable)
    count_stmt = select(func.count()).select_from(GeneratedContentTable)

    if content_type:
        stmt = stmt.where(GeneratedContentTable.content_type == content_type)
        count_stmt = count_stmt.where(GeneratedContentTable.content_type == content_type)
    if review_status:
        stmt = stmt.where(GeneratedContentTable.review_status == review_status)
        count_stmt = count_stmt.where(GeneratedContentTable.review_status == review_status)

    total_result = await db.execute(count_stmt)
    total = total_result.scalar() or 0

    stmt = stmt.order_by(GeneratedContentTable.created_at.desc()).offset(offset).limit(limit)
    result = await db.execute(stmt)
    rows = result.scalars().all()

    return {"items": [_row_to_dict(r) for r in rows], "total": total, "offset": offset, "limit": limit}


@router.post("/generate", status_code=201)
async def generate_content(
    request: Request,
    data: GenerateContentRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    source_intel = await _collect_source_intelligence(data.source_refs)

    validation = validate_domain_object("generated_content", data.model_dump())
    if not validation.is_valid:
        raise HTTPException(status_code=400, detail={"errors": validation.errors, "warnings": validation.warnings})

    custom_prompt = None
    if data.prompt_template_id:
        try:
            tmpl_result = await db.execute(
                select(PromptTemplateTable).where(PromptTemplateTable.id == data.prompt_template_id)
            )
            tmpl_row = tmpl_result.scalar_one_or_none()
            if tmpl_row:
                custom_prompt = tmpl_row.content
        except Exception as exc:
            logger.warning(f"Load prompt template failed: {exc}")

    generator = _get_content_generator(request)

    doc = await generator.generate(
        content_type=data.content_type.value,
        title=data.title,
        source_data=source_intel,
        source_refs=data.source_refs,
        template_id=data.prompt_template_id,
        model_id=data.model_id,
        custom_instructions=custom_prompt or data.context,
    )

    workflow = _get_review_workflow(request)
    auto_check_result = workflow.auto_check(data.content_type.value, doc.content)

    if auto_check_result["passed"]:
        review_status = "auto_checked"
    else:
        review_status = ReviewStatus.PENDING.value

    content_id = doc.doc_id
    source_refs_json = json.dumps(doc.source_refs, ensure_ascii=False)

    row = GeneratedContentTable(
        id=content_id,
        title=doc.title,
        content_type=doc.content_type,
        content=doc.content,
        review_status=review_status,
        source_refs_json=source_refs_json,
        model_id=doc.model_id,
        prompt_template_id=doc.template_id,
        created_by=data.created_by,
    )
    async with db_write(db, operation="生成内容"):
        db.add(row)
    await db.refresh(row)

    result = _row_to_dict(row)
    result["generation_meta"] = {
        "word_count": doc.word_count,
        "generation_time_ms": round(doc.generation_time_ms, 2),
        "tokens_used": doc.tokens_used,
    }
    result["auto_check"] = auto_check_result
    return result


@router.get("/contents/{content_id}")
async def get_content(
    content_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(GeneratedContentTable).where(GeneratedContentTable.id == content_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="内容不存在")
    return _row_to_dict(row)


@router.post("/contents/{content_id}/review")
async def review_content(
    content_id: str,
    data: ReviewRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(GeneratedContentTable).where(GeneratedContentTable.id == content_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="内容不存在")

    workflow = _get_review_workflow(request)
    current_status = row.review_status

    if data.action == "reject":
        new_review_status = "rejected"
    else:
        if not workflow.can_approve(row.content_type, current_status, data.reviewer_role):
            raise HTTPException(
                status_code=403,
                detail=f"当前角色 {data.reviewer_role} 无权审核状态为 {current_status} 的内容",
            )
        new_review_status = workflow.next_status(row.content_type, current_status, data.action)

    async with db_write(db, operation="审核内容"):
        row.review_status = new_review_status
        row.reviewer = data.reviewer
        row.review_comment = data.comment
        row.reviewed_at = datetime.now(timezone.utc)
    await db.refresh(row)

    result_data = _row_to_dict(row)
    result_data["review_levels"] = workflow.get_review_levels(row.content_type)
    return result_data


@router.put("/contents/{content_id}")
async def update_content(
    content_id: str,
    data: ContentUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(GeneratedContentTable).where(GeneratedContentTable.id == content_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="内容不存在")

    update_data = data.model_dump(exclude_unset=True)
    if "source_refs" in update_data and update_data["source_refs"] is not None:
        update_data["source_refs_json"] = json.dumps(update_data["source_refs"], ensure_ascii=False)
        del update_data["source_refs"]

    async with db_write(db, operation="更新内容"):
        for key, value in update_data.items():
            if hasattr(row, key) and value is not None:
                setattr(row, key, value)
        row.review_status = ReviewStatus.REVISED.value
    await db.refresh(row)
    return _row_to_dict(row)


@router.delete("/contents/{content_id}", status_code=204)
async def delete_content(
    content_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(GeneratedContentTable).where(GeneratedContentTable.id == content_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="内容不存在")
    async with db_write(db, operation="删除内容"):
        await db.delete(row)


@router.post("/generate-with-sources", status_code=201)
async def generate_with_sources(
    request: Request,
    data: GenerateWithSourcesRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    source_intel = await _collect_source_intelligence(data.source_ids)

    if not source_intel:
        raise HTTPException(status_code=400, detail="未找到指定情报源数据")

    validation = validate_domain_object("generated_content", data.model_dump())
    if not validation.is_valid:
        raise HTTPException(status_code=400, detail={"errors": validation.errors, "warnings": validation.warnings})

    generator = _get_content_generator(request)

    doc = await generator.generate(
        content_type=data.content_type.value,
        title=data.title,
        source_data=source_intel,
        source_refs=data.source_ids,
        model_id=data.model_id,
        custom_instructions=data.custom_instructions,
    )

    workflow = _get_review_workflow(request)
    auto_check_result = workflow.auto_check(data.content_type.value, doc.content)

    if auto_check_result["passed"]:
        review_status = "auto_checked"
    else:
        review_status = ReviewStatus.PENDING.value

    source_refs_json = json.dumps(doc.source_refs, ensure_ascii=False)

    row = GeneratedContentTable(
        id=doc.doc_id,
        title=doc.title,
        content_type=doc.content_type,
        content=doc.content,
        review_status=review_status,
        source_refs_json=source_refs_json,
        model_id=doc.model_id,
        created_by=data.created_by,
    )
    async with db_write(db, operation="基于情报源生成内容"):
        db.add(row)
    await db.refresh(row)

    result = _row_to_dict(row)
    result["generation_meta"] = {
        "word_count": doc.word_count,
        "generation_time_ms": round(doc.generation_time_ms, 2),
        "tokens_used": doc.tokens_used,
    }
    result["auto_check"] = auto_check_result
    result["source_count"] = len(data.source_ids)
    result["review_levels"] = workflow.get_review_levels(data.content_type.value)
    return result


@router.get("/types")
async def list_content_types(
    current_user: User = Depends(get_current_user),
):
    types = [
        {"value": ContentType.REPORT_SUMMARY.value, "label": "报告摘要", "description": "情报报告摘要生成"},
        {"value": ContentType.INTEL_BRIEF.value, "label": "情报简报", "description": "威胁情报简报生成"},
        {"value": ContentType.SECURITY_ADVICE.value, "label": "安全建议", "description": "安全防护建议生成"},
        {"value": ContentType.TREND_ANALYSIS.value, "label": "趋势分析", "description": "威胁趋势分析报告"},
        {"value": ContentType.THREAT_ASSESSMENT.value, "label": "威胁研判", "description": "威胁等级研判与风险评估报告"},
        {"value": ContentType.ATTACK_CHAIN_ANALYSIS.value, "label": "攻击链路分析", "description": "攻击手法链路还原与关联分析"},
        {"value": ContentType.THREAT_SITUATION_BRIEF.value, "label": "态势简报", "description": "黑灰产威胁态势周期性简报"},
        {"value": ContentType.HIGH_RISK_ALERT.value, "label": "高危预警", "description": "高危威胁预警通报"},
        {"value": ContentType.IOC_REPORT.value, "label": "IoC报告", "description": "失陷指标提取与关联报告"},
        {"value": ContentType.CRIME_PATTERN_ANALYSIS.value, "label": "犯罪模式分析", "description": "黑灰产犯罪模式识别与链路分析"},
    ]
    return {"types": types, "total": len(types)}


@router.get("/contents/{content_id}/versions")
async def get_content_versions(
    content_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(GeneratedContentTable).where(GeneratedContentTable.id == content_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="内容不存在")

    version_ids = [content_id]
    current_id = content_id
    for _ in range(50):
        child_result = await db.execute(
            select(GeneratedContentTable).where(GeneratedContentTable.parent_id == current_id)
        )
        child = child_result.scalar_one_or_none()
        if not child:
            break
        version_ids.append(child.id)
        current_id = child.id

    stmt = select(GeneratedContentTable).where(GeneratedContentTable.id.in_(version_ids))
    result = await db.execute(stmt.order_by(GeneratedContentTable.created_at.asc()))
    rows = result.scalars().all()

    versions = []
    for r in rows:
        versions.append({
            "id": r.id,
            "title": r.title,
            "content_type": r.content_type,
            "review_status": r.review_status,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "created_by": r.created_by,
            "parent_id": r.parent_id,
            "content_preview": r.content[:200] if r.content else "",
        })

    return {"content_id": content_id, "versions": versions, "total": len(versions)}


@router.post("/contents/{content_id}/create-version", status_code=201)
async def create_content_version(
    content_id: str,
    data: ContentUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(GeneratedContentTable).where(GeneratedContentTable.id == content_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="内容不存在")

    new_id = uuid.uuid4().hex
    update_data = data.model_dump(exclude_unset=True)

    source_refs_json = row.source_refs_json
    if "source_refs" in update_data and update_data["source_refs"] is not None:
        source_refs_json = json.dumps(update_data["source_refs"], ensure_ascii=False)

    new_row = GeneratedContentTable(
        id=new_id,
        title=update_data.get("title", row.title),
        content_type=row.content_type,
        content=update_data.get("content", row.content),
        review_status=ReviewStatus.PENDING.value,
        source_refs_json=source_refs_json,
        model_id=row.model_id,
        created_by=current_user.username if hasattr(current_user, "username") else "system",
        parent_id=content_id,
    )
    async with db_write(db, operation="创建内容版本"):
        db.add(new_row)
    await db.refresh(new_row)

    return {
        **_row_to_dict(new_row),
        "message": "内容版本已创建",
        "parent_id": content_id,
    }


@router.post("/contents/{content_id}/advance-review")
async def advance_review(
    content_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(GeneratedContentTable).where(GeneratedContentTable.id == content_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="内容不存在")

    workflow = _get_review_workflow(request)
    current_level = row.review_status
    new_status = None

    if current_level == ReviewStatus.PENDING.value:
        auto_result = workflow.auto_check(row.content_type, row.content)
        if auto_result["passed"]:
            new_status = "auto_checked"
        else:
            return {
                "content_id": content_id,
                "review_status": current_level,
                "message": "自动审核未通过，需要修改内容",
                "auto_check_result": auto_result,
            }
    elif current_level == "auto_checked":
        new_status = "expert_review"
    elif current_level == "expert_review":
        new_status = "supervisor_approved"
    elif current_level == ReviewStatus.REVISED.value:
        auto_result = workflow.auto_check(row.content_type, row.content)
        if auto_result["passed"]:
            new_status = "auto_checked"
        else:
            return {
                "content_id": content_id,
                "review_status": current_level,
                "message": "修改后自动审核仍未通过",
                "auto_check_result": auto_result,
            }
    else:
        raise HTTPException(status_code=400, detail=f"当前状态 {current_level} 无法推进审核")

    async with db_write(db, operation="推进审核"):
        row.review_status = new_status
    await db.refresh(row)

    return {
        "content_id": content_id,
        "review_status": row.review_status,
        "review_levels": workflow.get_review_levels(row.content_type),
        "message": f"审核已推进到: {row.review_status}",
    }


@router.post("/batch-review")
async def batch_review_content(
    data: BatchReviewRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(GeneratedContentTable).where(GeneratedContentTable.id.in_(data.content_ids))
    )
    rows = result.scalars().all()

    found_ids = {r.id for r in rows}
    missing_ids = [cid for cid in data.content_ids if cid not in found_ids]

    now = datetime.now(timezone.utc)
    reviewer = current_user.username if hasattr(current_user, "username") else "system"

    async with db_write(db, operation="批量审核内容"):
        for row in rows:
            row.review_status = data.review_status
            row.review_comment = data.review_comment
            row.reviewer = reviewer
            row.reviewed_at = now

    refreshed_items = []
    for row in rows:
        await db.refresh(row)
        refreshed_items.append(_row_to_dict(row))

    return {
        "total": len(data.content_ids),
        "updated_count": len(rows),
        "missing_ids": missing_ids,
        "items": refreshed_items,
    }


def _markdown_to_html(text: str) -> str:
    if not text:
        return ""
    html = text
    html = re.sub(r'^### (.+)$', r'<h3>\1</h3>', html, flags=re.MULTILINE)
    html = re.sub(r'^## (.+)$', r'<h2>\1</h2>', html, flags=re.MULTILINE)
    html = re.sub(r'^# (.+)$', r'<h1>\1</h1>', html, flags=re.MULTILINE)
    html = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', html)
    html = re.sub(r'\*(.+?)\*', r'<em>\1</em>', html)
    html = re.sub(r'^- (.+)$', r'<li>\1</li>', html, flags=re.MULTILINE)
    html = re.sub(r'(<li>[\s\S]*?</li>)', r'<ul>\1</ul>', html)
    paragraphs = html.split('\n\n')
    result = []
    for p in paragraphs:
        p = p.strip()
        if not p:
            continue
        if not any(p.startswith(tag) for tag in ['<h', '<ul', '<li']):
            p = f'<p>{p}</p>'
        result.append(p)
    return '\n'.join(result)


@router.post("/batch-generate", status_code=201)
async def batch_generate_content(
    request: Request,
    data: BatchGenerateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    results = []
    success_count = 0
    failure_count = 0
    generator = _get_content_generator(request)
    workflow = _get_review_workflow(request)

    async with db_write(db, operation="批量生成内容"):
        for idx, item in enumerate(data.items):
            try:
                async with db.begin_nested():
                    source_intel = await _collect_source_intelligence(item.source_refs)

                    validation = validate_domain_object("generated_content", item.model_dump())
                    if not validation.is_valid:
                        results.append({
                            "index": idx,
                            "title": item.title,
                            "status": "failed",
                            "error": {"errors": validation.errors, "warnings": validation.warnings},
                        })
                        failure_count += 1
                        continue

                    custom_prompt = None
                    if item.prompt_template_id:
                        try:
                            tmpl_result = await db.execute(
                                select(PromptTemplateTable).where(PromptTemplateTable.id == item.prompt_template_id)
                            )
                            tmpl_row = tmpl_result.scalar_one_or_none()
                            if tmpl_row:
                                custom_prompt = tmpl_row.content
                        except Exception as exc:
                            logger.warning(f"Load prompt template failed: {exc}")

                    doc = await generator.generate(
                        content_type=item.content_type.value,
                        title=item.title,
                        source_data=source_intel,
                        source_refs=item.source_refs,
                        template_id=item.prompt_template_id,
                        model_id=item.model_id,
                        custom_instructions=custom_prompt or item.context,
                    )

                    if data.auto_review:
                        auto_check_result = workflow.auto_check(item.content_type.value, doc.content)
                        if auto_check_result["passed"]:
                            review_status = "auto_checked"
                        else:
                            review_status = ReviewStatus.PENDING.value
                    else:
                        review_status = ReviewStatus.PENDING.value
                        auto_check_result = None

                    content_id = doc.doc_id
                    source_refs_json = json.dumps(doc.source_refs, ensure_ascii=False)

                    row = GeneratedContentTable(
                        id=content_id,
                        title=doc.title,
                        content_type=doc.content_type,
                        content=doc.content,
                        review_status=review_status,
                        source_refs_json=source_refs_json,
                        model_id=doc.model_id,
                        prompt_template_id=doc.template_id,
                        created_by=item.created_by,
                    )
                    db.add(row)
                    await db.flush()

                    item_result = _row_to_dict(row)
                    item_result["generation_meta"] = {
                        "word_count": doc.word_count,
                        "generation_time_ms": round(doc.generation_time_ms, 2),
                        "tokens_used": doc.tokens_used,
                    }
                    if auto_check_result:
                        item_result["auto_check"] = auto_check_result

                    results.append({
                        "index": idx,
                        "title": item.title,
                        "status": "success",
                        "data": item_result,
                    })
                    success_count += 1

            except Exception as exc:
                logger.error(f"Batch generate item {idx} failed: {exc}")
                results.append({
                    "index": idx,
                    "title": item.title,
                    "status": "failed",
                    "error": str(exc),
                })
                failure_count += 1

    return {
        "total": len(data.items),
        "success_count": success_count,
        "failure_count": failure_count,
        "results": results,
    }


@router.post("/contents/{content_id}/score")
async def score_content(
    content_id: str,
    data: ContentScoreRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(GeneratedContentTable).where(GeneratedContentTable.id == content_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="内容不存在")

    llm = getattr(request.app.state, "llm", None)
    if not llm:
        raise HTTPException(status_code=503, detail="LLM服务不可用，无法进行内容评分")

    dimensions_str = "、".join(data.dimensions)
    scoring_prompt = (
        f"请对以下威胁情报内容进行评分，评分维度为：{dimensions_str}。\n"
        f"每个维度按1-10分评分，1分最低，10分最高。\n"
        f'请以JSON格式返回评分结果，格式为：{{"scores": {{"维度名": 分数}}, "overall": 总分, "summary": "简要评价"}}\n\n'
        f"内容标题：{row.title}\n"
        f"内容类型：{row.content_type}\n"
        f"内容：\n{row.content[:3000]}"
    )

    dialogue_manager = getattr(request.app.state, "qa_dialogue_manager", None)
    if dialogue_manager is None:
        dialogue_manager = DialogueManager(llm_service=llm)
    try:
        response = await dialogue_manager.generate_response(
            messages=[{"role": "user", "content": scoring_prompt}],
            temperature=settings.LLM_TEMPERATURE_CREATIVE,
            max_tokens=settings.LLM_MAX_TOKENS_MEDIUM,
        )
        score_text = response.get("content", "")
        json_match = re.search(r'\{[\s\S]*\}', score_text)
        if json_match:
            score_data = json.loads(json_match.group())
        else:
            score_data = {"raw_response": score_text}
    except Exception as exc:
        logger.error(f"Content scoring failed: {exc}")
        raise HTTPException(status_code=500, detail=f"内容评分失败: {str(exc)[:200]}")

    return {
        "content_id": content_id,
        "title": row.title,
        "dimensions": data.dimensions,
        "scores": score_data.get("scores", {}),
        "overall": score_data.get("overall", 0),
        "summary": score_data.get("summary", ""),
        "model_used": response.get("model", "unknown") if isinstance(response, dict) else "unknown",
    }


@router.get("/contents/{content_id}/export")
async def export_content(
    content_id: str,
    format: str = Query("markdown", pattern=r"^(markdown|html|pdf|json)$"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(GeneratedContentTable).where(GeneratedContentTable.id == content_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="内容不存在")

    content_data = _row_to_dict(row)

    if format == "markdown":
        return {
            "content_id": content_id,
            "format": "markdown",
            "title": row.title,
            "content": row.content,
        }
    elif format == "html":
        html_body = _markdown_to_html(row.content or "")
        html_content = (
            f"<!DOCTYPE html>\n<html><head><meta charset='utf-8'>"
            f"<title>{row.title}</title></head>\n<body>\n"
            f"<h1>{row.title}</h1>\n{html_body}\n</body></html>"
        )
        return {
            "content_id": content_id,
            "format": "html",
            "title": row.title,
            "content": html_content,
        }
    elif format == "json":
        return {
            "content_id": content_id,
            "format": "json",
            "title": row.title,
            "content": content_data,
        }
    elif format == "pdf":
        raise HTTPException(status_code=501, detail="PDF导出功能需要安装额外的依赖库（如 weasyprint 或 reportlab）")


class ReportSummaryRequest(BaseModel):
    model_config = {"protected_namespaces": ()}
    title: str = Field(..., min_length=1, max_length=500)
    context: str = Field(..., min_length=1)
    data: Optional[Dict[str, Any]] = None


class IntelligenceBriefingRequest(BaseModel):
    model_config = {"protected_namespaces": ()}
    topics: List[str] = Field(..., min_length=1)
    time_range: str = Field("最近7天", max_length=50)


class SecurityAdviceRequest(BaseModel):
    model_config = {"protected_namespaces": ()}
    threat_type: str = Field(..., min_length=1, max_length=200)
    context: str = Field("", max_length=5000)


class TrendAnalysisRequest(BaseModel):
    model_config = {"protected_namespaces": ()}
    data_points: List[Dict[str, Any]] = Field(..., min_length=2)
    metric: str = Field("威胁指数", max_length=100)


@router.post("/report-summary")
async def generate_report_summary(
    data: ReportSummaryRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    generator = _get_content_generator(request)

    try:
        result = await generator.generate_report_summary(
            title=data.title,
            context=data.context,
            data=data.data,
        )
        return result
    except Exception as exc:
        logger.error(f"Report summary generation failed: {exc}")
        raise HTTPException(status_code=500, detail=f"报告摘要生成失败: {str(exc)[:200]}")


@router.post("/intelligence-briefing")
async def generate_intelligence_briefing(
    data: IntelligenceBriefingRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    generator = _get_content_generator(request)

    try:
        result = await generator.generate_intelligence_briefing(
            topics=data.topics,
            time_range=data.time_range,
        )
        return result
    except Exception as exc:
        logger.error(f"Intelligence briefing generation failed: {exc}")
        raise HTTPException(status_code=500, detail=f"情报简报生成失败: {str(exc)[:200]}")


@router.post("/security-advice")
async def generate_security_advice(
    data: SecurityAdviceRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    generator = _get_content_generator(request)

    try:
        result = await generator.generate_security_advice(
            threat_type=data.threat_type,
            context=data.context,
        )
        return result
    except Exception as exc:
        logger.error(f"Security advice generation failed: {exc}")
        raise HTTPException(status_code=500, detail=f"安全建议生成失败: {str(exc)[:200]}")


@router.post("/trend-analysis")
async def generate_trend_analysis(
    data: TrendAnalysisRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    generator = _get_content_generator(request)

    try:
        result = await generator.generate_trend_analysis(
            data_points=data.data_points,
            metric=data.metric,
        )
        return result
    except Exception as exc:
        logger.error(f"Trend analysis generation failed: {exc}")
        raise HTTPException(status_code=500, detail=f"趋势分析生成失败: {str(exc)[:200]}")
