from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from loguru import logger
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import User, get_current_user, require_role, Role
from app.db.crud import ReportCRUD
from app.db.database import get_db
from app.db.tables import RawIntelligenceTable
from app.models.report import Report, ReportStatus

router = APIRouter(prefix="/reports", tags=["reports"])


class ReportGenerateRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=256)
    pir_ids: List[str] = Field(default_factory=list)
    intelligence_ids: List[str] = Field(default_factory=list)
    context: Optional[str] = None


class ReportUpdateRequest(BaseModel):
    title: Optional[str] = None
    status: Optional[ReportStatus] = None
    summary: Optional[str] = None


@router.post("/generate")
async def generate_report(
    data: ReportGenerateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    crud = ReportCRUD(db)
    pir_id = data.pir_ids[0] if data.pir_ids else None
    report = Report(
        title=data.title,
        pir_id=pir_id,
    )
    result = await crud.create_report(report)
    await db.commit()

    task_id = ""
    try:
        from app.core.task_queue import task_queue
        task_id = await task_queue.submit(
            task_type="query",
            params={
                "query": f"生成报告: {data.title}",
                "context": {
                    "report_id": result.id,
                    "pir_ids": data.pir_ids,
                    "intelligence_ids": data.intelligence_ids,
                },
            },
        )
    except Exception as exc:
        logger.warning(f"Failed to trigger report generation task: {exc}")

    report_dict = result.model_dump()
    report_dict["task_id"] = task_id
    report_dict["report_type"] = "threat_summary"
    report_dict["content"] = result.summary or ""
    report_dict["sections"] = []
    report_dict["related_intelligence"] = []
    return report_dict


@router.get("")
async def list_reports(
    status: Optional[str] = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    crud = ReportCRUD(db)
    status_enum = None
    if status:
        try:
            status_enum = ReportStatus(status)
        except ValueError:
            pass
    items, total = await crud.list_reports(
        status=status_enum, offset=offset, limit=limit
    )
    await db.commit()
    result_items = []
    for r in items:
        rdict = r.model_dump()
        rdict["report_type"] = "threat_summary"
        rdict["content"] = r.summary or ""
        rdict["sections"] = []
        rdict["related_intelligence"] = []
        result_items.append(rdict)
    return {
        "items": result_items,
        "total": total,
        "offset": offset,
        "limit": limit,
    }


@router.get("/{report_id}")
async def get_report(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    crud = ReportCRUD(db)
    result = await crud.get_report(report_id)
    if result is None:
        raise HTTPException(status_code=404, detail="报告未找到")
    report_dict = result.model_dump()
    report_dict["report_type"] = "threat_summary"
    report_dict["content"] = result.summary or ""
    report_dict["sections"] = []
    report_dict["related_intelligence"] = []
    return report_dict


@router.patch("/{report_id}")
async def update_report(
    report_id: str,
    data: ReportUpdateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    crud = ReportCRUD(db)
    updates = data.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(status_code=400, detail="没有需要更新的字段")
    result = await crud.update_report(report_id, **updates)
    if result is None:
        raise HTTPException(status_code=404, detail="报告未找到")
    await db.commit()
    report_dict = result.model_dump()
    report_dict["report_type"] = "threat_summary"
    report_dict["content"] = result.summary or ""
    return report_dict


@router.delete("/{report_id}", status_code=204)
async def delete_report(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    crud = ReportCRUD(db)
    deleted = await crud.delete_report(report_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="报告未找到")
    await db.commit()


@router.post("/{report_id}/export")
async def export_report(
    report_id: str,
    format: str = "markdown",
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    crud = ReportCRUD(db)
    report = await crud.get_report(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="报告未找到")

    content = report.summary or ""
    title = report.title or "未命名报告"

    if format == "markdown":
        export_content = f"# {title}\n\n{content}"
    elif format == "html":
        export_content = f"<html><head><title>{title}</title></head><body><h1>{title}</h1><div>{content}</div></body></html>"
    else:
        export_content = content

    return {
        "report_id": report_id,
        "title": title,
        "format": format,
        "content": export_content,
    }


@router.post("/auto-generate")
async def auto_generate_reports(
    request: Request,
    limit: int = 5,
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
    db: AsyncSession = Depends(get_db),
):
    report_gen = getattr(request.app.state, 'report_generator', None)
    if report_gen is None:
        try:
            from app.core.report_generator import ReportGenerator
            llm = request.app.state.llm
            vector_store = request.app.state.vector_store
            report_gen = ReportGenerator(llm=llm, vector_store=vector_store)
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"Report generator not available: {exc}")
    try:
        result = await db.execute(
            select(RawIntelligenceTable).order_by(RawIntelligenceTable.collected_at.desc()).limit(limit * 10)
        )
        intels = result.scalars().all()

        import json
        from app.db.tables import ReportTable
        from datetime import datetime
        generated = []
        for i in range(0, len(intels), 10):
            batch = intels[i:i+10]
            if not batch:
                break
            context_parts = [f"[{j}] source={intel.source}: {(intel.content or '')[:200]}" for j, intel in enumerate(batch)]
            context = "\n".join(context_parts)
            title = f"情报分析报告 - 批次{len(generated)+1}"
            try:
                report = await report_gen.generate_report(title=title, context=context)
                generated.append({"id": report.id, "title": report.title, "confidence": report.confidence_score})
            except Exception as exc:
                logger.warning(f"Auto-generate report batch {len(generated)+1} failed: {exc}")
            if len(generated) >= limit:
                break
        return {"generated": len(generated), "reports": generated}
    except Exception as exc:
        raise HTTPException(status_code=500, detail="报告生成失败")
