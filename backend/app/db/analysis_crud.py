import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import func, select, desc, asc
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.tables import AnalysisResultTable
from loguru import logger


class AnalysisResultCRUD:
    @staticmethod
    async def create(session: AsyncSession, data: Dict[str, Any]) -> AnalysisResultTable:
        if "findings" in data:
            data["findings_json"] = json.dumps(data.pop("findings"), ensure_ascii=False, default=str)
        if "iocs" in data:
            data["iocs_json"] = json.dumps(data.pop("iocs"), ensure_ascii=False, default=str)
        if "recommendations" in data:
            data["recommendations_json"] = json.dumps(data.pop("recommendations"), ensure_ascii=False, default=str)
        if "result_data" in data:
            data["result_data_json"] = json.dumps(data.pop("result_data"), ensure_ascii=False, default=str)
        if "id" not in data:
            data["id"] = uuid.uuid4().hex[:16]
        row = AnalysisResultTable(**data)
        session.add(row)
        await session.commit()
        await session.refresh(row)
        return row

    @staticmethod
    async def bulk_create(session: AsyncSession, items: List[Dict[str, Any]]) -> List[AnalysisResultTable]:
        rows = []
        for data in items:
            if "findings" in data:
                data["findings_json"] = json.dumps(data.pop("findings"), ensure_ascii=False, default=str)
            if "iocs" in data:
                data["iocs_json"] = json.dumps(data.pop("iocs"), ensure_ascii=False, default=str)
            if "recommendations" in data:
                data["recommendations_json"] = json.dumps(data.pop("recommendations"), ensure_ascii=False, default=str)
            if "result_data" in data:
                data["result_data_json"] = json.dumps(data.pop("result_data"), ensure_ascii=False, default=str)
            if "id" not in data:
                data["id"] = uuid.uuid4().hex[:16]
            rows.append(AnalysisResultTable(**data))
        session.add_all(rows)
        await session.commit()
        return rows

    @staticmethod
    async def get_by_id(session: AsyncSession, result_id: str) -> Optional[AnalysisResultTable]:
        result = await session.execute(select(AnalysisResultTable).where(AnalysisResultTable.id == result_id))
        return result.scalars().first()

    @staticmethod
    async def list_by_type(session: AsyncSession, analysis_type: str, limit: int = 20, offset: int = 0, status: Optional[str] = None) -> tuple:
        q = select(AnalysisResultTable).where(AnalysisResultTable.analysis_type == analysis_type)
        if status:
            q = q.where(AnalysisResultTable.status == status)
        total_result = await session.execute(select(func.count()).select_from(q.subquery()))
        total = total_result.scalar() or 0
        q = q.order_by(desc(AnalysisResultTable.analyzed_at)).limit(limit).offset(offset)
        result = await session.execute(q)
        return result.scalars().all(), total

    @staticmethod
    async def list_all(session: AsyncSession, limit: int = 20, offset: int = 0, analysis_type: Optional[str] = None, status: Optional[str] = None, target_id: Optional[str] = None, sort_by: str = "analyzed_at", sort_order: str = "desc") -> tuple:
        q = select(AnalysisResultTable)
        if analysis_type:
            q = q.where(AnalysisResultTable.analysis_type == analysis_type)
        if status:
            q = q.where(AnalysisResultTable.status == status)
        if target_id:
            q = q.where(AnalysisResultTable.target_id == target_id)
        total_result = await session.execute(select(func.count()).select_from(q.subquery()))
        total = total_result.scalar() or 0
        sort_col = getattr(AnalysisResultTable, sort_by, AnalysisResultTable.analyzed_at)
        q = q.order_by(desc(sort_col) if sort_order == "desc" else asc(sort_col)).limit(limit).offset(offset)
        result = await session.execute(q)
        return result.scalars().all(), total

    @staticmethod
    async def get_stats(session: AsyncSession) -> Dict[str, Any]:
        total_result = await session.execute(select(func.count()).select_from(AnalysisResultTable))
        total_count = total_result.scalar() or 0
        by_type_result = await session.execute(
            select(AnalysisResultTable.analysis_type, func.count()).group_by(AnalysisResultTable.analysis_type)
        )
        by_type = {row[0]: row[1] for row in by_type_result.all()}
        by_status_result = await session.execute(
            select(AnalysisResultTable.status, func.count()).group_by(AnalysisResultTable.status)
        )
        by_status = {row[0]: row[1] for row in by_status_result.all()}
        avg_result = await session.execute(select(func.avg(AnalysisResultTable.confidence_score)))
        avg_confidence = avg_result.scalar() or 0.0
        return {
            "total_count": total_count,
            "by_type": by_type,
            "by_status": by_status,
            "avg_confidence": round(float(avg_confidence), 4),
        }

    @staticmethod
    async def get_type_stats(session: AsyncSession, analysis_type: str) -> Dict[str, Any]:
        total_result = await session.execute(
            select(func.count()).select_from(AnalysisResultTable).where(AnalysisResultTable.analysis_type == analysis_type)
        )
        total_count = total_result.scalar() or 0
        detection_result = await session.execute(
            select(func.count()).select_from(AnalysisResultTable).where(
                AnalysisResultTable.analysis_type == analysis_type,
                AnalysisResultTable.confidence_score > 0.5,
            )
        )
        detection_count = detection_result.scalar() or 0
        avg_result = await session.execute(
            select(func.avg(AnalysisResultTable.confidence_score)).where(AnalysisResultTable.analysis_type == analysis_type)
        )
        avg_confidence = avg_result.scalar() or 0.0
        last_result = await session.execute(
            select(AnalysisResultTable.analyzed_at)
            .where(AnalysisResultTable.analysis_type == analysis_type)
            .order_by(desc(AnalysisResultTable.analyzed_at))
            .limit(1)
        )
        last_analyzed_at = last_result.scalar()
        trend_result = await session.execute(
            select(func.date(AnalysisResultTable.analyzed_at), func.count())
            .where(AnalysisResultTable.analysis_type == analysis_type)
            .group_by(func.date(AnalysisResultTable.analyzed_at))
            .order_by(func.date(AnalysisResultTable.analyzed_at))
            .limit(30)
        )
        trend_data = [{"date": str(row[0]), "count": row[1]} for row in trend_result.all()]
        return {
            "analysis_type": analysis_type,
            "total_count": total_count,
            "detection_count": detection_count,
            "avg_confidence": round(float(avg_confidence), 4),
            "trend_data": trend_data,
            "last_analyzed_at": last_analyzed_at,
        }

    @staticmethod
    async def get_since(session: AsyncSession, since: datetime) -> List[AnalysisResultTable]:
        result = await session.execute(
            select(AnalysisResultTable).where(AnalysisResultTable.analyzed_at >= since).order_by(desc(AnalysisResultTable.analyzed_at))
        )
        return result.scalars().all()

    @staticmethod
    async def update_status(session: AsyncSession, result_id: str, status: str, error_message: Optional[str] = None) -> Optional[AnalysisResultTable]:
        row = await AnalysisResultCRUD.get_by_id(session, result_id)
        if row:
            row.status = status
            if error_message:
                row.error_message = error_message
            await session.commit()
            await session.refresh(row)
        return row

    @staticmethod
    async def get_last_analyzed_time(session: AsyncSession) -> Optional[datetime]:
        result = await session.execute(
            select(func.max(AnalysisResultTable.analyzed_at))
        )
        return result.scalar()

    @staticmethod
    def to_response_dict(row: AnalysisResultTable) -> Dict[str, Any]:
        findings = []
        iocs = []
        recommendations = []
        result_data = {}
        try:
            findings = json.loads(row.findings_json) if row.findings_json else []
        except (json.JSONDecodeError, TypeError):
            pass
        try:
            iocs = json.loads(row.iocs_json) if row.iocs_json else []
        except (json.JSONDecodeError, TypeError):
            pass
        try:
            recommendations = json.loads(row.recommendations_json) if row.recommendations_json else []
        except (json.JSONDecodeError, TypeError):
            pass
        try:
            result_data = json.loads(row.result_data_json) if row.result_data_json else {}
        except (json.JSONDecodeError, TypeError):
            pass
        return {
            "id": row.id,
            "analysis_type": row.analysis_type,
            "target_id": row.target_id,
            "target_type": row.target_type,
            "result_summary": row.result_summary,
            "findings": findings,
            "iocs": iocs,
            "recommendations": recommendations,
            "result_data": result_data,
            "confidence_score": row.confidence_score,
            "status": row.status,
            "error_message": row.error_message,
            "llm_tokens_used": row.llm_tokens_used,
            "input_content": row.input_content,
            "model_name": row.model_name,
            "analyzed_at": row.analyzed_at,
            "created_at": row.created_at,
        }
