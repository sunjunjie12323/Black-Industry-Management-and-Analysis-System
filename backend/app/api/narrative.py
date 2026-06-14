import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query, Request
from loguru import logger
from pydantic import BaseModel, Field
from sqlalchemy import func, select, desc

from app.config import settings
from app.core.auth import User, get_current_user, require_role, Role
from app.core.exceptions import AppException, NotFoundException
from app.core.llm import DEEPSEEK_THREAT_INTEL_SYSTEM
from app.db.database import async_session_factory
from app.db.tables import AnalysisResultTable
from app.utils.db_helpers import row_to_dict

router = APIRouter(prefix="/narrative", tags=["narrative"])


import os

NARRATIVE_KEYWORDS = {
    "propaganda": ["宣传", "洗脑", "舆论导向", "信息战", "认知作战", "propaganda", "narrative warfare"],
    "fear_appeal": ["恐慌", "威胁", "危险", "紧急", "fear", "urgent", "crisis"],
    "us_vs_them": ["我们vs他们", "敌对势力", "境外势力", "us vs them", "enemy"],
    "emotion_manipulation": ["愤怒", "仇恨", "民族情绪", "emotional manipulation", "outrage"],
    "disinformation": ["谣言", "假消息", "虚假信息", "disinformation", "fake news"],
}

_env_keywords = os.environ.get("NARRATIVE_KEYWORDS_JSON")
if _env_keywords:
    try:
        _override = json.loads(_env_keywords)
        if isinstance(_override, dict):
            NARRATIVE_KEYWORDS.update(_override)
    except (json.JSONDecodeError, TypeError):
        pass


class NarrativeAnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=50000)
    target_id: Optional[str] = Field(None, max_length=64)


def _analyze_narrative_patterns_keywords(text: str) -> Dict[str, Any]:
    text_lower = text.lower()
    detected_patterns = []
    for pattern_type, keywords in NARRATIVE_KEYWORDS.items():
        matched = [kw for kw in keywords if kw in text_lower]
        if matched:
            detected_patterns.append({
                "pattern": pattern_type,
                "matched_keywords": matched,
                "match_count": len(matched),
            })

    confidence = min(len(detected_patterns) * 0.2, 1.0) if detected_patterns else 0.0

    summary = "未检测到明显叙事模式" if not detected_patterns else f"检测到{len(detected_patterns)}种叙事模式"

    return {
        "detected_patterns": detected_patterns,
        "pattern_count": len(detected_patterns),
        "confidence": round(confidence, 4),
        "summary": summary,
    }


async def _analyze_narrative_patterns_llm(text: str, llm) -> Dict[str, Any]:
    prompt = (
        "你是一个叙事模式分析专家，专注于黑灰产威胁情报领域。请分析以下文本中是否存在叙事操纵模式，"
        "包括以下5种类型：\n"
        "1. propaganda（宣传叙事）：系统性宣传、洗脑、舆论导向、信息战、认知作战\n"
        "2. fear_appeal（恐惧诉求）：制造恐慌、夸大威胁、渲染危机\n"
        "3. us_vs_them（对立叙事）：制造我们vs他们的对立、敌我划分、境外势力论\n"
        "4. emotion_manipulation（情绪操纵）：煽动愤怒、仇恨、民族情绪\n"
        "5. disinformation（虚假信息）：传播谣言、假消息、虚假信息\n\n"
        "请返回严格JSON格式：\n"
        '{"detected_patterns": [{"pattern": "类型名", "evidence": "文本中的具体证据", '
        '"match_count": 匹配的证据数量}], '
        '"pattern_count": 检测到的模式数量, '
        '"confidence": 0.0-1.0的置信度, '
        '"summary": "中文摘要"}\n\n'
        "如果未检测到任何叙事模式，detected_patterns返回空数组。\n\n"
        f"待分析文本：\n{text[:8000]}"
    )
    try:
        result = await llm.generate_json(
            prompt=prompt,
            system_prompt=DEEPSEEK_THREAT_INTEL_SYSTEM,
            temperature=settings.LLM_TEMPERATURE_ANALYSIS,
        )
        if not isinstance(result, dict) or "detected_patterns" not in result:
            raise ValueError("Invalid LLM response structure")
        result.setdefault("pattern_count", len(result.get("detected_patterns", [])))
        result.setdefault("confidence", round(min(len(result.get("detected_patterns", [])) * 0.2, 1.0), 4))
        result.setdefault("summary", f"检测到{len(result.get('detected_patterns', []))}种叙事模式" if result.get("detected_patterns") else "未检测到明显叙事模式")
        for pat in result.get("detected_patterns", []):
            pat.setdefault("match_count", 1)
        return result
    except Exception as exc:
        logger.warning(f"LLM narrative analysis failed, falling back to keywords: {exc}")
        raise


@router.get("/analyses")
async def list_narrative_analyses(
    offset: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    status: Optional[str] = Query(None, max_length=32),
    current_user: User = Depends(get_current_user),
):
    try:
        async with async_session_factory() as session:
            q = select(AnalysisResultTable).where(AnalysisResultTable.analysis_type == "narrative")
            if status:
                q = q.where(AnalysisResultTable.status == status)

            count_q = select(func.count()).select_from(q.subquery())
            total_result = await session.execute(count_q)
            total = total_result.scalar() or 0

            q = q.order_by(desc(AnalysisResultTable.analyzed_at)).offset(offset).limit(limit)
            result = await session.execute(q)
            rows = result.scalars().all()

            items = [row_to_dict(r) for r in rows]
            return {"items": items, "total": total, "offset": offset, "limit": limit}
    except (AppException, NotFoundException):
        raise
    except Exception as exc:
        logger.error(f"List narrative analyses failed: {exc}")
        raise AppException(detail="获取叙事分析列表失败", error_code="DATABASE_ERROR", status_code=500)


@router.get("/analyses/{analysis_id}")
async def get_narrative_analysis(
    analysis_id: str,
    current_user: User = Depends(get_current_user),
):
    try:
        async with async_session_factory() as session:
            result = await session.execute(
                select(AnalysisResultTable).where(
                    AnalysisResultTable.id == analysis_id,
                    AnalysisResultTable.analysis_type == "narrative",
                )
            )
            row = result.scalar_one_or_none()
            if not row:
                raise NotFoundException(detail="叙事分析结果未找到")
            return row_to_dict(row)
    except (AppException, NotFoundException):
        raise
    except Exception as exc:
        logger.error(f"Get narrative analysis failed: {exc}")
        raise AppException(detail="获取叙事分析详情失败", error_code="DATABASE_ERROR", status_code=500)


@router.post("/analyze")
async def create_narrative_analysis(
    body: NarrativeAnalyzeRequest,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    llm = getattr(request.app.state, "llm", None)
    model_name = "rule-based"
    analysis_result = None

    if llm and llm.is_available:
        try:
            analysis_result = await _analyze_narrative_patterns_llm(body.text, llm)
            model_name = llm.model_name
        except Exception:
            analysis_result = None

    if analysis_result is None:
        analysis_result = _analyze_narrative_patterns_keywords(body.text)

    row_id = uuid.uuid4().hex[:16]
    now = datetime.now(timezone.utc)

    try:
        async with async_session_factory() as session:
            row = AnalysisResultTable(
                id=row_id,
                analysis_type="narrative",
                target_id=body.target_id or "",
                target_type="text",
                result_summary=analysis_result["summary"],
                findings_json=json.dumps(analysis_result["detected_patterns"], ensure_ascii=False, default=str),
                iocs_json="[]",
                recommendations_json="[]",
                result_data_json=json.dumps(analysis_result, ensure_ascii=False, default=str),
                confidence_score=analysis_result["confidence"],
                status="completed",
                input_content=body.text[:5000],
                model_name=model_name,
                analyzed_at=now,
                created_at=now,
                updated_at=now,
            )
            session.add(row)
            await session.commit()
            await session.refresh(row)
            return row_to_dict(row)
    except (AppException, NotFoundException):
        raise
    except Exception as exc:
        logger.error(f"Create narrative analysis failed: {exc}")
        raise AppException(detail="创建叙事分析失败", error_code="DATABASE_ERROR", status_code=500)


@router.get("/statistics")
async def get_narrative_statistics(
    current_user: User = Depends(get_current_user),
):
    try:
        async with async_session_factory() as session:
            total_result = await session.execute(
                select(func.count()).select_from(AnalysisResultTable).where(
                    AnalysisResultTable.analysis_type == "narrative"
                )
            )
            total_count = total_result.scalar() or 0

            high_confidence_result = await session.execute(
                select(func.count()).select_from(AnalysisResultTable).where(
                    AnalysisResultTable.analysis_type == "narrative",
                    AnalysisResultTable.confidence_score > 0.5,
                )
            )
            high_confidence_count = high_confidence_result.scalar() or 0

            avg_confidence_result = await session.execute(
                select(func.avg(AnalysisResultTable.confidence_score)).where(
                    AnalysisResultTable.analysis_type == "narrative"
                )
            )
            avg_confidence = avg_confidence_result.scalar() or 0.0

            by_status_result = await session.execute(
                select(AnalysisResultTable.status, func.count())
                .where(AnalysisResultTable.analysis_type == "narrative")
                .group_by(AnalysisResultTable.status)
            )
            by_status = {row[0]: row[1] for row in by_status_result.all()}

            trend_result = await session.execute(
                select(func.date(AnalysisResultTable.analyzed_at), func.count())
                .where(AnalysisResultTable.analysis_type == "narrative")
                .group_by(func.date(AnalysisResultTable.analyzed_at))
                .order_by(func.date(AnalysisResultTable.analyzed_at))
                .limit(30)
            )
            trend_data = [{"date": str(row[0]), "count": row[1]} for row in trend_result.all()]

            return {
                "analysis_type": "narrative",
                "total_count": total_count,
                "high_confidence_count": high_confidence_count,
                "avg_confidence": round(float(avg_confidence), 4),
                "by_status": by_status,
                "trend_data": trend_data,
            }
    except (AppException, NotFoundException):
        raise
    except Exception as exc:
        logger.error(f"Get narrative statistics failed: {exc}")
        raise AppException(detail="获取叙事分析统计失败", error_code="DATABASE_ERROR", status_code=500)
