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

router = APIRouter(prefix="/persona", tags=["persona"])


class PersonaAnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=50000)
    target_id: Optional[str] = Field(None, max_length=64)


def _analyze_persona_keywords(text: str) -> Dict[str, Any]:
    persona_traits = {
        "technical_sophistication": {
            "high": ["0day", "exploit", "逆向", "漏洞分析", "reverse engineering", "malware development"],
            "medium": ["脚本", "工具", "script", "tool", "自动化"],
            "low": ["教程", "新手", "beginner", "tutorial"],
        },
        "motivation": {
            "financial": ["出售", "交易", "价格", "sell", "price", "profit", "收益"],
            "ideological": ["主义", "信仰", "ideology", "belief", "cause"],
            "espionage": ["情报", "窃取", "espionage", "intelligence", "spy"],
            "disruption": ["破坏", "瘫痪", "disruption", "sabotage", "destruction"],
        },
        "operational_pattern": {
            "organized": ["组织", "团队", "APT", "group", "organized", "campaign"],
            "opportunistic": ["随机", "机会性", "opportunistic", "random"],
            "persistent": ["持续", "长期", "persistent", "long-term", "advanced persistent"],
        },
        "resource_level": {
            "high": ["国家级", "大量资源", "state-sponsored", "well-funded", "nation-state"],
            "medium": ["中等资源", "团队协作", "moderate", "team-based"],
            "low": ["个人", "独立", "individual", "solo", "lone wolf"],
        },
    }

    text_lower = text.lower()
    profile = {}

    for trait, levels in persona_traits.items():
        trait_result = {}
        for level, keywords in levels.items():
            matched = [kw for kw in keywords if kw in text_lower]
            if matched:
                trait_result[level] = {
                    "matched_keywords": matched,
                    "score": len(matched),
                }
        if trait_result:
            profile[trait] = trait_result

    dominant_traits = {}
    for trait, levels in profile.items():
        if levels:
            dominant = max(levels.items(), key=lambda x: x[1]["score"])
            dominant_traits[trait] = dominant[0]

    threat_level = "low"
    if dominant_traits.get("technical_sophistication") == "high":
        threat_level = "high"
    elif dominant_traits.get("technical_sophistication") == "medium":
        threat_level = "medium"
    if dominant_traits.get("resource_level") == "high":
        threat_level = "critical" if threat_level == "high" else "high"
    if dominant_traits.get("motivation") in ("espionage", "disruption"):
        threat_level = "high" if threat_level != "critical" else threat_level

    confidence = min(len(profile) * 0.15 + len(dominant_traits) * 0.1, 1.0)
    summary = "未检测到角色特征" if not profile else f"检测到{len(profile)}类角色特征，威胁等级: {threat_level}"

    recommendations = []
    if threat_level in ("critical", "high"):
        recommendations.append("建议提升监控等级，加强防御措施")
    if dominant_traits.get("operational_pattern") == "persistent":
        recommendations.append("检测到持续性威胁行为模式，建议进行长期跟踪")
    if dominant_traits.get("motivation") == "financial":
        recommendations.append("检测到经济动机，建议关注金融相关攻击面")
    if dominant_traits.get("motivation") == "espionage":
        recommendations.append("检测到间谍动机，建议加强敏感数据保护")
    if not recommendations:
        recommendations.append("建议持续监控角色行为变化")

    return {
        "profile": profile,
        "dominant_traits": dominant_traits,
        "threat_level": threat_level,
        "confidence": round(confidence, 4),
        "summary": summary,
        "recommendations": recommendations,
    }


async def _analyze_persona_llm(text: str, llm) -> Dict[str, Any]:
    prompt = (
        "你是一个黑灰产威胁行为者角色画像专家。请分析以下文本，推断威胁行为者的角色特征，"
        "包括以下4个维度：\n"
        "1. technical_sophistication（技术 sophistication）：high（0day/exploit/逆向/漏洞分析/malware development）、"
        "medium（脚本/工具/自动化）、low（教程/新手）\n"
        "2. motivation（动机）：financial（出售/交易/价格/收益）、ideological（主义/信仰）、"
        "espionage（情报/窃取/间谍）、disruption（破坏/瘫痪）\n"
        "3. operational_pattern（行为模式）：organized（组织/团队/APT/campaign）、"
        "opportunistic（随机/机会性）、persistent（持续/长期/advanced persistent）\n"
        "4. resource_level（资源水平）：high（国家级/大量资源/state-sponsored）、"
        "medium（中等资源/团队协作）、low（个人/独立/lone wolf）\n\n"
        "请返回严格JSON格式：\n"
        '{"profile": {"technical_sophistication": {"level": "high/medium/low", "evidence": "证据"}, '
        '"motivation": {"level": "financial/ideological/espionage/disruption", "evidence": "证据"}, '
        '"operational_pattern": {"level": "organized/opportunistic/persistent", "evidence": "证据"}, '
        '"resource_level": {"level": "high/medium/low", "evidence": "证据"}}, '
        '"dominant_traits": {"technical_sophistication": "主要等级", "motivation": "主要动机", '
        '"operational_pattern": "主要模式", "resource_level": "主要资源水平"}, '
        '"threat_level": "critical/high/medium/low", '
        '"confidence": 0.0-1.0, '
        '"summary": "中文摘要", '
        '"recommendations": ["建议1", "建议2"]}\n\n'
        "threat_level规则：technical_sophistication=high且resource_level=high时为critical；"
        "technical_sophistication=high为high；motivation为espionage或disruption提升等级。\n"
        "如果某个维度无法判断，可以省略该维度。\n\n"
        f"待分析文本：\n{text[:8000]}"
    )
    try:
        result = await llm.generate_json(
            prompt=prompt,
            system_prompt=DEEPSEEK_THREAT_INTEL_SYSTEM,
            temperature=settings.LLM_TEMPERATURE_ANALYSIS,
        )
        if not isinstance(result, dict) or "profile" not in result:
            raise ValueError("Invalid LLM response structure")
        result.setdefault("dominant_traits", {})
        result.setdefault("threat_level", "low")
        result.setdefault("confidence", 0.5)
        result.setdefault("summary", f"检测到角色特征，威胁等级: {result.get('threat_level', 'low')}")
        result.setdefault("recommendations", ["建议持续监控角色行为变化"])
        return result
    except Exception as exc:
        logger.warning(f"LLM persona analysis failed, falling back to keywords: {exc}")
        raise


@router.get("/personas")
async def list_persona_analyses(
    offset: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    status: Optional[str] = Query(None, max_length=32),
    current_user: User = Depends(get_current_user),
):
    try:
        async with async_session_factory() as session:
            q = select(AnalysisResultTable).where(AnalysisResultTable.analysis_type == "persona")
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
        logger.error(f"List persona analyses failed: {exc}")
        raise AppException(detail="获取角色建模列表失败", error_code="DATABASE_ERROR", status_code=500)


@router.post("/analyze")
async def create_persona_analysis(
    body: PersonaAnalyzeRequest,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    llm = getattr(request.app.state, "llm", None)
    model_name = "rule-based"
    analysis_result = None

    if llm and llm.is_available:
        try:
            analysis_result = await _analyze_persona_llm(body.text, llm)
            model_name = llm.model_name
        except Exception:
            analysis_result = None

    if analysis_result is None:
        analysis_result = _analyze_persona_keywords(body.text)

    row_id = uuid.uuid4().hex[:16]
    now = datetime.now(timezone.utc)

    try:
        async with async_session_factory() as session:
            row = AnalysisResultTable(
                id=row_id,
                analysis_type="persona",
                target_id=body.target_id or "",
                target_type="actor",
                result_summary=analysis_result["summary"],
                findings_json=json.dumps(analysis_result["profile"], ensure_ascii=False, default=str),
                iocs_json="[]",
                recommendations_json=json.dumps(analysis_result["recommendations"], ensure_ascii=False, default=str),
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
        logger.error(f"Create persona analysis failed: {exc}")
        raise AppException(detail="创建角色分析失败", error_code="DATABASE_ERROR", status_code=500)


@router.get("/statistics")
async def get_persona_statistics(
    current_user: User = Depends(get_current_user),
):
    try:
        async with async_session_factory() as session:
            total_result = await session.execute(
                select(func.count()).select_from(AnalysisResultTable).where(
                    AnalysisResultTable.analysis_type == "persona"
                )
            )
            total_count = total_result.scalar() or 0

            high_confidence_result = await session.execute(
                select(func.count()).select_from(AnalysisResultTable).where(
                    AnalysisResultTable.analysis_type == "persona",
                    AnalysisResultTable.confidence_score > 0.5,
                )
            )
            high_confidence_count = high_confidence_result.scalar() or 0

            avg_confidence_result = await session.execute(
                select(func.avg(AnalysisResultTable.confidence_score)).where(
                    AnalysisResultTable.analysis_type == "persona"
                )
            )
            avg_confidence = avg_confidence_result.scalar() or 0.0

            by_status_result = await session.execute(
                select(AnalysisResultTable.status, func.count())
                .where(AnalysisResultTable.analysis_type == "persona")
                .group_by(AnalysisResultTable.status)
            )
            by_status = {row[0]: row[1] for row in by_status_result.all()}

            trend_result = await session.execute(
                select(func.date(AnalysisResultTable.analyzed_at), func.count())
                .where(AnalysisResultTable.analysis_type == "persona")
                .group_by(func.date(AnalysisResultTable.analyzed_at))
                .order_by(func.date(AnalysisResultTable.analyzed_at))
                .limit(30)
            )
            trend_data = [{"date": str(row[0]), "count": row[1]} for row in trend_result.all()]

            return {
                "analysis_type": "persona",
                "total_count": total_count,
                "high_confidence_count": high_confidence_count,
                "avg_confidence": round(float(avg_confidence), 4),
                "by_status": by_status,
                "trend_data": trend_data,
            }
    except (AppException, NotFoundException):
        raise
    except Exception as exc:
        logger.error(f"Get persona statistics failed: {exc}")
        raise AppException(detail="获取角色建模统计失败", error_code="DATABASE_ERROR", status_code=500)
