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

router = APIRouter(prefix="/deception", tags=["deception"])


class DeceptionDetectRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=50000)
    target_id: Optional[str] = Field(None, max_length=64)


def _detect_deception_keywords(text: str) -> Dict[str, Any]:
    deception_indicators = {
        "credential_phishing": ["密码", "账号", "验证", "登录", "password", "credential", "phishing", "钓鱼"],
        "social_engineering": ["冒充", "伪装", "身份伪造", "impersonation", "social engineering", "社工"],
        "financial_fraud": ["转账", "汇款", "投资回报", "理财", "fraud", "scam", "诈骗"],
        "identity_theft": ["身份证", "银行卡", "个人信息", "identity theft", "身份盗用"],
        "manipulation": ["紧急", "限时", "最后机会", "urgency", "limited time", "last chance"],
    }

    text_lower = text.lower()
    detected_indicators = []
    for indicator_type, keywords in deception_indicators.items():
        matched = [kw for kw in keywords if kw in text_lower]
        if matched:
            detected_indicators.append({
                "indicator": indicator_type,
                "matched_keywords": matched,
                "severity": "high" if indicator_type in ("credential_phishing", "financial_fraud") else "medium",
            })

    confidence = min(len(detected_indicators) * 0.25, 1.0) if detected_indicators else 0.0
    summary = "未检测到欺骗指标" if not detected_indicators else f"检测到{len(detected_indicators)}种欺骗指标"

    recommendations = []
    if detected_indicators:
        for ind in detected_indicators:
            if ind["indicator"] == "credential_phishing":
                recommendations.append("建议加强凭据保护，启用多因素认证")
            elif ind["indicator"] == "financial_fraud":
                recommendations.append("建议进行金融风险预警，通知相关用户")
            elif ind["indicator"] == "social_engineering":
                recommendations.append("建议进行身份验证核查")
            elif ind["indicator"] == "identity_theft":
                recommendations.append("建议加强个人信息保护措施")
            elif ind["indicator"] == "manipulation":
                recommendations.append("建议标记为操纵性内容，提高用户警觉")

    return {
        "detected_indicators": detected_indicators,
        "indicator_count": len(detected_indicators),
        "confidence": round(confidence, 4),
        "summary": summary,
        "recommendations": recommendations,
    }


async def _detect_deception_llm(text: str, llm) -> Dict[str, Any]:
    prompt = (
        "你是一个黑灰产欺骗检测专家。请分析以下文本中是否存在欺骗性指标，"
        "包括以下5种类型：\n"
        "1. credential_phishing（凭据钓鱼）：诱导用户提供密码、账号等凭据\n"
        "2. social_engineering（社会工程学）：冒充身份、伪装权威进行欺骗\n"
        "3. financial_fraud（金融诈骗）：涉及转账、汇款、虚假投资等经济诈骗\n"
        "4. identity_theft（身份盗用）：窃取身份证、银行卡、个人信息等\n"
        "5. manipulation（心理操纵）：利用紧急、限时、最后机会等制造紧迫感\n\n"
        "请返回严格JSON格式：\n"
        '{"detected_indicators": [{"indicator": "类型名", "evidence": "文本中的具体证据", '
        '"severity": "high/medium/low"}], '
        '"indicator_count": 检测到的指标数量, '
        '"confidence": 0.0-1.0的置信度, '
        '"summary": "中文摘要", '
        '"recommendations": ["建议1", "建议2"]}\n\n'
        "如果未检测到任何欺骗指标，返回空数组。severity规则："
        "credential_phishing和financial_fraud默认high，其他默认medium。\n\n"
        f"待分析文本：\n{text[:8000]}"
    )
    try:
        result = await llm.generate_json(
            prompt=prompt,
            system_prompt=DEEPSEEK_THREAT_INTEL_SYSTEM,
            temperature=settings.LLM_TEMPERATURE_ANALYSIS,
        )
        if not isinstance(result, dict) or "detected_indicators" not in result:
            raise ValueError("Invalid LLM response structure")
        result.setdefault("indicator_count", len(result.get("detected_indicators", [])))
        result.setdefault("confidence", round(min(len(result.get("detected_indicators", [])) * 0.25, 1.0), 4))
        result.setdefault("summary", f"检测到{len(result.get('detected_indicators', []))}种欺骗指标")
        result.setdefault("recommendations", [])
        for ind in result.get("detected_indicators", []):
            ind.setdefault("severity", "high" if ind.get("indicator") in ("credential_phishing", "financial_fraud") else "medium")
        return result
    except Exception as exc:
        logger.warning(f"LLM deception detection failed, falling back to keywords: {exc}")
        raise


@router.get("/detections")
async def list_deception_detections(
    offset: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    status: Optional[str] = Query(None, max_length=32),
    current_user: User = Depends(get_current_user),
):
    try:
        async with async_session_factory() as session:
            q = select(AnalysisResultTable).where(AnalysisResultTable.analysis_type == "deception")
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
        logger.error(f"List deception detections failed: {exc}")
        raise AppException(detail="获取欺骗检测列表失败", error_code="DATABASE_ERROR", status_code=500)


@router.get("/detections/{detection_id}")
async def get_deception_detection(
    detection_id: str,
    current_user: User = Depends(get_current_user),
):
    try:
        async with async_session_factory() as session:
            result = await session.execute(
                select(AnalysisResultTable).where(
                    AnalysisResultTable.id == detection_id,
                    AnalysisResultTable.analysis_type == "deception",
                )
            )
            row = result.scalar_one_or_none()
            if not row:
                raise NotFoundException(detail="欺骗检测结果未找到")
            return row_to_dict(row)
    except (AppException, NotFoundException):
        raise
    except Exception as exc:
        logger.error(f"Get deception detection failed: {exc}")
        raise AppException(detail="获取欺骗检测详情失败", error_code="DATABASE_ERROR", status_code=500)


@router.post("/detect")
async def create_deception_detection(
    body: DeceptionDetectRequest,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    llm = getattr(request.app.state, "llm", None)
    model_name = "rule-based"
    detection_result = None

    if llm and llm.is_available:
        try:
            detection_result = await _detect_deception_llm(body.text, llm)
            model_name = llm.model_name
        except Exception:
            detection_result = None

    if detection_result is None:
        detection_result = _detect_deception_keywords(body.text)

    row_id = uuid.uuid4().hex[:16]
    now = datetime.now(timezone.utc)

    try:
        async with async_session_factory() as session:
            row = AnalysisResultTable(
                id=row_id,
                analysis_type="deception",
                target_id=body.target_id or "",
                target_type="text",
                result_summary=detection_result["summary"],
                findings_json=json.dumps(detection_result["detected_indicators"], ensure_ascii=False, default=str),
                iocs_json="[]",
                recommendations_json=json.dumps(detection_result["recommendations"], ensure_ascii=False, default=str),
                result_data_json=json.dumps(detection_result, ensure_ascii=False, default=str),
                confidence_score=detection_result["confidence"],
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
        logger.error(f"Create deception detection failed: {exc}")
        raise AppException(detail="创建欺骗检测失败", error_code="DATABASE_ERROR", status_code=500)


@router.get("/statistics")
async def get_deception_statistics(
    current_user: User = Depends(get_current_user),
):
    try:
        async with async_session_factory() as session:
            total_result = await session.execute(
                select(func.count()).select_from(AnalysisResultTable).where(
                    AnalysisResultTable.analysis_type == "deception"
                )
            )
            total_count = total_result.scalar() or 0

            high_confidence_result = await session.execute(
                select(func.count()).select_from(AnalysisResultTable).where(
                    AnalysisResultTable.analysis_type == "deception",
                    AnalysisResultTable.confidence_score > 0.5,
                )
            )
            high_confidence_count = high_confidence_result.scalar() or 0

            avg_confidence_result = await session.execute(
                select(func.avg(AnalysisResultTable.confidence_score)).where(
                    AnalysisResultTable.analysis_type == "deception"
                )
            )
            avg_confidence = avg_confidence_result.scalar() or 0.0

            by_status_result = await session.execute(
                select(AnalysisResultTable.status, func.count())
                .where(AnalysisResultTable.analysis_type == "deception")
                .group_by(AnalysisResultTable.status)
            )
            by_status = {row[0]: row[1] for row in by_status_result.all()}

            trend_result = await session.execute(
                select(func.date(AnalysisResultTable.analyzed_at), func.count())
                .where(AnalysisResultTable.analysis_type == "deception")
                .group_by(func.date(AnalysisResultTable.analyzed_at))
                .order_by(func.date(AnalysisResultTable.analyzed_at))
                .limit(30)
            )
            trend_data = [{"date": str(row[0]), "count": row[1]} for row in trend_result.all()]

            return {
                "analysis_type": "deception",
                "total_count": total_count,
                "high_confidence_count": high_confidence_count,
                "avg_confidence": round(float(avg_confidence), 4),
                "by_status": by_status,
                "trend_data": trend_data,
            }
    except (AppException, NotFoundException):
        raise
    except Exception as exc:
        logger.error(f"Get deception statistics failed: {exc}")
        raise AppException(detail="获取欺骗检测统计失败", error_code="DATABASE_ERROR", status_code=500)
