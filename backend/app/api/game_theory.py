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

router = APIRouter(prefix="/game-theory", tags=["game-theory"])


class GameTheoryAnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=50000)
    target_id: Optional[str] = Field(None, max_length=64)
    scenario_type: Optional[str] = Field(None, max_length=32)


def _analyze_game_theory_keywords(text: str, scenario_type: Optional[str] = None) -> Dict[str, Any]:
    game_scenarios = {
        "zero_sum": ["零和博弈", "对抗", "攻防", "zero-sum", "adversarial", "offense vs defense"],
        "non_zero_sum": ["合作", "共赢", "non-zero-sum", "cooperative", "collaboration"],
        "nash_equilibrium": ["均衡", "纳什均衡", "策略平衡", "nash equilibrium", "strategic balance"],
        "prisoner_dilemma": ["囚徒困境", "信任博弈", "prisoner", "dilemma", "trust game"],
        "signaling_game": ["信号", "伪装", "信息不对称", "signaling", "asymmetric information"],
        "stackelberg": ["领导者", "跟随者", "先手优势", "stackelberg", "leader-follower"],
    }

    text_lower = text.lower()
    detected_scenarios = []
    for scenario, keywords in game_scenarios.items():
        matched = [kw for kw in keywords if kw in text_lower]
        if matched:
            detected_scenarios.append({
                "scenario": scenario,
                "matched_keywords": matched,
                "relevance": "high" if len(matched) >= 2 else "medium",
            })

    primary_scenario = scenario_type
    if not primary_scenario and detected_scenarios:
        primary_scenario = detected_scenarios[0]["scenario"]

    players = []
    attacker_keywords = ["攻击者", "黑客", "APT", "attacker", "hacker", "threat actor"]
    defender_keywords = ["防御者", "安全团队", "defender", "security team", "blue team"]
    for kw in attacker_keywords:
        if kw in text_lower:
            players.append({"role": "attacker", "indicator": kw})
            break
    for kw in defender_keywords:
        if kw in text_lower:
            players.append({"role": "defender", "indicator": kw})
            break

    strategies = []
    if any(kw in text_lower for kw in ["攻击", "exploit", "漏洞利用"]):
        strategies.append({"player": "attacker", "strategy": "exploit_vulnerability"})
    if any(kw in text_lower for kw in ["防御", "防护", "patch", "mitigation"]):
        strategies.append({"player": "defender", "strategy": "apply_mitigation"})
    if any(kw in text_lower for kw in ["侦察", "reconnaissance", "侦查"]):
        strategies.append({"player": "attacker", "strategy": "reconnaissance"})
    if any(kw in text_lower for kw in ["监控", "monitoring", "检测", "detection"]):
        strategies.append({"player": "defender", "strategy": "monitoring_detection"})

    confidence = min(len(detected_scenarios) * 0.2 + (0.1 if players else 0.0) + (0.1 if strategies else 0.0), 1.0)
    summary = "未检测到博弈场景" if not detected_scenarios else f"检测到{len(detected_scenarios)}种博弈场景，主要场景: {primary_scenario or 'unknown'}"

    recommendations = []
    if primary_scenario == "zero_sum":
        recommendations.append("建议采用最大化最小收益策略，优先加强防御")
    elif primary_scenario == "signaling_game":
        recommendations.append("建议增强信号验证机制，减少信息不对称")
    elif primary_scenario == "stackelberg":
        recommendations.append("建议利用先手优势，主动发布防御策略")
    elif primary_scenario == "prisoner_dilemma":
        recommendations.append("建议建立信任验证机制，降低合作风险")
    if not recommendations:
        recommendations.append("建议持续监控博弈态势变化")

    return {
        "detected_scenarios": detected_scenarios,
        "primary_scenario": primary_scenario,
        "players": players,
        "strategies": strategies,
        "confidence": round(confidence, 4),
        "summary": summary,
        "recommendations": recommendations,
    }


async def _analyze_game_theory_llm(text: str, scenario_type: Optional[str], llm) -> Dict[str, Any]:
    scenario_hint = f"\n用户提示的博弈场景类型：{scenario_type}" if scenario_type else ""
    prompt = (
        "你是一个博弈论与网络安全分析专家。请分析以下文本中涉及的博弈论场景，"
        "包括以下6种类型：\n"
        "1. zero_sum（零和博弈）：攻防对抗、一方收益即另一方损失\n"
        "2. non_zero_sum（非零和博弈）：合作共赢、双方可能同时获益\n"
        "3. nash_equilibrium（纳什均衡）：策略平衡、各方无动力单方面改变策略\n"
        "4. prisoner_dilemma（囚徒困境）：信任博弈、合作与背叛的选择\n"
        "5. signaling_game（信号博弈）：信息不对称、伪装与信号验证\n"
        "6. stackelberg（斯塔克尔伯格博弈）：领导者-跟随者、先手优势\n\n"
        "同时识别博弈参与者（attacker/defender）和各方策略。\n\n"
        "请返回严格JSON格式：\n"
        '{"detected_scenarios": [{"scenario": "类型名", "evidence": "文本中的具体证据", '
        '"relevance": "high/medium"}], '
        '"primary_scenario": "最主要的博弈场景类型", '
        '"players": [{"role": "attacker/defender", "indicator": "识别依据"}], '
        '"strategies": [{"player": "attacker/defender", "strategy": "策略描述"}], '
        '"confidence": 0.0-1.0, '
        '"summary": "中文摘要", '
        '"recommendations": ["建议1", "建议2"]}\n\n'
        "如果未检测到博弈场景，detected_scenarios返回空数组，primary_scenario为null。"
        f"{scenario_hint}\n\n"
        f"待分析文本：\n{text[:8000]}"
    )
    try:
        result = await llm.generate_json(
            prompt=prompt,
            system_prompt=DEEPSEEK_THREAT_INTEL_SYSTEM,
            temperature=settings.LLM_TEMPERATURE_ANALYSIS,
        )
        if not isinstance(result, dict) or "detected_scenarios" not in result:
            raise ValueError("Invalid LLM response structure")
        result.setdefault("primary_scenario", scenario_type or (result["detected_scenarios"][0]["scenario"] if result.get("detected_scenarios") else None))
        result.setdefault("players", [])
        result.setdefault("strategies", [])
        result.setdefault("confidence", round(min(len(result.get("detected_scenarios", [])) * 0.2 + 0.1, 1.0), 4))
        result.setdefault("summary", f"检测到{len(result.get('detected_scenarios', []))}种博弈场景" if result.get("detected_scenarios") else "未检测到博弈场景")
        result.setdefault("recommendations", ["建议持续监控博弈态势变化"])
        for sc in result.get("detected_scenarios", []):
            sc.setdefault("relevance", "medium")
        return result
    except Exception as exc:
        logger.warning(f"LLM game theory analysis failed, falling back to keywords: {exc}")
        raise


@router.get("/games")
async def list_game_analyses(
    offset: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    status: Optional[str] = Query(None, max_length=32),
    current_user: User = Depends(get_current_user),
):
    try:
        async with async_session_factory() as session:
            q = select(AnalysisResultTable).where(AnalysisResultTable.analysis_type == "game_theory")
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
        logger.error(f"List game analyses failed: {exc}")
        raise AppException(detail="获取博弈分析列表失败", error_code="DATABASE_ERROR", status_code=500)


@router.post("/analyze")
async def create_game_analysis(
    body: GameTheoryAnalyzeRequest,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN, Role.ANALYST)),
):
    llm = getattr(request.app.state, "llm", None)
    model_name = "rule-based"
    analysis_result = None

    if llm and llm.is_available:
        try:
            analysis_result = await _analyze_game_theory_llm(body.text, body.scenario_type, llm)
            model_name = llm.model_name
        except Exception:
            analysis_result = None

    if analysis_result is None:
        analysis_result = _analyze_game_theory_keywords(body.text, body.scenario_type)

    row_id = uuid.uuid4().hex[:16]
    now = datetime.now(timezone.utc)

    try:
        async with async_session_factory() as session:
            row = AnalysisResultTable(
                id=row_id,
                analysis_type="game_theory",
                target_id=body.target_id or "",
                target_type="scenario",
                result_summary=analysis_result["summary"],
                findings_json=json.dumps(analysis_result["detected_scenarios"], ensure_ascii=False, default=str),
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
        logger.error(f"Create game analysis failed: {exc}")
        raise AppException(detail="创建博弈分析失败", error_code="DATABASE_ERROR", status_code=500)


@router.get("/statistics")
async def get_game_theory_statistics(
    current_user: User = Depends(get_current_user),
):
    try:
        async with async_session_factory() as session:
            total_result = await session.execute(
                select(func.count()).select_from(AnalysisResultTable).where(
                    AnalysisResultTable.analysis_type == "game_theory"
                )
            )
            total_count = total_result.scalar() or 0

            high_confidence_result = await session.execute(
                select(func.count()).select_from(AnalysisResultTable).where(
                    AnalysisResultTable.analysis_type == "game_theory",
                    AnalysisResultTable.confidence_score > 0.5,
                )
            )
            high_confidence_count = high_confidence_result.scalar() or 0

            avg_confidence_result = await session.execute(
                select(func.avg(AnalysisResultTable.confidence_score)).where(
                    AnalysisResultTable.analysis_type == "game_theory"
                )
            )
            avg_confidence = avg_confidence_result.scalar() or 0.0

            by_status_result = await session.execute(
                select(AnalysisResultTable.status, func.count())
                .where(AnalysisResultTable.analysis_type == "game_theory")
                .group_by(AnalysisResultTable.status)
            )
            by_status = {row[0]: row[1] for row in by_status_result.all()}

            trend_result = await session.execute(
                select(func.date(AnalysisResultTable.analyzed_at), func.count())
                .where(AnalysisResultTable.analysis_type == "game_theory")
                .group_by(func.date(AnalysisResultTable.analyzed_at))
                .order_by(func.date(AnalysisResultTable.analyzed_at))
                .limit(30)
            )
            trend_data = [{"date": str(row[0]), "count": row[1]} for row in trend_result.all()]

            return {
                "analysis_type": "game_theory",
                "total_count": total_count,
                "high_confidence_count": high_confidence_count,
                "avg_confidence": round(float(avg_confidence), 4),
                "by_status": by_status,
                "trend_data": trend_data,
            }
    except (AppException, NotFoundException):
        raise
    except Exception as exc:
        logger.error(f"Get game theory statistics failed: {exc}")
        raise AppException(detail="获取博弈分析统计失败", error_code="DATABASE_ERROR", status_code=500)
