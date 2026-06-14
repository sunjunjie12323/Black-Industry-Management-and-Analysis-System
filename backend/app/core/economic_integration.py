"""
Economic Integration Patch — 将经济系统集成到OrchestratorAgent
此文件提供补丁方法，在OrchestratorAgent初始化后注入经济引擎
"""
from typing import Dict, List, Optional
from loguru import logger
from app.core.economic_engine import EconomicEngine


def patch_orchestrator_with_economic(orchestrator, economic_engine: EconomicEngine):
    orchestrator.economic_engine = economic_engine
    original_execute_query = orchestrator.execute_query

    async def execute_query_with_economic(query: str, context: Dict = None) -> Dict:
        result = await original_execute_query(query, context)
        if result.get("status") == "success":
            try:
                await _feed_economic_from_result(orchestrator, result)
            except Exception as exc:
                logger.warning(f"Economic feeding from query result failed: {exc}")
        return result

    orchestrator.execute_query = execute_query_with_economic

    original_execute_pir = orchestrator.execute_pir

    async def execute_pir_with_economic(pir_id: str) -> Dict:
        result = await original_execute_pir(pir_id)
        if result.get("evaluation"):
            try:
                await _feed_economic_from_pir(orchestrator, result)
            except Exception as exc:
                logger.warning(f"Economic feeding from PIR result failed: {exc}")
        return result

    orchestrator.execute_pir = execute_pir_with_economic

    logger.info("OrchestratorAgent patched with EconomicEngine integration")


async def _feed_economic_from_result(orchestrator, result: Dict):
    economic_engine: EconomicEngine = orchestrator.economic_engine
    step_results = result.get("step_results", [])

    for step in step_results:
        agent = step.get("agent", "")
        step_data = step.get("result", {}).get("data", {})

        if agent == "analyst":
            analyzed = step_data.get("analyzed_intelligence", {})
            if analyzed:
                threat_level = analyzed.get("threat_level", "info")
                threat_categories = analyzed.get("threat_categories", [])
                intel_ids = [analyzed.get("id", "")]
                summary = analyzed.get("analysis_summary", "")[:200]
                if threat_categories and threat_level not in ("info",):
                    impacts, alerts = economic_engine.process_intelligence_findings(
                        threat_categories=threat_categories,
                        threat_level=threat_level,
                        intelligence_ids=intel_ids,
                        content_summary=summary,
                    )
                    if impacts:
                        result["economic_impacts"] = [i.to_dict() for i in impacts]
                    if alerts:
                        result["economic_alerts"] = [a.to_dict() for a in alerts]

        elif agent == "cleaner":
            cleaned = step_data.get("cleaned_intelligence", {})
            if cleaned:
                threat_level = cleaned.get("threat_level", "info")
                blacktalk_terms = cleaned.get("blacktalk_terms", {})
                if threat_level in ("high", "critical") and blacktalk_terms:
                    threat_categories = _infer_categories_from_blacktalk(blacktalk_terms)
                    intel_ids = [cleaned.get("id", "")]
                    economic_engine.process_intelligence_findings(
                        threat_categories=threat_categories,
                        threat_level=threat_level,
                        intelligence_ids=intel_ids,
                        content_summary=f"黑话密度高: {', '.join(list(blacktalk_terms.keys())[:5])}",
                    )


async def _feed_economic_from_pir(orchestrator, result: Dict):
    economic_engine: EconomicEngine = orchestrator.economic_engine
    task_results = result.get("task_results", [])
    all_threat_categories: List[str] = []
    highest_threat_level = "info"
    all_intel_ids: List[str] = []

    for task in task_results:
        if task.get("status") != "completed":
            continue
        task_result = task.get("result", {})
        data = task_result.get("data", {})
        analyzed = data.get("analyzed_intelligence", {})
        if analyzed:
            categories = analyzed.get("threat_categories", [])
            all_threat_categories.extend(categories)
            level = analyzed.get("threat_level", "info")
            level_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
            if level_order.get(level, 0) > level_order.get(highest_threat_level, 0):
                highest_threat_level = level
            all_intel_ids.append(analyzed.get("id", ""))

    if all_threat_categories and highest_threat_level not in ("info",):
        unique_categories = list(set(all_threat_categories))
        economic_engine.process_intelligence_findings(
            threat_categories=unique_categories,
            threat_level=highest_threat_level,
            intelligence_ids=all_intel_ids,
            content_summary=f"PIR分析结果: {result.get('title', '')}",
        )


def _infer_categories_from_blacktalk(blacktalk_terms: Dict[str, str]) -> List[str]:
    category_keywords = {
        "fraud": ["诈骗", "骗", "杀猪", "套路", "跑分"],
        "money_laundering": ["洗钱", "跑分", "水房", "过桥"],
        "phishing": ["钓鱼", "仿冒", "伪造"],
        "data_theft": ["脱裤", "撞库", "社工库", "料子"],
        "hacking": ["木马", "远控", "提权", "拿站"],
        "gambling": ["菠菜", "盘口", "代理"],
    }
    categories = set()
    for term in blacktalk_terms.keys():
        for cat, keywords in category_keywords.items():
            if any(kw in term for kw in keywords):
                categories.add(cat)
    return list(categories) if categories else ["other"]
