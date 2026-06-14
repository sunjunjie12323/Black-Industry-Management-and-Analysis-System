from typing import Dict

from loguru import logger

from app.core.llm import LLMService
from app.core.temporal_decay import TemporalDecay
from app.engine.analyzers.base import BaseAnalyzer
from app.engine.prompts.decay_prompts import DECAY_SYSTEM_PROMPT
from sqlalchemy.ext.asyncio import async_sessionmaker


class DecayAnalyzer(BaseAnalyzer):
    analysis_type = "decay"

    def __init__(self, llm_client: LLMService, db_session_factory: async_sessionmaker, temporal_decay: TemporalDecay):
        super().__init__(llm_client, db_session_factory)
        self.temporal_decay = temporal_decay
        self._system_prompt = DECAY_SYSTEM_PROMPT

    async def _rule_based_analyze(self, target_data: Dict) -> Dict:
        intel_id = target_data.get("id", "")
        try:
            batch_result = await self.temporal_decay.batch_decay_analysis()
            batch_dict = batch_result.to_dict() if hasattr(batch_result, "to_dict") else {"total_items": 0, "average_confidence": 0.0}
            try:
                curve = await self.temporal_decay.compute_decay_curve(intel_id)
                curve_data = curve if isinstance(curve, list) else []
            except Exception:
                curve_data = []
            try:
                refresh_recs = await self.temporal_decay.recommend_refresh()
                refresh_data = [r.to_dict() if hasattr(r, "to_dict") else str(r) for r in refresh_recs[:10]]
            except Exception:
                refresh_data = []
            avg_conf = batch_dict.get("average_confidence", 0.0)
            total = batch_dict.get("total_items", 0)
            expired = batch_dict.get("expired_items", 0)
            summary = f"衰减分析完成：{total}条情报，平均置信度{avg_conf:.2f}，{expired}条已过期"
            return {
                "result_summary": summary,
                "findings": [{"id": intel_id, "decay_curve_points": len(curve_data)}],
                "confidence_score": avg_conf,
                "status": "completed",
                "iocs": [],
                "recommendations": [f"刷新{len(refresh_data)}条过期情报"] if refresh_data else [],
                "result_data": {"batch_summary": batch_dict, "decay_curve": curve_data[:20], "refresh_recommendations": refresh_data},
                "input_content": target_data.get("content", "")[:2000],
            }
        except Exception as exc:
            logger.warning(f"Decay rule analysis error: {exc}")
            return {"result_summary": f"衰减分析: {intel_id}", "findings": [], "confidence_score": 0.3, "status": "completed", "iocs": [], "recommendations": [], "result_data": {}, "input_content": target_data.get("content", "")[:2000]}

    def _should_enhance_with_llm(self, rule_result: Dict) -> bool:
        return rule_result.get("confidence_score", 0) < 0.3

    def _build_prompt(self, target_data: Dict, rule_result: Dict) -> str:
        content = target_data.get("content", "")[:2000]
        conf = rule_result.get("confidence_score", 0)
        return f"请评估以下已衰减的威胁情报是否仍有分析价值：\n\n情报内容：\n{content}\n\n当前衰减后置信度：{conf:.2f}\n\n请判断此情报是否仍具分析价值。"

    def _merge_results(self, rule_result: Dict, llm_result: Dict) -> Dict:
        merged = rule_result.copy()
        if isinstance(llm_result, dict):
            if llm_result.get("still_valuable", True):
                merged["confidence_score"] = max(rule_result.get("confidence_score", 0.1), llm_result.get("remaining_relevance", 0.2))
                merged["result_summary"] += " [LLM评估: 仍有价值]"
            else:
                merged["result_summary"] += " [LLM评估: 建议归档]"
            merged["result_data"] = {**rule_result.get("result_data", {}), "llm_value_assessment": llm_result}
            if llm_result.get("recommendations"):
                merged["recommendations"] = list(set(rule_result.get("recommendations", []) + llm_result["recommendations"]))
        return merged
