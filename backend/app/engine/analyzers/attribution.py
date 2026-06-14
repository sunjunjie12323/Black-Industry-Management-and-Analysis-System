from typing import Dict

from loguru import logger

from app.core.llm import LLMService
from app.core.entity_attribution import EntityAttribution
from app.engine.analyzers.base import BaseAnalyzer
from app.engine.prompts.attribution_prompts import ATTRIBUTION_SYSTEM_PROMPT
from sqlalchemy.ext.asyncio import async_sessionmaker


class AttributionAnalyzer(BaseAnalyzer):
    analysis_type = "attribution"

    def __init__(self, llm_client: LLMService, db_session_factory: async_sessionmaker, entity_attribution: EntityAttribution):
        super().__init__(llm_client, db_session_factory)
        self.entity_attribution = entity_attribution
        self._system_prompt = ATTRIBUTION_SYSTEM_PROMPT

    async def _rule_based_analyze(self, target_data: Dict) -> Dict:
        entity_id = target_data.get("id", "")
        try:
            fingerprint = await self.entity_attribution.compute_behavioral_fingerprint(entity_id)
            same_entities = await self.entity_attribution.find_same_entity(entity_id, threshold=0.7)
            findings = []
            for r in same_entities:
                d = r.to_dict() if hasattr(r, "to_dict") else {"source": r.source_entity_id, "target": r.target_entity_id, "similarity": r.similarity}
                findings.append(d)
            avg_sim = sum(r.similarity for r in same_entities) / len(same_entities) if same_entities else 0.0
            summary = f"实体溯源分析完成：发现{len(same_entities)}个同源实体，平均相似度{avg_sim:.2f}"
            fp_dict = fingerprint.to_dict() if hasattr(fingerprint, "to_dict") else str(fingerprint)
            return {
                "result_summary": summary,
                "findings": findings,
                "confidence_score": min(avg_sim + 0.1, 1.0),
                "status": "completed",
                "iocs": [],
                "recommendations": ["对同源实体进行关联分析", "更新实体指纹库"] if same_entities else [],
                "result_data": {"fingerprint": fp_dict, "same_entity_count": len(same_entities), "avg_similarity": round(avg_sim, 4)},
                "input_content": target_data.get("value", "")[:500],
            }
        except Exception as exc:
            logger.warning(f"Attribution rule analysis error: {exc}")
            return {"result_summary": f"溯源分析: 实体{entity_id}", "findings": [], "confidence_score": 0.1, "status": "completed", "iocs": [], "recommendations": [], "result_data": {}, "input_content": target_data.get("value", "")[:500]}

    def _should_enhance_with_llm(self, rule_result: Dict) -> bool:
        data = rule_result.get("result_data", {})
        avg_sim = data.get("avg_similarity", 0)
        return 0.7 <= avg_sim <= 0.9

    def _build_prompt(self, target_data: Dict, rule_result: Dict) -> str:
        findings = rule_result.get("findings", [])
        findings_text = "\n".join([str(f) for f in findings[:5]])
        return f"请验证以下同源实体匹配是否合理：\n\n源实体：{target_data.get('value', '')} (类型: {target_data.get('type', '')})\n\n同源匹配结果：\n{findings_text}\n\n请判断这些实体是否确实属于同一威胁行为者。"

    def _merge_results(self, rule_result: Dict, llm_result: Dict) -> Dict:
        merged = rule_result.copy()
        if isinstance(llm_result, dict):
            adj = llm_result.get("confidence_adjustment", 0)
            if adj:
                merged["confidence_score"] = min(max(rule_result.get("confidence_score", 0.5) + (adj - 0.5) * 0.3, 0), 1.0)
            merged["result_data"] = {**rule_result.get("result_data", {}), "llm_verification": llm_result}
            if llm_result.get("evidence_summary"):
                merged["result_summary"] += f" [LLM: {llm_result['evidence_summary'][:100]}]"
        return merged
