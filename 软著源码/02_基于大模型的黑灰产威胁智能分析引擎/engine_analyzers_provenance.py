from typing import Dict

from loguru import logger

from app.core.llm import LLMService
from app.core.provenance_chain import ProvenanceChain
from app.engine.analyzers.base import BaseAnalyzer
from app.engine.prompts.provenance_prompts import PROVENANCE_SYSTEM_PROMPT
from sqlalchemy.ext.asyncio import async_sessionmaker


class ProvenanceAnalyzer(BaseAnalyzer):
    analysis_type = "provenance"

    def __init__(self, llm_client: LLMService, db_session_factory: async_sessionmaker, provenance_chain: ProvenanceChain):
        super().__init__(llm_client, db_session_factory)
        self.provenance_chain = provenance_chain
        self._system_prompt = PROVENANCE_SYSTEM_PROMPT

    async def _rule_based_analyze(self, target_data: Dict) -> Dict:
        intel_id = target_data.get("id", "")
        try:
            verification = await self.provenance_chain.verify_provenance(intel_id)
            ver_dict = verification.to_dict() if hasattr(verification, "to_dict") else {"is_valid": False, "chain_length": 0, "completeness": 0.0}
            try:
                evolution = await self.provenance_chain.get_confidence_evolution(intel_id)
                evo_data = evolution if isinstance(evolution, list) else []
            except Exception:
                evo_data = []
            try:
                hallucination = await self.provenance_chain.detect_hallucination(intel_id)
                hall_data = hallucination if isinstance(hallucination, dict) else {"hallucination_detected": False}
            except Exception:
                hall_data = {"hallucination_detected": False}
            is_valid = ver_dict.get("is_valid", False)
            completeness = ver_dict.get("completeness", 0.0)
            confidence = completeness * 0.7 + (0.3 if is_valid else 0.0)
            summary = f"情报证实完成：链长{ver_dict.get('chain_length', 0)}，完整性{completeness:.2f}，{'有效' if is_valid else '存疑'}"
            return {
                "result_summary": summary,
                "findings": [ver_dict],
                "confidence_score": confidence,
                "status": "completed",
                "iocs": [],
                "recommendations": ["补充源链记录"] if completeness < 0.5 else [],
                "result_data": {"verification": ver_dict, "confidence_evolution": evo_data, "hallucination": hall_data},
                "input_content": target_data.get("content", "")[:2000],
            }
        except Exception as exc:
            logger.warning(f"Provenance rule analysis error: {exc}")
            return {"result_summary": f"情报证实: {intel_id}", "findings": [], "confidence_score": 0.2, "status": "completed", "iocs": [], "recommendations": [], "result_data": {}, "input_content": target_data.get("content", "")[:2000]}

    def _should_enhance_with_llm(self, rule_result: Dict) -> bool:
        return rule_result.get("confidence_score", 0) < 0.5

    def _build_prompt(self, target_data: Dict, rule_result: Dict) -> str:
        content = target_data.get("content", "")[:2000]
        return f"请评估以下威胁情报的可信度：\n\n情报内容：\n{content}\n\n已有源链验证结果：{rule_result.get('result_summary', '')}\n\n请判断此情报是否可信，是否存在幻觉或虚假信息。"

    def _merge_results(self, rule_result: Dict, llm_result: Dict) -> Dict:
        merged = rule_result.copy()
        if isinstance(llm_result, dict):
            reliability = llm_result.get("source_reliability", 0.5)
            merged["confidence_score"] = (rule_result.get("confidence_score", 0.3) + reliability) / 2
            merged["result_data"] = {**rule_result.get("result_data", {}), "llm_assessment": llm_result}
            if llm_result.get("recommendations"):
                merged["recommendations"] = list(set(rule_result.get("recommendations", []) + llm_result["recommendations"]))
        return merged
