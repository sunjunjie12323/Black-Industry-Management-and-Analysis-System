from typing import Dict

from loguru import logger

from app.core.llm import LLMService
from app.core.zero_day_detector import ZeroDayDetector
from app.engine.analyzers.base import BaseAnalyzer
from app.engine.prompts.zero_day_prompts import ZERO_DAY_SYSTEM_PROMPT
from sqlalchemy.ext.asyncio import async_sessionmaker


class ZeroDayAnalyzer(BaseAnalyzer):
    analysis_type = "zero_day"

    def __init__(self, llm_client: LLMService, db_session_factory: async_sessionmaker, zero_day_detector: ZeroDayDetector):
        super().__init__(llm_client, db_session_factory)
        self.zero_day_detector = zero_day_detector
        self._system_prompt = ZERO_DAY_SYSTEM_PROMPT

    async def _rule_based_analyze(self, target_data: Dict) -> Dict:
        content = target_data.get("content", "")
        if len(content) < 10:
            return {"result_summary": "内容过短，跳过0日检测", "findings": [], "confidence_score": 0.0, "status": "skipped", "iocs": [], "recommendations": [], "result_data": {}}
        try:
            if not self.zero_day_detector._trained:
                return {"result_summary": "0日检测器未训练，跳过规则检测", "findings": [], "confidence_score": 0.0, "status": "skipped", "iocs": [], "recommendations": [], "result_data": {}}
            # detect_zero_day_terms 返回列表[ZeroDayTerm]，不是字典
            zero_day_terms = await self.zero_day_detector.detect_zero_day_terms(content)
            findings = [t.to_dict() if hasattr(t, "to_dict") else t for t in zero_day_terms]
            is_likely = len(zero_day_terms) > 0
            confidence = min(0.3 + len(zero_day_terms) * 0.15, 0.9) if is_likely else 0.1
            summary = f"检测到{len(zero_day_terms)}个疑似0日术语"
            return {
                "result_summary": summary,
                "findings": findings,
                "confidence_score": confidence,
                "status": "completed",
                "iocs": [],
                "recommendations": ["关注疑似0日术语的后续披露", "监控相关漏洞情报"] if is_likely else [],
                "result_data": {"zero_day_terms_count": len(zero_day_terms), "is_zero_day_likely": is_likely},
                "input_content": content[:2000],
            }
        except Exception as exc:
            logger.warning(f"ZeroDay rule analysis error: {exc}")
            return {"result_summary": f"规则检测异常: {str(exc)[:100]}", "findings": [], "confidence_score": 0.0, "status": "completed", "iocs": [], "recommendations": [], "result_data": {}}

    def _should_enhance_with_llm(self, rule_result: Dict) -> bool:
        if rule_result.get("status") == "skipped":
            return False
        data = rule_result.get("result_data", {})
        return data.get("is_zero_day_likely", False) or rule_result.get("confidence_score", 0) >= 0.3

    def _build_prompt(self, target_data: Dict, rule_result: Dict) -> str:
        content = target_data.get("content", "")[:3000]
        findings = rule_result.get("findings", [])
        findings_text = "\n".join([str(f) for f in findings[:5]])
        return f"请分析以下威胁情报是否描述了0日漏洞特征：\n\n情报内容：\n{content}\n\n规则检测已发现：\n{findings_text}\n\n请综合判断此情报是否涉及0日漏洞。"

    def _merge_results(self, rule_result: Dict, llm_result: Dict) -> Dict:
        merged = rule_result.copy()
        if isinstance(llm_result, dict):
            if llm_result.get("is_zero_day_likely"):
                merged["confidence_score"] = min(rule_result.get("confidence_score", 0.3) + 0.2, 1.0)
                merged["result_summary"] += " [LLM确认可能为0日]"
            merged["result_data"] = {**rule_result.get("result_data", {}), "llm_analysis": llm_result}
            if llm_result.get("recommendations"):
                merged["recommendations"] = list(set(rule_result.get("recommendations", []) + llm_result["recommendations"]))
        return merged
