from typing import Dict

from loguru import logger

from app.core.llm import LLMService
from app.core.attack_chain_predictor import AttackChainPredictor
from app.engine.analyzers.base import BaseAnalyzer
from app.engine.prompts.attack_prediction_prompts import ATTACK_PREDICTION_SYSTEM_PROMPT
from sqlalchemy.ext.asyncio import async_sessionmaker


class AttackPredictionAnalyzer(BaseAnalyzer):
    analysis_type = "attack_prediction"

    def __init__(self, llm_client: LLMService, db_session_factory: async_sessionmaker, attack_predictor: AttackChainPredictor):
        super().__init__(llm_client, db_session_factory)
        self.attack_predictor = attack_predictor
        self._system_prompt = ATTACK_PREDICTION_SYSTEM_PROMPT

    async def _rule_based_analyze(self, target_data: Dict) -> Dict:
        entity_id = target_data.get("id", "")
        try:
            prediction_result = await self.attack_predictor.predict_next_steps(entity_id, depth=3)
            # predict_next_steps 返回 PredictionResult 对象，predictions 属性才是列表
            predictions = prediction_result.predictions if hasattr(prediction_result, 'predictions') else []
            pred_data = [p.to_dict() if hasattr(p, "to_dict") else str(p) for p in predictions]
            try:
                warnings = await self.attack_predictor.find_early_warning_signals(prediction_result)
                warn_data = [w.to_dict() if hasattr(w, "to_dict") else str(w) for w in warnings[:10]]
            except Exception:
                warn_data = []
            findings = pred_data[:5]
            avg_prob = sum(p.probability for p in predictions) / len(predictions) if predictions else 0.0
            summary = f"攻击预测完成：{len(predictions)}个预测步骤，{len(warn_data)}个预警信号，平均概率{avg_prob:.2f}"
            return {
                "result_summary": summary,
                "findings": findings,
                "confidence_score": avg_prob,
                "status": "completed",
                "iocs": [],
                "recommendations": ["关注高概率攻击步骤", "加强早期预警监控"] if avg_prob > 0.5 else [],
                "result_data": {"predictions": pred_data, "early_warnings": warn_data, "avg_probability": round(avg_prob, 4)},
                "input_content": target_data.get("value", target_data.get("content", ""))[:2000],
            }
        except Exception as exc:
            logger.warning(f"AttackPrediction rule analysis error: {exc}")
            return {"result_summary": f"攻击预测: {entity_id}", "findings": [], "confidence_score": 0.1, "status": "completed", "iocs": [], "recommendations": [], "result_data": {}, "input_content": target_data.get("value", "")[:500]}

    def _should_enhance_with_llm(self, rule_result: Dict) -> bool:
        return rule_result.get("confidence_score", 0) < 0.6

    def _build_prompt(self, target_data: Dict, rule_result: Dict) -> str:
        value = target_data.get("value", target_data.get("content", ""))[:2000]
        findings = rule_result.get("findings", [])
        findings_text = "\n".join([str(f) for f in findings[:5]])
        return f"请基于MITRE ATT&CK框架预测以下实体的下一步攻击行为：\n\n实体信息：{value}\n\n已有预测结果：\n{findings_text}\n\n请补充可能的攻击步骤和早期预警信号。"

    def _merge_results(self, rule_result: Dict, llm_result: Dict) -> Dict:
        merged = rule_result.copy()
        if isinstance(llm_result, dict):
            if llm_result.get("predicted_next_steps"):
                existing = rule_result.get("result_data", {}).get("predictions", [])
                new_steps = llm_result["predicted_next_steps"]
                merged["result_data"] = {**rule_result.get("result_data", {}), "llm_predictions": new_steps, "predictions": existing + new_steps}
            if llm_result.get("early_warning_indicators"):
                merged["result_data"]["llm_warnings"] = llm_result["early_warning_indicators"]
            if llm_result.get("defensive_recommendations"):
                merged["recommendations"] = list(set(rule_result.get("recommendations", []) + llm_result["defensive_recommendations"]))
            merged["result_summary"] += " [LLM补充预测]"
        return merged
