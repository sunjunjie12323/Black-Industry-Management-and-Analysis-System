import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from loguru import logger
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.config import settings
from app.core.llm import LLMService
from app.db.analysis_crud import AnalysisResultCRUD
from app.engine.prompts.report_prompts import REPORT_GENERATION_SYSTEM_PROMPT


class ReportGenerator:
    def __init__(self, llm_client: LLMService, db_session_factory: async_sessionmaker):
        self.llm_client = llm_client
        self.db_session_factory = db_session_factory

    async def generate_from_results(self, results: List[Dict]) -> List[str]:
        if not results:
            return []
        by_type: Dict[str, List[Dict]] = {}
        for r in results:
            atype = r.get("analysis_type", "unknown")
            by_type.setdefault(atype, []).append(r)
        report_ids = []
        for atype, type_results in by_type.items():
            try:
                report_type = {
                    "zero_day": "zero_day_alert",
                    "attribution": "attribution_report",
                    "provenance": "provenance_report",
                    "decay": "decay_report",
                    "attack_prediction": "attack_prediction_report",
                }.get(atype, "analysis_report")
                rid = await self._generate_report(report_type, type_results)
                if rid:
                    report_ids.append(rid)
            except Exception as exc:
                logger.error(f"Report generation failed for {atype}: {exc}")
        if len(by_type) > 1:
            try:
                rid = await self._generate_report("comprehensive", results)
                if rid:
                    report_ids.append(rid)
            except Exception as exc:
                logger.error(f"Comprehensive report generation failed: {exc}")
        return report_ids

    async def _generate_report(self, report_type: str, results: List[Dict]) -> Optional[str]:
        context = self._assemble_context(results)
        prompt = (
            f"请基于以下分析结果生成一份{report_type}类型的威胁情报报告：\n\n"
            f"{context}\n\n"
            f"报告类型：{report_type}\n"
            f"请生成完整结构化报告。"
        )
        try:
            report_data = await self.llm_client.generate_json(prompt=prompt, system_prompt=REPORT_GENERATION_SYSTEM_PROMPT, temperature=settings.LLM_TEMPERATURE_CREATIVE)
        except Exception as exc:
            logger.warning(f"LLM report generation failed, creating minimal report: {exc}")
            report_data = {
                "title": f"{report_type} 自动生成报告",
                "summary": f"基于{len(results)}条分析结果自动生成",
                "key_findings": [r.get("result_summary", "")[:100] for r in results[:5]],
                "iocs": [],
                "threat_actors": [],
                "attack_chains": [],
                "recommendations": [],
                "evidence_chain": [],
                "confidence_score": 0.3,
            }
        report_id = await self._save_report(report_type, report_data)
        return report_id

    def _assemble_context(self, results: List[Dict]) -> str:
        lines = []
        for i, r in enumerate(results[:20]):
            lines.append(
                f"[分析结果{i+1}] 类型: {r.get('analysis_type', '')}, "
                f"目标: {r.get('target_id', '')[:20]}, "
                f"摘要: {r.get('result_summary', '')[:200]}, "
                f"置信度: {r.get('confidence_score', 0):.2f}"
            )
        return "\n".join(lines)

    async def _save_report(self, report_type: str, report_data: Dict) -> str:
        report_id = uuid.uuid4().hex[:16]
        try:
            from app.db.tables import ReportTable
            async with self.db_session_factory() as session:
                row = ReportTable(
                    id=report_id,
                    title=report_data.get("title", f"{report_type}报告"),
                    status="draft",
                    summary=report_data.get("summary", ""),
                    key_findings_json=json.dumps(report_data.get("key_findings", []), ensure_ascii=False, default=str),
                    threat_actors_json=json.dumps(report_data.get("threat_actors", []), ensure_ascii=False, default=str),
                    iocs_json=json.dumps(report_data.get("iocs", []), ensure_ascii=False, default=str),
                    attack_chains_json=json.dumps(report_data.get("attack_chains", []), ensure_ascii=False, default=str),
                    recommendations_json=json.dumps(report_data.get("recommendations", []), ensure_ascii=False, default=str),
                    evidence_chain_json=json.dumps(report_data.get("evidence_chain", []), ensure_ascii=False, default=str),
                    confidence_score=report_data.get("confidence_score", 0.0),
                    author="auto_analysis_engine",
                )
                session.add(row)
                await session.commit()
            logger.info(f"Report saved: {report_id} ({report_type})")
        except Exception as exc:
            logger.error(f"Failed to save report: {exc}")
        return report_id
