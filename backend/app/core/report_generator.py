import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from loguru import logger

from app.config import settings
from app.core.llm import LLMService
from app.core.evidence_chain import EvidenceChain, Evidence
from app.core.vector_store import VectorStore
from app.models.intelligence import IntelligenceReport


class ReportGenerator:
    def __init__(self, llm: LLMService, vector_store: VectorStore):
        self.llm = llm
        self.vector_store = vector_store
        self.evidence_chain = EvidenceChain(llm, vector_store)

    async def generate_report(
        self,
        title: str,
        context: str,
        pir_id: Optional[str] = None,
        intelligence_ids: Optional[List[str]] = None,
    ) -> IntelligenceReport:
        related_intel = await self._collect_evidence(context, intelligence_ids)

        report_data = await self._llm_generate(title, context, related_intel)

        verification = await self._verify_evidence(report_data, related_intel)

        confidence = self._compute_confidence(report_data, verification)
        report = IntelligenceReport(
            pir_id=pir_id,
            title=f"情报报告: {title}",
            summary=report_data.get("summary", ""),
            key_findings=report_data.get("key_findings", []),
            threat_actors=report_data.get("threat_actors", []),
            iocs=report_data.get("iocs", []),
            recommendations=report_data.get("recommendations", []),
            confidence_score=confidence,
            evidence_chain=[e.id for e in related_intel],
        )

        await self._persist_report(report)

        return report

    async def _collect_evidence(self, context: str, intelligence_ids: Optional[List[str]] = None) -> List[Evidence]:
        evidences = []
        keywords = context.split()[:5]
        for kw in keywords:
            try:
                results = await self.vector_store.search_intelligence(kw, n_results=3)
                for r in results:
                    evidences.append(Evidence(
                        id=uuid4().hex,
                        source_id=r.get("id", uuid4().hex),
                        source_type="intelligence",
                        content=r.get("document", ""),
                        confidence=1.0 - r.get("distance", 0.5),
                    ))
            except Exception:
                pass
        return evidences[:20]

    async def _llm_generate(self, title: str, context: str, evidences: List[Evidence]) -> Dict:
        system_prompt = (
            "你是一个黑灰产情报分析报告撰写专家。生成结构化报告，返回JSON：\n"
            "- summary: 摘要(200字内)\n- key_findings: 关键发现列表\n"
            "- threat_actors: 威胁行为者\n- iocs: IoC列表\n"
            "- recommendations: 建议措施\n- confidence_score: 0-1\n"
            "只返回JSON。"
        )
        evidence_text = "\n".join(e.content[:200] for e in evidences[:10])
        prompt = f"标题：{title}\n上下文：{context}\n证据：\n{evidence_text}"
        try:
            return await self.llm.generate_json(prompt=prompt, system_prompt=system_prompt, temperature=settings.LLM_TEMPERATURE_CREATIVE)
        except Exception as exc:
            logger.error(f"LLM report generation failed: {exc}")
            return self._fallback_generate(title, context, evidences)

    def _fallback_generate(self, title: str, context: str, evidences: List[Evidence]) -> Dict:
        import re
        iocs: List[str] = []
        ip_pat = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        url_pat = re.compile(r'https?://[^\s]+')
        email_pat = re.compile(r'[\w.+-]+@[\w-]+\.[\w.]+')
        sha_pat = re.compile(r'\b[a-fA-F0-9]{32,64}\b')
        for e in evidences:
            iocs.extend(ip_pat.findall(e.content)[:3])
            iocs.extend(url_pat.findall(e.content)[:2])
            iocs.extend(email_pat.findall(e.content)[:2])
            iocs.extend(sha_pat.findall(e.content)[:2])
        return {
            "summary": f"关于「{title}」的情报分析报告（规则生成，基于{len(evidences)}条证据）",
            "key_findings": [title, f"采集{len(evidences)}条关联证据"] + ([f"提取{len(iocs)}个IoC指标"] if iocs else []),
            "threat_actors": [],
            "iocs": iocs[:15],
            "recommendations": ["建议持续监控相关情报", "加强关联实体排查", "对提取的IoC指标进行验证和封堵"],
            "confidence_score": min(0.6, 0.3 + len(evidences) * 0.05),
        }

    async def _verify_evidence(self, report_data: Dict, evidences: List[Evidence]) -> Any:
        if not evidences:
            from app.core.evidence_chain import VerificationResult
            return VerificationResult(
                conclusion=report_data.get("summary", ""),
                confidence=0.5,
                evidence_count=0,
                source_count=0,
                cross_validated=False,
                evidence_list=[],
                verification_details="无证据，默认置信度0.5",
            )
        return await self.evidence_chain.verify(
            conclusion=report_data.get("summary", ""),
            sources=evidences,
        )

    def _compute_confidence(self, report_data: Dict, verification: Any) -> float:
        try:
            conf = float(report_data.get("confidence_score", 0.5))
        except (ValueError, TypeError):
            conf = 0.5
        conf = max(0.0, min(1.0, conf * getattr(verification, 'confidence', 1.0)))
        return conf

    async def _persist_report(self, report: IntelligenceReport) -> None:
        try:
            from app.db.database import async_session_factory
            from app.db.tables import ReportTable
            async with async_session_factory() as session:
                db_report = ReportTable(
                    id=report.id,
                    title=report.title,
                    status="published",
                    summary=report.summary,
                    key_findings_json=json.dumps(report.key_findings),
                    threat_actors_json=json.dumps(report.threat_actors),
                    iocs_json=json.dumps(report.iocs),
                    recommendations_json=json.dumps(report.recommendations),
                    confidence_score=report.confidence_score,
                    author="system",
                    published_at=datetime.now(timezone.utc),
                )
                session.add(db_report)
                await session.commit()
                logger.info(f"Persisted report {report.id} to database")
        except Exception as exc:
            logger.error(f"Failed to persist report: {exc}")
