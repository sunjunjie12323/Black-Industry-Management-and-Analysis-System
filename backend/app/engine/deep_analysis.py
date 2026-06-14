import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from loguru import logger
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.config import settings
from app.core.llm import LLMService
from app.core.knowledge_graph import KnowledgeGraph
from app.db.analysis_crud import AnalysisResultCRUD
from app.engine.prompts.deep_analysis_prompts import DEEP_ANALYSIS_SYSTEM_PROMPT
from app.engine.web_search import WebSearchService
from app.schemas.analysis import DeepAnalysisRequest, DeepAnalysisResponse


class DeepAnalysisService:
    def __init__(self, llm_client: LLMService, web_search_service: WebSearchService, db_session_factory: async_sessionmaker, knowledge_graph: KnowledgeGraph):
        self.llm_client = llm_client
        self.web_search_service = web_search_service
        self.db_session_factory = db_session_factory
        self.knowledge_graph = knowledge_graph

    async def deep_analyze(self, request: DeepAnalysisRequest) -> DeepAnalysisResponse:
        web_context = ""
        data_sources = ["local_database"]
        if request.include_web_search:
            try:
                search_results = await self.web_search_service.search(request.target_identifier, request.search_keywords)
                web_context = self._format_search_results(search_results)
                if search_results:
                    data_sources.append("web_search")
            except Exception as exc:
                logger.warning(f"Web search failed, continuing with local data: {exc}")
                web_context = "联网搜索不可用，基于本地数据分析"
        local_data = await self._query_local_intelligence(request.target_identifier)
        graph_relations = await self._query_graph_relations(request.target_identifier)
        if graph_relations:
            data_sources.append("knowledge_graph")
        prompt = self._build_deep_analysis_prompt(request.target_identifier, local_data, web_context, graph_relations)
        try:
            llm_result = await self.llm_client.generate_json(prompt=prompt, system_prompt=DEEP_ANALYSIS_SYSTEM_PROMPT, temperature=settings.LLM_TEMPERATURE_CREATIVE)
        except Exception as exc:
            logger.error(f"Deep analysis LLM call failed: {exc}")
            llm_result = {
                "threat_assessment": f"深度分析部分完成（LLM不可用）: {str(exc)[:100]}",
                "related_threats": [],
                "risk_indicators": [],
                "recommended_actions": ["请稍后重试深度分析"],
                "confidence_score": 0.1,
                "data_sources_used": data_sources,
            }
        result_id = uuid.uuid4().hex[:16]
        try:
            async with self.db_session_factory() as session:
                await AnalysisResultCRUD.create(session, {
                    "analysis_type": "deep_analysis",
                    "target_id": request.target_identifier,
                    "target_type": request.target_type,
                    "result_summary": llm_result.get("threat_assessment", "")[:500],
                    "findings": llm_result.get("related_threats", []),
                    "iocs": [],
                    "recommendations": llm_result.get("recommended_actions", []),
                    "result_data": llm_result,
                    "confidence_score": llm_result.get("confidence_score", 0.0),
                    "status": "completed",
                    "model_name": self.llm_client.model_name,
                    "input_content": request.target_identifier[:500],
                })
        except Exception as exc:
            logger.warning(f"Failed to persist deep analysis result: {exc}")
        return DeepAnalysisResponse(
            result_id=result_id,
            threat_assessment=llm_result.get("threat_assessment", ""),
            related_threats=llm_result.get("related_threats", []),
            risk_indicators=llm_result.get("risk_indicators", []),
            recommended_actions=llm_result.get("recommended_actions", []),
            confidence_score=llm_result.get("confidence_score", 0.0),
            data_sources_used=data_sources,
        )

    async def _query_local_intelligence(self, target_identifier: str) -> str:
        from app.db.tables import RawIntelligenceTable
        from sqlalchemy import select
        try:
            async with self.db_session_factory() as session:
                result = await session.execute(
                    select(RawIntelligenceTable).where(RawIntelligenceTable.content.contains(target_identifier)).limit(5)
                )
                rows = result.scalars().all()
                if not rows:
                    return "本地未找到相关情报"
                return "\n---\n".join([f"[情报{i+1}] {(r.content or '')[:300]}" for i, r in enumerate(rows)])
        except Exception:
            return "本地情报查询失败"

    async def _query_graph_relations(self, target_identifier: str) -> str:
        try:
            kg = self.knowledge_graph
            if not kg.graph.nodes:
                return "知识图谱为空"
            matching = [nid for nid, ndata in kg.graph.nodes(data=True) if target_identifier in str(ndata.get("value", ""))]
            if not matching:
                return "知识图谱中未找到匹配实体"
            relations = []
            for nid in matching[:3]:
                for neighbor in kg.graph.neighbors(nid):
                    edge = kg.graph.edges[nid, neighbor]
                    relations.append(f"实体{nid[:8]} -> {neighbor[:8]} (类型: {edge.get('type', 'unknown')}, 置信度: {edge.get('confidence', 0)})")
            return "\n".join(relations[:10]) if relations else "无关联关系"
        except Exception:
            return "知识图谱查询失败"

    def _format_search_results(self, results) -> str:
        if not results:
            return "联网搜索无结果"
        lines = []
        for r in results[:10]:
            lines.append(f"- [{r.source}] {r.title}: {r.snippet[:150]}")
        return "\n".join(lines)

    def _build_deep_analysis_prompt(self, target: str, local_data: str, web_context: str, graph_relations: str) -> str:
        return (
            f"请对以下目标进行深度威胁情报分析：\n\n"
            f"分析目标：{target}\n\n"
            f"=== 本地情报数据 ===\n{local_data}\n\n"
            f"=== 联网搜索结果 ===\n{web_context}\n\n"
            f"=== 知识图谱关联 ===\n{graph_relations}\n\n"
            f"请综合以上所有信息源，进行深度研判分析。"
        )
