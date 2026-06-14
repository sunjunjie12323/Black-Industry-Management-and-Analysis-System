import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

from loguru import logger

from app.config import settings
from app.agents.analyst import AnalystAgent
from app.agents.cleaner import CleanerAgent
from app.agents.collector import CollectorAgent
from app.agents.graph_builder import GraphBuilderAgent
from app.core.blacktalk_engine import BlackTalkEngine
from app.core.data_governance import DataClassification, DataMinimizer, ClassificationLevel
from app.core.data_masking import PIIDetector
from app.core.evidence_chain import EvidenceChain, Evidence, CrossValidator, HallucinationDetector
from app.core.knowledge_graph import KnowledgeGraph
from app.core.llm import LLMService
from app.core.message_queue import (
    TOPIC_INTELLIGENCE_COLLECTED,
    TOPIC_INTELLIGENCE_CLEANED,
    TOPIC_INTELLIGENCE_ANALYZED,
    TOPIC_ENTITY_DISCOVERED,
)
from app.core.pir_engine import PIREngine
from app.core.provenance_chain import ProvenanceChain
from app.core.report_generator import ReportGenerator
from app.core.vector_store import VectorStore
from app.models.intelligence import IntelligenceReport, ThreatLevel
from app.models.pir import PIRTaskStatus


class OrchestratorAgent:
    def __init__(
        self,
        llm: LLMService,
        vector_store: VectorStore,
        blacktalk_engine: BlackTalkEngine,
        knowledge_graph: KnowledgeGraph,
        evidence_chain: EvidenceChain,
        pir_engine: PIREngine,
        data_classification: DataClassification = None,
        data_minimizer: DataMinimizer = None,
        pii_detector: PIIDetector = None,
        provenance_chain: ProvenanceChain = None,
        cross_validator: CrossValidator = None,
        hallucination_detector: HallucinationDetector = None,
        ner_engine = None,
        message_queue = None,
    ):
        self.llm = llm
        self.vector_store = vector_store
        self.blacktalk_engine = blacktalk_engine
        self.knowledge_graph = knowledge_graph
        self.evidence_chain = evidence_chain
        self.pir_engine = pir_engine
        self.data_classification = data_classification
        self.data_minimizer = data_minimizer
        self.pii_detector = pii_detector
        self.provenance_chain = provenance_chain
        self.cross_validator = cross_validator
        self.hallucination_detector = hallucination_detector
        self.ner_engine = ner_engine
        self.message_queue = message_queue
        self.report_generator = ReportGenerator(llm, vector_store)

        self.collector = CollectorAgent(llm, vector_store, knowledge_graph)
        self.cleaner = CleanerAgent(llm, vector_store, blacktalk_engine)
        self.analyst = AnalystAgent(
            llm, vector_store, blacktalk_engine, knowledge_graph, evidence_chain
        )
        self.graph_builder = GraphBuilderAgent(
            llm, vector_store, knowledge_graph, evidence_chain
        )

        self.logger = logger.bind(agent="orchestrator")
        self._history_file = "./model_data/orchestrator/execution_history.json"
        self.execution_history: List[Dict] = []
        self._plan_cache: Dict[str, List[Dict]] = {}
        self._plan_cache_max = 50
        self._load_history()

    async def execute_query(
        self, query: str, context: Dict = None
    ) -> Dict:
        execution_id = uuid4().hex
        start_time = datetime.now(timezone.utc)

        self.logger.info(f"Executing query [{execution_id}]: {query[:100]}")

        try:
            plan = await self._plan_execution(query)

            self.logger.info(
                f"Execution plan [{execution_id}]: {len(plan)} steps"
            )

            collected_items: List[Dict] = []
            cleaned_items: List[Dict] = []
            analyzed_items: List[Dict] = []
            results: List[Dict] = []

            collector_steps = [s for s in plan if s.get("agent") == "collector"]
            other_steps = [s for s in plan if s.get("agent") != "collector"]

            if collector_steps:
                step = collector_steps[0]
                step_result = await self._execute_agent_step(
                    step.get("agent", ""), step.get("task", {}), context
                )
                results.append({
                    "step": 1,
                    "agent": step.get("agent", ""),
                    "task_type": step.get("task", {}).get("type", "unknown"),
                    "result": step_result,
                })
                if step_result.get("status") == "success":
                    items = step_result.get("data", {}).get("items", [])
                    for item in items:
                        content = item.get("content", "")
                        if self.data_classification:
                            try:
                                cls_result = self.data_classification.classify(content, item.get("metadata"))
                                item["classification_level"] = cls_result.level.value
                            except Exception as exc:
                                self.logger.warning(f"Data classification failed: {exc}")
                        if self.pii_detector:
                            try:
                                pii_matches = self.pii_detector.detect_pii(content)
                                if pii_matches:
                                    item["pii_detected"] = True
                                    item["pii_types"] = list({m.pii_type.value for m in pii_matches})
                                    if self.data_minimizer and item.get("classification_level") == ClassificationLevel.RESTRICTED.value:
                                        item["content"] = self.data_minimizer.minimize_pii(
                                            content, ClassificationLevel.RESTRICTED
                                        )
                            except Exception as exc:
                                self.logger.warning(f"PII detection failed: {exc}")
                    collected_items.extend(items)
                    if self.message_queue:
                        try:
                            await self.message_queue.publish(
                                TOPIC_INTELLIGENCE_COLLECTED,
                                {"items": collected_items, "count": len(collected_items)},
                            )
                        except Exception as exc:
                            self.logger.warning(f"Message queue publish failed for collected: {exc}")

            parallel_groups: List[List[Dict]] = []
            current_group: List[Dict] = []
            for step in other_steps:
                agent = step.get("agent", "")
                if agent in ("cleaner", "graph_builder"):
                    current_group.append(step)
                else:
                    if current_group:
                        parallel_groups.append(current_group)
                        current_group = []
                    parallel_groups.append([step])
            if current_group:
                parallel_groups.append(current_group)

            step_idx = len(results)
            for group in parallel_groups:
                if len(group) == 1:
                    step = group[0]
                    step_idx += 1
                    step_result = await self._execute_agent_step(
                        step.get("agent", ""), step.get("task", {}), context
                    )
                    results.append({
                        "step": step_idx,
                        "agent": step.get("agent", ""),
                        "task_type": step.get("task", {}).get("type", "unknown"),
                        "result": step_result,
                    })
                    self._collect_step_data(step.get("agent", ""), step_result,
                                            cleaned_items, analyzed_items)
                else:
                    tasks = []
                    for step in group:
                        tasks.append(
                            self._execute_agent_step(
                                step.get("agent", ""), step.get("task", {}), context
                            )
                        )
                    step_results = await asyncio.gather(*tasks, return_exceptions=True)
                    for i, (step, sr) in enumerate(zip(group, step_results)):
                        step_idx += 1
                        if isinstance(sr, Exception):
                            sr = {"status": "failed", "errors": [str(sr)]}
                        results.append({
                            "step": step_idx,
                            "agent": step.get("agent", ""),
                            "task_type": step.get("task", {}).get("type", "unknown"),
                            "result": sr,
                        })
                        self._collect_step_data(step.get("agent", ""), sr,
                                                cleaned_items, analyzed_items)

            aggregated = await self._aggregate_results(results, query)

            for item in cleaned_items:
                if self.provenance_chain:
                    try:
                        await self.provenance_chain.record_provenance(
                            intelligence_id=item.get("id", uuid4().hex),
                            stage="cleaned",
                            input_data={"source": item.get("source", "unknown")},
                            output_data={"content": (item.get("content", "") or "")[:500]},
                        )
                    except Exception as exc:
                        self.logger.warning(f"Provenance chain record failed for cleaned: {exc}")
            if self.message_queue and cleaned_items:
                try:
                    await self.message_queue.publish(
                        TOPIC_INTELLIGENCE_CLEANED,
                        {"items": cleaned_items, "count": len(cleaned_items)},
                    )
                except Exception as exc:
                    self.logger.warning(f"Message queue publish failed for cleaned: {exc}")

            for item in analyzed_items:
                content = item.get("analysis_summary", "") or item.get("content", "")
                if self.ner_engine:
                    try:
                        ner_entities = await self.ner_engine.extract(content)
                        if ner_entities:
                            item["ner_entities"] = [e.to_dict() for e in ner_entities]
                    except Exception as exc:
                        self.logger.warning(f"NER extraction failed: {exc}")
                if self.cross_validator:
                    try:
                        evidence_list = []
                        sources = item.get("sources", [])
                        for src in sources:
                            evidence_list.append(Evidence(
                                id=uuid4().hex,
                                source_id=src.get("id", ""),
                                source_type=src.get("type", "unknown"),
                                content=src.get("content", ""),
                                confidence=src.get("confidence", 0.5),
                            ))
                        if evidence_list:
                            cv_result = self.cross_validator.cross_validate(evidence_list)
                            item["cross_validation"] = cv_result
                    except Exception as exc:
                        self.logger.warning(f"Cross validation failed: {exc}")
                if self.hallucination_detector:
                    try:
                        original = item.get("original_content", "") or item.get("content", "")
                        analysis_text = item.get("analysis_summary", "") or json.dumps(item, ensure_ascii=False, default=str)[:1000]
                        hallucination_report = await self.hallucination_detector.detect_hallucination(
                            original, analysis_text
                        )
                        if hallucination_report.is_likely_hallucination:
                            item["confirmation_status"] = "unconfirmed"
                            item["hallucination_score"] = hallucination_report.hallucination_score
                        item["hallucination_report"] = hallucination_report.to_dict()
                    except Exception as exc:
                        self.logger.warning(f"Hallucination detection failed: {exc}")
                if self.evidence_chain:
                    try:
                        evidence_list = await self.evidence_chain.create_evidence_chain(
                            conclusion=item.get("analysis_summary", ""),
                            analysis_result=item,
                        )
                        item["evidence_chain_created"] = True
                    except Exception as exc:
                        self.logger.warning(f"Evidence chain creation failed for analyzed: {exc}")
            if self.message_queue and analyzed_items:
                try:
                    await self.message_queue.publish(
                        TOPIC_INTELLIGENCE_ANALYZED,
                        {"items": analyzed_items, "count": len(analyzed_items)},
                    )
                except Exception as exc:
                    self.logger.warning(f"Message queue publish failed for analyzed: {exc}")

            for r in results:
                if r.get("agent") == "graph_builder" and r.get("result", {}).get("status") == "success":
                    data = r.get("result", {}).get("data", {})
                    new_entities = data.get("new_entities", [])
                    if self.message_queue and new_entities:
                        try:
                            await self.message_queue.publish(
                                TOPIC_ENTITY_DISCOVERED,
                                {"entities": new_entities, "count": len(new_entities)},
                            )
                        except Exception as exc:
                            self.logger.warning(f"Message queue publish failed for entity_discovered: {exc}")

            report = await self._generate_report(query, aggregated)

            try:
                evidence_list = await self.evidence_chain.create_evidence_chain(
                    conclusion=report.get("summary", query),
                    analysis_result={
                        "raw_intelligence_ids": [
                            item.get("id", "") for item in collected_items
                        ],
                        "analysis_summary": report.get("summary", ""),
                        "confidence_score": report.get("confidence_score", 0.5),
                        "entity_ids": [
                            e.get("value", "")
                            for item in cleaned_items
                            for e in item.get("entity_details", [])
                        ],
                    },
                )

                verification = await self.evidence_chain.verify(
                    conclusion=report.get("summary", query),
                    sources=evidence_list,
                )

                report["evidence_verification"] = verification.to_dict()
                original_confidence = report.get("confidence_score", 0.5)
                report["confidence_score"] = max(
                    0.0, min(1.0, original_confidence * verification.confidence)
                )
            except Exception as exc:
                self.logger.warning(f"Evidence verification failed: {exc}")

            end_time = datetime.now(timezone.utc)
            execution_record = {
                "execution_id": execution_id,
                "query": query,
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "duration_seconds": (end_time - start_time).total_seconds(),
                "steps": len(plan),
                "results_summary": {
                    "collected": len(collected_items),
                    "cleaned": len(cleaned_items),
                    "analyzed": len(analyzed_items),
                },
                "status": "success",
            }
            self.execution_history.append(execution_record)
            self._save_history()

            return {
                "execution_id": execution_id,
                "query": query,
                "plan": plan,
                "step_results": results,
                "report": report,
                "collected_count": len(collected_items),
                "cleaned_count": len(cleaned_items),
                "analyzed_count": len(analyzed_items),
                "status": "success",
            }

        except Exception as exc:
            self.logger.error(f"Query execution failed [{execution_id}]: {exc}")
            end_time = datetime.now(timezone.utc)
            execution_record = {
                "execution_id": execution_id,
                "query": query,
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "duration_seconds": (end_time - start_time).total_seconds(),
                "status": "failed",
                "error": str(exc),
            }
            self.execution_history.append(execution_record)
            self._save_history()

            return {
                "execution_id": execution_id,
                "query": query,
                "status": "failed",
                "error": str(exc),
            }

    async def execute_pir(self, pir_id: str) -> Dict:
        pir = await self.pir_engine.get_pir(pir_id)
        if not pir:
            return {"error": f"PIR {pir_id} not found"}

        self.logger.info(f"Executing PIR: {pir_id} - {pir.title}")

        tasks = await self.pir_engine.decompose_pir(pir)

        task_results: List[Dict] = []
        for task in tasks:
            try:
                await self.pir_engine.update_task_status(
                    task.id, PIRTaskStatus.RUNNING.value
                )

                agent_task = self._pir_task_to_agent_task(task, pir)
                step_result = await self._execute_agent_step(
                    task.agent_type, agent_task
                )

                await self.pir_engine.update_task_status(
                    task.id,
                    PIRTaskStatus.COMPLETED.value,
                    result=step_result,
                )

                task_results.append({
                    "task_id": task.id,
                    "agent_type": task.agent_type,
                    "status": "completed",
                    "result": step_result,
                })

            except Exception as exc:
                self.logger.error(
                    f"PIR task {task.id} failed: {exc}"
                )
                await self.pir_engine.update_task_status(
                    task.id, PIRTaskStatus.FAILED.value
                )
                task_results.append({
                    "task_id": task.id,
                    "agent_type": task.agent_type,
                    "status": "failed",
                    "error": str(exc),
                })

        evaluation = await self.pir_engine.evaluate_pir(pir_id)

        try:
            report = await self.pir_engine.generate_pir_report(pir_id)
            report_data = report.model_dump()
        except Exception as exc:
            self.logger.error(f"PIR report generation failed: {exc}")
            report_data = {
                "title": f"情报报告: {pir.title}",
                "summary": "报告生成失败",
                "error": str(exc),
            }

        return {
            "pir_id": pir_id,
            "title": pir.title,
            "task_results": task_results,
            "evaluation": evaluation,
            "report": report_data,
        }

    def _collect_step_data(self, agent_name: str, step_result: Dict,
                           cleaned_items: List[Dict], analyzed_items: List[Dict]):
        if step_result.get("status") != "success":
            return
        data = step_result.get("data", {})
        if agent_name == "cleaner":
            if "cleaned_intelligence" in data:
                cleaned_items.append(data["cleaned_intelligence"])
            if "cleaned_intelligences" in data:
                cleaned_items.extend(data["cleaned_intelligences"])
        elif agent_name == "analyst":
            if "analyzed_intelligence" in data:
                analyzed_items.append(data["analyzed_intelligence"])

    async def _plan_execution(self, query: str) -> List[Dict]:
        system_prompt = (
            "你是一个黑灰产情报分析任务规划专家。根据用户的查询，"
            "规划需要执行的Agent任务序列。\n\n"
            "可用的Agent：\n"
            "- collector: 情报采集，从各渠道搜索和收集情报\n"
            "- cleaner: 情报清洗，解码黑话、提取实体、标准化数据\n"
            "- analyst: 情报分析，识别威胁模式、评估威胁等级、分析攻击链\n"
            "- graph_builder: 图谱构建，更新知识图谱、发现关联关系\n\n"
            "任务类型：\n"
            "- collector: collect（采集）, search（搜索已有数据）\n"
            "- cleaner: clean（清洗单条）, batch_clean（批量清洗）\n"
            "- analyst: analyze（深度分析）, find_patterns（模式发现）, "
            "reconstruct_chain（链路重建）, predict_trend（趋势预测）\n"
            "- graph_builder: build（构建图谱）, query（查询图谱）, "
            "trace（追踪链路）, find_gangs（发现团伙）\n\n"
            "返回JSON数组，按执行顺序排列，每个元素包含：\n"
            "- agent: agent名称（collector/cleaner/analyst/graph_builder）\n"
            "- task: 任务对象，包含type和其他参数\n\n"
            "只返回JSON数组，不要其他内容。"
        )
        prompt = (
            f"用户查询：{query}\n\n"
            f"请规划执行任务序列。"
        )

        try:
            cache_key = query.strip().lower()[:100]
            if cache_key in self._plan_cache:
                self.logger.info(f"Using cached plan for: {query[:50]}")
                return self._plan_cache[cache_key]

            result = await self.llm.generate_json(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=settings.LLM_TEMPERATURE_CREATIVE,
            )
            if isinstance(result, list) and result:
                validated_plan = []
                for step in result:
                    if not isinstance(step, dict):
                        continue
                    agent = step.get("agent", "")
                    task = step.get("task", {})
                    if agent in ("collector", "cleaner", "analyst", "graph_builder"):
                        validated_plan.append(step)
                if validated_plan:
                    if len(self._plan_cache) >= self._plan_cache_max:
                        oldest_key = next(iter(self._plan_cache))
                        del self._plan_cache[oldest_key]
                    self._plan_cache[cache_key] = validated_plan
                    return validated_plan
        except Exception as exc:
            self.logger.warning(f"LLM planning failed, using default plan: {exc}")

        return self._default_plan(query)

    async def _aggregate_results(
        self, results: List[Dict], query: str
    ) -> Dict:
        successful = [r for r in results if r.get("result", {}).get("status") == "success"]
        failed = [r for r in results if r.get("result", {}).get("status") == "failed"]

        collected_data: List[Dict] = []
        cleaned_data: List[Dict] = []
        analyzed_data: List[Dict] = []
        graph_data: List[Dict] = []

        for r in successful:
            agent = r.get("agent", "")
            data = r.get("result", {}).get("data", {})

            if agent == "collector":
                items = data.get("items", [])
                collected_data.extend(items)
            elif agent == "cleaner":
                if "cleaned_intelligence" in data:
                    cleaned_data.append(data["cleaned_intelligence"])
                if "cleaned_intelligences" in data:
                    cleaned_data.extend(data["cleaned_intelligences"])
            elif agent == "analyst":
                if "analyzed_intelligence" in data:
                    analyzed_data.append(data["analyzed_intelligence"])
                if "patterns" in data:
                    analyzed_data.append({"patterns": data["patterns"]})
                if "technique_chain" in data:
                    analyzed_data.append({"technique_chain": data["technique_chain"]})
                if "trend_prediction" in data:
                    analyzed_data.append({"trend_prediction": data["trend_prediction"]})
            elif agent == "graph_builder":
                graph_data.append(data)

        context_parts: List[str] = []
        for item in analyzed_data[:5]:
            summary = item.get("analysis_summary", "")
            if summary:
                context_parts.append(f"分析结果: {summary[:300]}")
            patterns = item.get("patterns", [])
            if patterns:
                for p in patterns[:3]:
                    context_parts.append(
                        f"攻击模式: {p.get('pattern_name', '')} - {p.get('description', '')[:200]}"
                    )
        for item in cleaned_data[:3]:
            content = item.get("content", "")
            decoded = item.get("decoded_content", "")
            if decoded:
                context_parts.append(f"清洗情报: {decoded[:300]}")
            elif content:
                context_parts.append(f"原始情报: {content[:300]}")

        context_text = "\n\n".join(context_parts) if context_parts else "暂无详细分析数据"

        system_prompt = (
            "你是一个黑灰产情报综合分析专家。根据多个Agent的分析结果，"
            "综合归纳关键发现和结论。\n\n"
            "返回JSON对象，包含：\n"
            "- key_findings: 关键发现列表（字符串数组，每条不超过100字）\n"
            "- threat_assessment: 威胁评估（critical/high/medium/low/info）\n"
            "- main_threat_categories: 主要威胁类别列表\n"
            "- confidence: 综合置信度（0-1）\n"
            "- summary: 综合分析摘要（300字以内）\n\n"
            "只返回JSON，不要其他内容。"
        )
        prompt = (
            f"用户查询：{query}\n\n"
            f"成功步骤数：{len(successful)}\n"
            f"失败步骤数：{len(failed)}\n"
            f"采集情报数：{len(collected_data)}\n"
            f"清洗情报数：{len(cleaned_data)}\n"
            f"分析结果数：{len(analyzed_data)}\n\n"
            f"详细数据：\n{context_text}"
        )

        try:
            result = await self.llm.generate_json(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=settings.LLM_TEMPERATURE_CREATIVE,
            )
            if isinstance(result, dict):
                return {
                    "key_findings": result.get("key_findings", []),
                    "threat_assessment": result.get("threat_assessment", "info"),
                    "main_threat_categories": result.get("main_threat_categories", []),
                    "confidence": result.get("confidence", 0.5),
                    "summary": result.get("summary", ""),
                    "collected_count": len(collected_data),
                    "cleaned_count": len(cleaned_data),
                    "analyzed_count": len(analyzed_data),
                    "graph_operations": len(graph_data),
                    "successful_steps": len(successful),
                    "failed_steps": len(failed),
                }
        except Exception as exc:
            self.logger.warning(f"Result aggregation failed: {exc}")

        threat_levels = []
        for item in cleaned_data:
            tl = item.get("threat_level", "info")
            threat_levels.append(tl)
        for item in analyzed_data:
            tl = item.get("threat_level", "info")
            threat_levels.append(tl)

        overall_threat = self._pick_highest_threat(threat_levels)

        return {
            "key_findings": [f"查询: {query}", f"共采集{len(collected_data)}条情报"],
            "threat_assessment": overall_threat,
            "main_threat_categories": [],
            "confidence": settings.CONFIDENCE_LOW,
            "summary": f"针对查询「{query}」的分析完成，共处理{len(collected_data)}条情报。",
            "collected_count": len(collected_data),
            "cleaned_count": len(cleaned_data),
            "analyzed_count": len(analyzed_data),
            "graph_operations": len(graph_data),
            "successful_steps": len(successful),
            "failed_steps": len(failed),
        }

    async def _generate_report(
        self, query: str, aggregated: Dict
    ) -> Dict:
        key_findings = aggregated.get("key_findings", [])
        threat_assessment = aggregated.get("threat_assessment", "info")
        main_categories = aggregated.get("main_threat_categories", [])
        confidence = aggregated.get("confidence", 0.5)
        summary = aggregated.get("summary", "")

        context_parts = [
            f"威胁评估：{threat_assessment}",
            f"主要威胁类别：{', '.join(main_categories) if main_categories else '未分类'}",
            f"综合置信度：{confidence:.2f}",
            f"关键发现：{'; '.join(key_findings[:10]) if key_findings else '无'}",
            f"分析摘要：{summary}",
        ]
        context = "\n".join(context_parts)

        try:
            report = await self.report_generator.generate_report(
                title=query[:100],
                context=context,
            )
            return report.model_dump()
        except Exception as exc:
            self.logger.warning(f"Report generation via ReportGenerator failed: {exc}")
            report = IntelligenceReport(
                title=f"情报报告: {query[:50]}",
                summary=summary,
                key_findings=key_findings,
                threat_actors=[],
                iocs=[],
                recommendations=["建议持续监控相关情报动态"],
                confidence_score=confidence,
                evidence_chain=[],
            )
            return report.model_dump()

    async def _execute_agent_step(
        self, agent_name: str, task: Dict, context: Dict = None
    ) -> Dict:
        if context and isinstance(task, dict):
            task.setdefault("context", context)

        agent_timeout = 180.0
        try:
            if agent_name == "collector":
                result = await asyncio.wait_for(self.collector.execute(task), timeout=agent_timeout)
            elif agent_name == "cleaner":
                result = await asyncio.wait_for(self.cleaner.execute(task), timeout=agent_timeout)
            elif agent_name == "analyst":
                result = await asyncio.wait_for(self.analyst.execute(task), timeout=agent_timeout)
            elif agent_name == "graph_builder":
                result = await asyncio.wait_for(self.graph_builder.execute(task), timeout=agent_timeout)
            else:
                return {
                    "status": "failed",
                    "errors": [f"Unknown agent: {agent_name}"],
                }
            return result
        except asyncio.TimeoutError:
            self.logger.error(f"Agent {agent_name} timed out after {agent_timeout}s")
            return {
                "status": "failed",
                "errors": [f"Agent {agent_name} timed out after {agent_timeout}s"],
            }
        except Exception as exc:
            self.logger.error(f"Agent {agent_name} execution failed: {exc}")
            return {
                "status": "failed",
                "errors": [str(exc)],
            }

    def _pir_task_to_agent_task(self, task, pir) -> Dict:
        agent_type = task.agent_type
        description = task.task_description

        if agent_type == "collector":
            return {
                "type": "collect",
                "source": "all",
                "keywords": pir.keywords,
                "max_results": 50,
            }
        elif agent_type == "cleaner":
            return {
                "type": "batch_clean",
                "raw_intelligence": [],
                "decode_blacktalk": True,
                "extract_entities": True,
            }
        elif agent_type == "analyst":
            return {
                "type": "analyze",
                "cleaned_intelligence": {},
                "context": {
                    "pir_id": pir.id,
                    "pir_title": pir.title,
                    "keywords": pir.keywords,
                },
            }
        elif agent_type == "graph_builder":
            return {
                "type": "build",
                "analysis_result": {},
            }
        else:
            return {"type": "unknown", "description": description}

    def _default_plan(self, query: str) -> List[Dict]:
        keywords = query.split()[:5] if query else []
        return [
            {
                "agent": "collector",
                "task": {
                    "type": "collect",
                    "source": "all",
                    "keywords": keywords,
                    "max_results": 50,
                },
            },
            {
                "agent": "cleaner",
                "task": {
                    "type": "batch_clean",
                    "raw_intelligence": [],
                    "decode_blacktalk": True,
                    "extract_entities": True,
                },
            },
            {
                "agent": "analyst",
                "task": {
                    "type": "analyze",
                    "cleaned_intelligence": {},
                },
            },
            {
                "agent": "graph_builder",
                "task": {
                    "type": "build",
                    "analysis_result": {},
                },
            },
        ]

    def _pick_highest_threat(self, threat_levels: List[str]) -> str:
        priority = {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "info": 1,
        }
        if not threat_levels:
            return "info"
        highest = "info"
        for level in threat_levels:
            if priority.get(level, 0) > priority.get(highest, 0):
                highest = level
        return highest

    def get_execution_history(self, limit: int = 20) -> List[Dict]:
        return self.execution_history[-limit:]

    def _save_history(self):
        try:
            os.makedirs(os.path.dirname(self._history_file), exist_ok=True)
            data = self.execution_history[-500:]
            with open(self._history_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2, default=str)
            self.logger.debug(f"Saved {len(data)} execution history records to {self._history_file}")
        except Exception as exc:
            self.logger.warning(f"Failed to save execution history: {exc}")

    def _load_history(self):
        try:
            file_path = Path(self._history_file)
            if not file_path.exists():
                self.logger.debug("No persisted execution history found")
                return
            with open(self._history_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                self.execution_history = data
                self.logger.info(f"Loaded {len(data)} execution history records from disk")
        except Exception as exc:
            self.logger.warning(f"Failed to load execution history: {exc}")

    def get_agent_status(self) -> Dict:
        return {
            "orchestrator": "active",
            "collector": {
                "name": self.collector.name,
                "registered_sources": list(self.collector.collectors.keys()),
                "active_monitors": sum(
                    1 for m in self.collector._monitor_tasks.values()
                    if m.get("status") == "active"
                ),
            },
            "cleaner": {
                "name": self.cleaner.name,
                "blacktalk_terms_count": len(
                    self.blacktalk_engine._dictionary
                ),
            },
            "analyst": {
                "name": self.analyst.name,
            },
            "graph_builder": {
                "name": self.graph_builder.name,
            },
            "execution_history_count": len(self.execution_history),
        }
