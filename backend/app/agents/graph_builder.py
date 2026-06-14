from datetime import datetime
from typing import Dict, List, Optional
from uuid import uuid4

from loguru import logger

from app.config import settings
from app.agents.base import BaseAgent
from app.core.evidence_chain import EvidenceChain
from app.core.knowledge_graph import KnowledgeGraph
from app.core.llm import LLMService
from app.core.vector_store import VectorStore
from app.models.entity import Entity, EntityType, Relation, RelationType
from app.models.intelligence import ThreatLevel


_ENTITY_TYPE_MAP = {
    "ip": EntityType.IP,
    "domain": EntityType.DOMAIN,
    "url": EntityType.URL,
    "hash": EntityType.HASH,
    "email": EntityType.EMAIL,
    "phone": EntityType.PHONE,
    "account": EntityType.ACCOUNT,
    "tool": EntityType.TOOL,
    "blacktalk": EntityType.BLACKTALK,
    "organization": EntityType.ORGANIZATION,
    "person": EntityType.PERSON,
    "crypto_wallet": EntityType.CRYPTO_WALLET,
    "payment_method": EntityType.PAYMENT_METHOD,
    "malware": EntityType.MALWARE,
    "service": EntityType.SERVICE,
}

_RELATION_TYPE_MAP = {
    "uses": RelationType.USES,
    "belongs_to": RelationType.BELONGS_TO,
    "communicates_with": RelationType.COMMUNICATES_WITH,
    "operates": RelationType.OPERATES,
    "sells": RelationType.SELLS,
    "buys": RelationType.BUYS,
    "associated_with": RelationType.ASSOCIATED_WITH,
    "located_in": RelationType.LOCATED_IN,
    "controls": RelationType.CONTROLS,
    "derived_from": RelationType.DERIVED_FROM,
    "使用": RelationType.USES,
    "属于": RelationType.BELONGS_TO,
    "通信": RelationType.COMMUNICATES_WITH,
    "运营": RelationType.OPERATES,
    "出售": RelationType.SELLS,
    "购买": RelationType.BUYS,
    "关联": RelationType.ASSOCIATED_WITH,
    "位于": RelationType.LOCATED_IN,
    "控制": RelationType.CONTROLS,
    "来源于": RelationType.DERIVED_FROM,
}


class GraphBuilderAgent(BaseAgent):
    def __init__(
        self,
        llm: LLMService,
        vector_store: VectorStore,
        knowledge_graph: KnowledgeGraph,
        evidence_chain: EvidenceChain,
    ):
        super().__init__("graph_builder", llm, vector_store)
        self.knowledge_graph = knowledge_graph
        self.evidence_chain = evidence_chain

    async def execute(self, task: Dict) -> Dict:
        task_type = task.get("type", "build")
        try:
            if task_type == "build":
                analysis_result = task.get("analysis_result")
                if not analysis_result:
                    return self._create_task_result(
                        status="failed",
                        data={},
                        errors=["analysis_result is required for build task"],
                    )
                build_result = await self.build_from_analysis(analysis_result)
                result = self._create_task_result(
                    status="success",
                    data=build_result,
                )

            elif task_type == "query":
                query = task.get("query")
                if not query:
                    return self._create_task_result(
                        status="failed",
                        data={},
                        errors=["query is required for query task"],
                    )
                query_result = await self.query_graph(query)
                result = self._create_task_result(
                    status="success",
                    data=query_result,
                )

            elif task_type == "trace":
                entity_id = task.get("entity_id")
                if not entity_id:
                    return self._create_task_result(
                        status="failed",
                        data={},
                        errors=["entity_id is required for trace task"],
                    )
                trace_result = await self.trace_attack_chain(entity_id)
                result = self._create_task_result(
                    status="success",
                    data=trace_result,
                )

            elif task_type == "find_gangs":
                min_size = task.get("min_size", 3)
                gangs = await self.find_gangs(min_size)
                result = self._create_task_result(
                    status="success",
                    data={
                        "gang_count": len(gangs),
                        "gangs": gangs,
                    },
                )

            else:
                result = self._create_task_result(
                    status="failed",
                    data={},
                    errors=[f"Unknown task type: {task_type}"],
                )

        except Exception as exc:
            self.logger.error(f"GraphBuilder task failed: {exc}")
            result = self._create_task_result(
                status="failed",
                data={},
                errors=[str(exc)],
            )

        await self._log_execution(task, result)
        return result

    async def build_from_analysis(self, analysis_result: Dict) -> Dict:
        content = analysis_result.get("content", "")
        analysis_summary = analysis_result.get("analysis_summary", "")
        entity_details = analysis_result.get("entity_details", [])
        cleaned_id = analysis_result.get("cleaned_id", "")
        threat_categories = analysis_result.get("threat_categories", [])
        confidence_score = analysis_result.get("confidence_score", 0.5)

        full_content = content
        if analysis_summary:
            full_content = f"{content}\n分析摘要：{analysis_summary}"

        if not entity_details:
            entity_details = await self._extract_entities_from_content(full_content)

        added_entities: List[Dict] = []
        entity_id_map: Dict[str, str] = {}

        for entity_data in entity_details:
            entity_type_str = entity_data.get("type", "other").lower()
            entity_value = entity_data.get("value", "")
            entity_context = entity_data.get("context", "")

            if not entity_value:
                continue

            entity_type = _ENTITY_TYPE_MAP.get(entity_type_str)
            if not entity_type:
                try:
                    entity_type = EntityType(entity_type_str)
                except ValueError:
                    entity_type = EntityType.ACCOUNT

            existing = await self.knowledge_graph.search_entities(
                query=entity_value,
                entity_type=entity_type.value,
                limit=1,
            )

            if existing and existing[0].value == entity_value:
                entity_id_map[entity_value] = existing[0].id
                continue

            entity = Entity(
                type=entity_type,
                value=entity_value,
                context=entity_context,
                source_ids=[cleaned_id] if cleaned_id else [],
                confidence=confidence_score,
                metadata={
                    "threat_categories": threat_categories,
                    "discovered_via": "graph_builder",
                },
            )

            await self.knowledge_graph.add_entity(entity)
            entity_id_map[entity_value] = entity.id
            added_entities.append(entity.model_dump())

            try:
                await self.vector_store.add_entity(
                    entity_id=entity.id,
                    content=f"{entity_type.value}: {entity_value} {entity_context}",
                    metadata={
                        "type": entity_type.value,
                        "value": entity_value,
                        "confidence": confidence_score,
                    },
                )
            except Exception as exc:
                self.logger.warning(
                    f"Failed to add entity to vector store: {exc}"
                )

        relations = await self._extract_relations(full_content, added_entities)

        added_relations: List[Dict] = []
        for rel_data in relations:
            source_value = rel_data.get("source", "")
            target_value = rel_data.get("target", "")
            rel_type_str = rel_data.get("type", "associated_with")
            evidence = rel_data.get("evidence", "")
            rel_confidence = rel_data.get("confidence", 0.5)

            source_id = entity_id_map.get(source_value)
            target_id = entity_id_map.get(target_value)

            if not source_id or not target_id:
                if not source_id:
                    source_entities = await self.knowledge_graph.search_entities(
                        query=source_value, limit=1
                    )
                    if source_entities:
                        source_id = source_entities[0].id
                        entity_id_map[source_value] = source_id
                if not target_id:
                    target_entities = await self.knowledge_graph.search_entities(
                        query=target_value, limit=1
                    )
                    if target_entities:
                        target_id = target_entities[0].id
                        entity_id_map[target_value] = target_id

            if not source_id or not target_id or source_id == target_id:
                continue

            rel_type = _RELATION_TYPE_MAP.get(rel_type_str, RelationType.ASSOCIATED_WITH)

            relation = Relation(
                source_entity_id=source_id,
                target_entity_id=target_id,
                type=rel_type,
                confidence=rel_confidence,
                evidence=evidence,
            )

            await self.knowledge_graph.add_relation(relation)
            added_relations.append(relation.model_dump())

        try:
            await self.knowledge_graph.save()
        except Exception as exc:
            self.logger.warning(f"Failed to save knowledge graph: {exc}")

        return {
            "entities_added": len(added_entities),
            "relations_added": len(added_relations),
            "entities": added_entities,
            "relations": added_relations,
        }

    async def query_graph(self, query: Dict) -> Dict:
        query_type = query.get("type", "search")
        results: Dict = {"query_type": query_type}

        if query_type == "search":
            search_text = query.get("text", "")
            entity_type = query.get("entity_type")
            limit = query.get("limit", 20)
            entities = await self.knowledge_graph.search_entities(
                query=search_text,
                entity_type=entity_type,
                limit=limit,
            )
            results["entities"] = [e.model_dump() for e in entities]
            results["count"] = len(entities)

        elif query_type == "entity_lookup":
            entity_id = query.get("entity_id", "")
            entity = await self.knowledge_graph.get_entity(entity_id)
            if entity:
                relations = await self.knowledge_graph.get_entity_relations(
                    entity_id
                )
                results["entity"] = entity.model_dump()
                results["relations"] = [r.model_dump() for r in relations]
            else:
                results["entity"] = None
                results["relations"] = []

        elif query_type == "path":
            source_id = query.get("source_id", "")
            target_id = query.get("target_id", "")
            max_depth = query.get("max_depth", 5)
            paths = await self.knowledge_graph.find_path(
                source_id, target_id, max_depth
            )
            results["paths"] = paths
            results["path_count"] = len(paths)

        elif query_type == "subgraph":
            entity_ids = query.get("entity_ids", [])
            depth = query.get("depth", 1)
            subgraph = await self.knowledge_graph.get_subgraph(
                entity_ids, depth
            )
            results["subgraph"] = subgraph

        elif query_type == "statistics":
            stats = await self.knowledge_graph.get_statistics()
            results["statistics"] = stats

        else:
            results["error"] = f"Unknown query type: {query_type}"

        return results

    async def trace_attack_chain(self, entity_id: str) -> Dict:
        entity = await self.knowledge_graph.get_entity(entity_id)
        if not entity:
            return {
                "entity_id": entity_id,
                "found": False,
                "error": f"Entity {entity_id} not found",
            }

        relations = await self.knowledge_graph.get_entity_relations(
            entity_id, direction="both"
        )

        chain_stages: List[Dict] = []
        visited: set = {entity_id}
        frontier = [entity_id]

        for _ in range(3):
            next_frontier: List[str] = []
            for fid in frontier:
                related = await self.knowledge_graph.get_entity_relations(
                    fid, direction="both"
                )
                for rel in related:
                    other_id = (
                        rel.target_entity_id
                        if rel.source_entity_id == fid
                        else rel.source_entity_id
                    )
                    if other_id in visited:
                        continue
                    visited.add(other_id)

                    other_entity = await self.knowledge_graph.get_entity(other_id)
                    if not other_entity:
                        continue

                    chain_stages.append({
                        "entity_id": other_id,
                        "entity_type": other_entity.type.value,
                        "entity_value": other_entity.value,
                        "relation_type": rel.type.value,
                        "relation_confidence": rel.confidence,
                        "evidence": rel.evidence,
                    })
                    next_frontier.append(other_id)

            frontier = next_frontier
            if not frontier:
                break

        subgraph = await self.knowledge_graph.get_subgraph(
            list(visited), depth=1
        )

        chain_description = await self._generate_chain_description(
            entity, chain_stages
        )

        return {
            "entity_id": entity_id,
            "found": True,
            "entity": entity.model_dump(),
            "chain_stages": chain_stages,
            "chain_description": chain_description,
            "connected_entities": len(chain_stages),
            "subgraph": subgraph,
        }

    async def find_gangs(self, min_size: int = 3) -> List[Dict]:
        communities = await self.knowledge_graph.find_communities(
            algorithm="louvain"
        )

        gangs: List[Dict] = []
        for community in communities:
            if len(community) < min_size:
                continue

            members: List[Dict] = []
            member_types: Dict[str, int] = {}
            activities: List[str] = []

            for member_id in community:
                entity = await self.knowledge_graph.get_entity(member_id)
                if not entity:
                    continue

                members.append({
                    "entity_id": entity.id,
                    "type": entity.type.value,
                    "value": entity.value,
                    "confidence": entity.confidence,
                })

                type_key = entity.type.value
                member_types[type_key] = member_types.get(type_key, 0) + 1

                relations = await self.knowledge_graph.get_entity_relations(
                    member_id
                )
                for rel in relations:
                    if rel.evidence and rel.evidence not in activities:
                        activities.append(rel.evidence)

            if not members:
                continue

            gang_name = await self._generate_gang_name(members, member_types)

            gang = {
                "gang_id": uuid4().hex,
                "name": gang_name,
                "member_count": len(members),
                "members": members,
                "member_types": member_types,
                "activities": activities[:10],
                "risk_level": self._assess_gang_risk(members, member_types),
            }
            gangs.append(gang)

        gangs.sort(key=lambda g: g["member_count"], reverse=True)
        return gangs

    async def _extract_relations(
        self, content: str, entities: List[Dict]
    ) -> List[Dict]:
        if not entities or len(entities) < 2:
            return []

        entity_descriptions = "\n".join(
            f"- {e.get('type', 'unknown')}: {e.get('value', '')}"
            for e in entities[:30]
        )

        system_prompt = (
            "你是一个黑灰产实体关系提取专家。根据文本内容和已识别的实体，"
            "提取实体之间的关系。\n\n"
            "关系类型：\n"
            "- uses: 使用（某人使用某工具）\n"
            "- belongs_to: 属于（某账号属于某人）\n"
            "- communicates_with: 通信（两个实体之间有通信联系）\n"
            "- operates: 运营（某人运营某平台）\n"
            "- sells: 出售（某人出售某物）\n"
            "- buys: 购买（某人购买某物）\n"
            "- associated_with: 关联（两个实体有关联）\n"
            "- located_in: 位于（某实体位于某地）\n"
            "- controls: 控制（某人控制某资源）\n"
            "- derived_from: 来源于（某物来源于另一物）\n\n"
            "返回JSON数组，每个元素包含：\n"
            "- source: 源实体的value值\n"
            "- target: 目标实体的value值\n"
            "- type: 关系类型（英文）\n"
            "- evidence: 支持该关系的文本证据\n"
            "- confidence: 置信度（0-1）\n\n"
            "只返回JSON数组，不要其他内容。如果没有关系，返回空数组[]。"
        )
        prompt = (
            f"文本内容：{content[:2000]}\n\n"
            f"已识别实体：\n{entity_descriptions}\n\n"
            f"请提取实体之间的关系。"
        )

        try:
            result = await self.llm.generate_json(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=settings.LLM_TEMPERATURE_DEFAULT,
            )
            if isinstance(result, list):
                return result
            if isinstance(result, dict) and "relations" in result:
                return result["relations"]
            return []
        except Exception as exc:
            self.logger.warning(f"Relation extraction failed: {exc}")
            return []

    async def _extract_entities_from_content(
        self, content: str
    ) -> List[Dict]:
        if not content:
            return []

        system_prompt = (
            "你是一个黑灰产情报实体提取专家。从以下文本中提取所有有价值的实体。\n\n"
            "实体类型：ip, domain, url, hash, email, phone, account, tool, "
            "organization, person, crypto_wallet, payment_method, malware, service\n\n"
            "返回JSON数组，每个元素包含：\n"
            "- type: 实体类型\n"
            "- value: 实体值\n"
            "- context: 上下文\n\n"
            "只返回JSON数组。"
        )
        prompt = f"请提取实体：\n\n{content}"

        try:
            result = await self.llm.generate_json(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=settings.LLM_TEMPERATURE_ANALYSIS,
            )
            if isinstance(result, list):
                return [
                    e for e in result
                    if isinstance(e, dict) and e.get("value")
                ]
            return []
        except Exception as exc:
            self.logger.warning(f"Entity extraction from content failed: {exc}")
            return []

    async def _generate_chain_description(
        self, entity: Entity, chain_stages: List[Dict]
    ) -> str:
        if not chain_stages:
            return f"实体 {entity.value}（{entity.type.value}）未发现关联攻击链。"

        stages_text = "\n".join(
            f"- {s['entity_type']} {s['entity_value']} "
            f"(关系: {s['relation_type']}, 置信度: {s['relation_confidence']:.2f})"
            for s in chain_stages
        )

        system_prompt = (
            "你是一个黑灰产攻击链分析专家。根据起始实体和关联实体信息，"
            "生成一段攻击链描述（150字以内）。\n"
            "只返回描述文本，不要其他内容。"
        )
        prompt = (
            f"起始实体：{entity.type.value} - {entity.value}\n\n"
            f"关联实体：\n{stages_text}\n\n"
            f"请描述攻击链路。"
        )

        try:
            description = await self.llm.generate(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=settings.LLM_TEMPERATURE_CREATIVE,
                max_tokens=settings.LLM_MAX_TOKENS_SHORT,
            )
            return description.strip()
        except Exception as exc:
            self.logger.warning(f"Chain description generation failed: {exc}")
            return f"从 {entity.value} 出发，发现 {len(chain_stages)} 个关联实体。"

    async def _generate_gang_name(
        self, members: List[Dict], member_types: Dict[str, int]
    ) -> str:
        dominant_type = max(member_types, key=member_types.get) if member_types else "unknown"
        type_names = {
            "account": "账号",
            "ip": "IP",
            "domain": "域名",
            "tool": "工具",
            "organization": "组织",
            "person": "人员",
            "phone": "电话",
            "payment_method": "支付",
            "crypto_wallet": "钱包",
        }
        type_cn = type_names.get(dominant_type, dominant_type)
        return f"{type_cn}关联团伙({len(members)}人)"

    def _assess_gang_risk(
        self, members: List[Dict], member_types: Dict[str, int]
    ) -> str:
        high_risk_types = {"tool", "malware", "organization", "crypto_wallet", "payment_method"}
        risk_score = 0

        for rtype in high_risk_types:
            if rtype in member_types:
                risk_score += member_types[rtype]

        if len(members) >= 10 or risk_score >= 5:
            return "critical"
        if len(members) >= 5 or risk_score >= 3:
            return "high"
        if len(members) >= 3 or risk_score >= 1:
            return "medium"
        return "low"
