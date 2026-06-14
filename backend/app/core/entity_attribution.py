import hashlib
import json
import os
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import numpy as np
from loguru import logger

from app.config import settings
from app.core.knowledge_graph import KnowledgeGraph
from app.core.vector_store import VectorStore


@dataclass
class EntityProfile:
    entity_id: str
    entity_type: str
    value: str
    platforms: List[str] = field(default_factory=list)
    behavioral_features: Dict[str, float] = field(default_factory=dict)
    embedding: Optional[List[float]] = None

    def to_dict(self) -> dict:
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "value": self.value,
            "platforms": self.platforms,
            "behavioral_features": self.behavioral_features,
        }


@dataclass
class AttributionResult:
    source_entity_id: str
    target_entity_id: str
    similarity: float
    source_platform: str
    target_platform: str
    evidence: List[str] = field(default_factory=list)
    confidence: float = 0.0

    def to_dict(self) -> dict:
        return {
            "source_entity_id": self.source_entity_id,
            "target_entity_id": self.target_entity_id,
            "similarity": self.similarity,
            "source_platform": self.source_platform,
            "target_platform": self.target_platform,
            "evidence": self.evidence,
            "confidence": self.confidence,
        }


@dataclass
class BehavioralFingerprint:
    entity_id: str
    entity_type: str
    entity_value: str
    embedding: Optional[List[float]] = None
    behavioral_features: Dict[str, float] = field(default_factory=dict)
    fingerprint_hash: str = ""
    platforms: List[str] = field(default_factory=list)
    created_at: str = ""

    def to_dict(self) -> dict:
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "entity_value": self.entity_value,
            "embedding": self.embedding,
            "behavioral_features": self.behavioral_features,
            "fingerprint_hash": self.fingerprint_hash,
            "platforms": self.platforms,
            "created_at": self.created_at,
        }


class TransEModel:
    def __init__(self, n_entities: int, n_relations: int, embed_dim: int = 64, margin: float = 1.0, norm: int = 2):
        self.n_entities = n_entities
        self.n_relations = n_relations
        self.embed_dim = embed_dim
        self.margin = margin
        self.norm = norm
        bound = 6.0 / (embed_dim ** 0.5)
        self.entity_embeddings = np.random.uniform(-bound, bound, (n_entities, embed_dim))
        self.relation_embeddings = np.random.uniform(-bound, bound, (n_relations, embed_dim))
        self._normalize()

    def _normalize(self):
        norms = np.linalg.norm(self.entity_embeddings, axis=1, keepdims=True)
        norms = np.clip(norms, 1e-8, None)
        self.entity_embeddings = self.entity_embeddings / norms
        norms = np.linalg.norm(self.relation_embeddings, axis=1, keepdims=True)
        norms = np.clip(norms, 1e-8, None)
        self.relation_embeddings = self.relation_embeddings / norms

    def score(self, h: int, r: int, t: int) -> float:
        h_emb = self.entity_embeddings[h]
        r_emb = self.relation_embeddings[r]
        t_emb = self.entity_embeddings[t]
        diff = h_emb + r_emb - t_emb
        return float(np.linalg.norm(diff, ord=self.norm))

    def train_step(self, positive_triples: List[Tuple[int, int, int]], lr: float = 0.01, n_neg: int = 1):
        total_loss = 0.0
        for h, r, t in positive_triples:
            pos_score = self.score(h, r, t)
            for _ in range(n_neg):
                corrupt_head = np.random.random() < 0.5
                if corrupt_head:
                    neg_h = np.random.randint(self.n_entities)
                    neg_score = self.score(neg_h, r, t)
                else:
                    neg_t = np.random.randint(self.n_entities)
                    neg_score = self.score(h, r, neg_t)

                loss = max(0.0, self.margin + pos_score - neg_score)
                total_loss += loss

                if loss > 0:
                    grad_pos = self._grad(h, r, t)
                    if corrupt_head:
                        grad_neg = self._grad(neg_h, r, t)
                        self.entity_embeddings[h] -= lr * grad_pos
                        self.entity_embeddings[neg_h] += lr * grad_neg
                    else:
                        grad_neg = self._grad(h, r, neg_t)
                        self.entity_embeddings[h] -= lr * grad_pos
                        self.entity_embeddings[neg_t] += lr * grad_neg
                    self.relation_embeddings[r] -= lr * grad_pos

            self._normalize()
        return total_loss / max(len(positive_triples), 1)

    def _grad(self, h: int, r: int, t: int) -> np.ndarray:
        diff = self.entity_embeddings[h] + self.relation_embeddings[r] - self.entity_embeddings[t]
        norm = np.linalg.norm(diff)
        if norm < 1e-8:
            return np.zeros_like(diff)
        if self.norm == 2:
            return diff / norm
        return np.sign(diff)

    def get_entity_embedding(self, entity_idx: int) -> np.ndarray:
        return self.entity_embeddings[entity_idx].copy()

    def save(self, path: str):
        data = {
            "n_entities": self.n_entities,
            "n_relations": self.n_relations,
            "embed_dim": self.embed_dim,
            "margin": self.margin,
            "norm": self.norm,
            "entity_embeddings": self.entity_embeddings.tolist(),
            "relation_embeddings": self.relation_embeddings.tolist(),
        }
        with open(path, "w") as f:
            json.dump(data, f)

    @classmethod
    def load(cls, path: str) -> "TransEModel":
        with open(path, "r") as f:
            data = json.load(f)
        model = cls(data["n_entities"], data["n_relations"], data["embed_dim"], data["margin"], data["norm"])
        model.entity_embeddings = np.array(data["entity_embeddings"])
        model.relation_embeddings = np.array(data["relation_embeddings"])
        return model


class EntityAttribution:
    SIMILARITY_THRESHOLD = 0.6
    EMBED_DIM = 64
    TRAIN_EPOCHS = 50
    TRAIN_LR = 0.01

    def __init__(self, vector_store: VectorStore, knowledge_graph: KnowledgeGraph):
        self.vector_store = vector_store
        self.knowledge_graph = knowledge_graph
        self._model: Optional[TransEModel] = None
        self._entity2idx: Dict[str, int] = {}
        self._idx2entity: Dict[int, str] = {}
        self._relation2idx: Dict[str, int] = {}
        self._idx2relation: Dict[int, str] = {}
        self._name2id: Dict[str, str] = {}
        self._persist_dir = "./model_data/attribution"
        os.makedirs(self._persist_dir, exist_ok=True)
        self._try_load_model()

    def _try_load_model(self) -> bool:
        model_path = os.path.join(self._persist_dir, "transe_model.json")
        meta_path = os.path.join(self._persist_dir, "metadata.json")
        if not os.path.exists(model_path) or not os.path.exists(meta_path):
            return False
        try:
            self._model = TransEModel.load(model_path)
            with open(meta_path, "r") as f:
                meta = json.load(f)
            self._entity2idx = meta.get("entity2idx", {})
            self._idx2entity = {int(v): k for k, v in self._entity2idx.items()}
            self._relation2idx = meta.get("relation2idx", {})
            self._idx2relation = {int(v): k for k, v in self._relation2idx.items()}
            self._name2id = meta.get("name2id", {})
            logger.info(f"TransE model loaded: {self._model.n_entities} entities, {self._model.n_relations} relations")
            return True
        except Exception as exc:
            logger.warning(f"Failed to load TransE model: {exc}")
            return False

    def _save_model(self):
        if self._model is None:
            return
        model_path = os.path.join(self._persist_dir, "transe_model.json")
        meta_path = os.path.join(self._persist_dir, "metadata.json")
        self._model.save(model_path)
        with open(meta_path, "w") as f:
            json.dump({
                "entity2idx": self._entity2idx,
                "relation2idx": self._relation2idx,
                "name2id": self._name2id,
            }, f)
        logger.info(f"TransE model saved: {self._model.n_entities} entities")

    def train_from_graph(self):
        if not self.knowledge_graph.graph or self.knowledge_graph.graph.number_of_nodes() == 0:
            logger.warning("Knowledge graph empty, cannot train TransE")
            return

        entities = list(self.knowledge_graph.graph.nodes())
        relations = set()
        triples = []

        for idx, eid in enumerate(entities):
            self._entity2idx[eid] = idx
            self._idx2entity[idx] = eid
            node_data = self.knowledge_graph.graph.nodes[eid]
            entity_value = node_data.get("value", "")
            if entity_value:
                self._name2id[entity_value.lower()] = eid

        for u, v, data in self.knowledge_graph.graph.edges(data=True):
            rtype = data.get("type", data.get("relation_type", "related_to"))
            if rtype not in self._relation2idx:
                ridx = len(self._relation2idx)
                self._relation2idx[rtype] = ridx
                self._idx2relation[ridx] = rtype
            relations.add(rtype)
            triples.append((self._entity2idx[u], self._relation2idx[rtype], self._entity2idx[v]))

        if len(triples) < 2:
            logger.warning("Too few triples for TransE training")
            return

        self._model = TransEModel(
            n_entities=len(entities),
            n_relations=len(self._relation2idx),
            embed_dim=self.EMBED_DIM,
        )

        logger.info(f"Training TransE: {len(triples)} triples, {len(entities)} entities, {len(self._relation2idx)} relations")

        for epoch in range(self.TRAIN_EPOCHS):
            np.random.shuffle(triples)
            batch = triples[:min(64, len(triples))]
            loss = self._model.train_step(batch, lr=self.TRAIN_LR)
            if (epoch + 1) % 10 == 0:
                logger.info(f"TransE epoch {epoch + 1}/{self.TRAIN_EPOCHS}, loss: {loss:.4f}")

        self._save_model()
        logger.info("TransE training complete")

    async def attribute_entity(self, entity_id: str, threshold: float = None) -> List[AttributionResult]:
        if threshold is None:
            threshold = self.SIMILARITY_THRESHOLD

        if self._model is None:
            self._try_load_model()

        resolved_id = entity_id
        if self._model is None or resolved_id not in self._entity2idx:
            if entity_id.lower() in self._name2id:
                resolved_id = self._name2id[entity_id.lower()]
            else:
                try:
                    search_results = await self.knowledge_graph.search_entities(entity_id, limit=5)
                    for ent in search_results:
                        if ent.id in self._entity2idx:
                            resolved_id = ent.id
                            self._name2id[entity_id.lower()] = resolved_id
                            break
                        if ent.value.lower() == entity_id.lower() and ent.id in self._entity2idx:
                            resolved_id = ent.id
                            self._name2id[entity_id.lower()] = resolved_id
                            break
                except Exception:
                    pass

        if self._model is None or resolved_id not in self._entity2idx:
            return []

        entity_idx = self._entity2idx[resolved_id]
        entity_emb = self._model.get_entity_embedding(entity_idx)

        source_entity = await self.knowledge_graph.get_entity(resolved_id)
        source_type = source_entity.type.value if source_entity and hasattr(source_entity.type, 'value') else "unknown"
        source_platform = self._infer_platform(source_type)

        similarities = []
        for other_id, other_idx in self._entity2idx.items():
            if other_id == resolved_id:
                continue
            other_emb = self._model.get_entity_embedding(other_idx)
            norm_e = np.linalg.norm(entity_emb)
            norm_o = np.linalg.norm(other_emb)
            if norm_e < 1e-8 or norm_o < 1e-8:
                continue
            sim = float(np.dot(entity_emb, other_emb) / (norm_e * norm_o))
            if sim >= threshold:
                similarities.append((other_id, sim))

        similarities.sort(key=lambda x: x[1], reverse=True)

        results = []
        for target_id, sim in similarities[:10]:
            target_entity = await self.knowledge_graph.get_entity(target_id)
            target_type = target_entity.type.value if target_entity and hasattr(target_entity.type, 'value') else "unknown"
            target_platform = self._infer_platform(target_type)

            evidence = self._generate_evidence(resolved_id, target_id, sim, source_type, target_type)

            results.append(AttributionResult(
                source_entity_id=resolved_id,
                target_entity_id=target_id,
                similarity=round(sim, 4),
                source_platform=source_platform,
                target_platform=target_platform,
                evidence=evidence,
                confidence=round(sim * 0.9, 4),
            ))

        logger.info(f"TransE attribution: {len(results)} matches for entity {resolved_id[:8]}")
        return results

    def _infer_platform(self, entity_type: str) -> str:
        platform_map = {
            "ip_address": "network", "domain": "network", "url": "web",
            "email": "email", "phone": "telecom", "malware": "darkweb",
            "hash": "darkweb", "tool": "darkweb", "person": "social",
            "organization": "business", "financial_account": "financial",
        }
        return platform_map.get(entity_type, "unknown")

    def _generate_evidence(self, src_id: str, tgt_id: str, sim: float, src_type: str, tgt_type: str) -> List[str]:
        evidence = [f"TransE嵌入余弦相似度: {sim:.4f}"]
        if src_type == tgt_type:
            evidence.append(f"实体类型一致: {src_type}")
        common_relations = self._find_common_relations(src_id, tgt_id)
        if common_relations:
            evidence.append(f"共享关系类型: {', '.join(common_relations[:3])}")
        return evidence

    def _find_common_relations(self, src_id: str, tgt_id: str) -> List[str]:
        src_relations = set()
        tgt_relations = set()
        if src_id in self.knowledge_graph.graph:
            for _, _, data in self.knowledge_graph.graph.out_edges(src_id, data=True):
                src_relations.add(data.get("relation_type", ""))
            for _, _, data in self.knowledge_graph.graph.in_edges(src_id, data=True):
                src_relations.add(data.get("relation_type", ""))
        if tgt_id in self.knowledge_graph.graph:
            for _, _, data in self.knowledge_graph.graph.out_edges(tgt_id, data=True):
                tgt_relations.add(data.get("relation_type", ""))
            for _, _, data in self.knowledge_graph.graph.in_edges(tgt_id, data=True):
                tgt_relations.add(data.get("relation_type", ""))
        return list(src_relations & tgt_relations - {""})

    async def find_similar_entities(self, entity_id: str, top_k: int = 5) -> List[AttributionResult]:
        results = await self.attribute_entity(entity_id, threshold=0.3)
        return results[:top_k]

    async def build_entity_profile(self, entity_id: str) -> EntityProfile:
        entity = await self.knowledge_graph.get_entity(entity_id)
        if not entity:
            return EntityProfile(entity_id=entity_id, entity_type="unknown", value="unknown")

        entity_type = entity.type.value if hasattr(entity.type, 'value') else str(entity.type)
        features = self._compute_behavioral_features(entity_id)
        embedding = None
        if self._model and entity_id in self._entity2idx:
            emb = self._model.get_entity_embedding(self._entity2idx[entity_id])
            embedding = emb.tolist()

        return EntityProfile(
            entity_id=entity_id,
            entity_type=entity_type,
            value=entity.value,
            platforms=[self._infer_platform(entity_type)],
            behavioral_features=features,
            embedding=embedding,
        )

    def _compute_behavioral_features(self, entity_id: str) -> Dict[str, float]:
        features = {}
        if entity_id not in self.knowledge_graph.graph:
            return features
        out_deg = self.knowledge_graph.graph.out_degree(entity_id)
        in_deg = self.knowledge_graph.graph.in_degree(entity_id)
        features["out_degree"] = float(out_deg)
        features["in_degree"] = float(in_deg)
        features["centrality"] = float(out_deg + in_deg) / max(self.knowledge_graph.graph.number_of_nodes(), 1)

        relation_types = Counter()
        for _, _, data in self.knowledge_graph.graph.out_edges(entity_id, data=True):
            relation_types[data.get("relation_type", "unknown")] += 1
        for _, _, data in self.knowledge_graph.graph.in_edges(entity_id, data=True):
            relation_types[data.get("relation_type", "unknown")] += 1
        features["relation_diversity"] = float(len(relation_types))
        if relation_types:
            features["dominant_relation_ratio"] = float(relation_types.most_common(1)[0][1]) / max(sum(relation_types.values()), 1)
        return features

    async def compute_behavioral_fingerprint(self, entity_id: str) -> BehavioralFingerprint:
        if self._model is None:
            self._try_load_model()

        resolved_id = entity_id
        if self._model is not None and resolved_id not in self._entity2idx:
            if entity_id.lower() in self._name2id:
                resolved_id = self._name2id[entity_id.lower()]

        entity = await self.knowledge_graph.get_entity(resolved_id)
        entity_type = "unknown"
        entity_value = entity_id
        platforms = []
        if entity:
            entity_type = entity.type.value if hasattr(entity.type, 'value') else str(entity.type)
            entity_value = entity.value
            platforms = [self._infer_platform(entity_type)]

        features = self._compute_behavioral_features(resolved_id)

        embedding = None
        if self._model is not None and resolved_id in self._entity2idx:
            emb = self._model.get_entity_embedding(self._entity2idx[resolved_id])
            embedding = emb.tolist()

        fingerprint_str = json.dumps(features, sort_keys=True)
        fingerprint_hash = hashlib.sha256(fingerprint_str.encode()).hexdigest()[:16]

        return BehavioralFingerprint(
            entity_id=resolved_id,
            entity_type=entity_type,
            entity_value=entity_value,
            embedding=embedding,
            behavioral_features=features,
            fingerprint_hash=fingerprint_hash,
            platforms=platforms,
            created_at=datetime.now(timezone.utc).isoformat(),
        )

    async def find_same_entity(self, entity_id: str, threshold: float = 0.8) -> List[AttributionResult]:
        return await self.attribute_entity(entity_id, threshold=threshold)

    async def generate_attribution_report(self, entity_id: str) -> Dict:
        profile = await self.build_entity_profile(entity_id)
        attributions = await self.attribute_entity(entity_id)
        return {
            "profile": profile.to_dict(),
            "attributions": [a.to_dict() for a in attributions],
            "total_matches": len(attributions),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }


class EntityAttributionEngine:
    def __init__(self, vector_store: VectorStore, knowledge_graph: KnowledgeGraph, llm=None):
        self.vector_store = vector_store
        self.knowledge_graph = knowledge_graph
        self._llm = llm
        self._core = EntityAttribution(vector_store, knowledge_graph)

    def set_llm(self, llm):
        self._llm = llm

    async def attribute_entities(self, entities: list[dict], context: str = "") -> list[dict]:
        results = []

        for entity in entities:
            entity_value = entity.get("value", "")
            entity_type = entity.get("type", entity.get("entity_type", ""))

            graph_results = await self._find_in_graph(entity_value, entity_type)
            if graph_results:
                results.extend(graph_results)
                continue

            if self._llm:
                try:
                    llm_results = await self._llm_attribute(entity, context)
                    results.extend(llm_results)
                except Exception as e:
                    logger.warning(f"LLM attribution failed for {entity_value}: {e}")

        return results

    async def _find_in_graph(self, entity_value: str, entity_type: str) -> list[dict]:
        results = []
        try:
            for eid, entity in self.knowledge_graph._entities.items():
                if entity.value.lower() == entity_value.lower():
                    attribution_results = await self._core.attribute_entity(eid, threshold=0.4)
                    for ar in attribution_results[:5]:
                        target_entity = await self.knowledge_graph.get_entity(ar.target_entity_id)
                        results.append({
                            "entity_value": entity_value,
                            "entity_type": entity_type,
                            "attributed_to": target_entity.value if target_entity else ar.target_entity_id,
                            "attribution_type": "actor" if ar.target_platform in ("darkweb", "social") else "campaign",
                            "confidence": ar.confidence,
                            "evidence": ar.evidence,
                            "source": "knowledge_graph",
                        })
                    break
        except Exception as e:
            logger.debug(f"Graph search failed for {entity_value}: {e}")

        if not results:
            try:
                embedding = await self.vector_store.get_embedding(entity_value)
                search_results = await self.vector_store.search(
                    collection="entities",
                    query_embedding=embedding,
                    top_k=5,
                )
                for sr in search_results:
                    metadata = sr.get("metadata", {})
                    sim = sr.get("distance", 1.0)
                    if sim < 0.4:
                        results.append({
                            "entity_value": entity_value,
                            "entity_type": entity_type,
                            "attributed_to": metadata.get("value", sr.get("id", "")),
                            "attribution_type": "related_entity",
                            "confidence": round(1.0 - sim, 4),
                            "evidence": [f"向量相似度: {1.0 - sim:.4f}"],
                            "source": "vector_search",
                        })
            except Exception as e:
                logger.debug(f"Vector search failed for {entity_value}: {e}")

        return results

    async def _llm_attribute(self, entity: dict, context: str) -> list[dict]:
        entity_value = entity.get("value", "")
        entity_type = entity.get("type", entity.get("entity_type", ""))

        prompt = (
            f"请分析以下威胁情报实体，判断其可能归属的威胁行为者或攻击组织。\n\n"
            f"实体值: {entity_value}\n"
            f"实体类型: {entity_type}\n"
            f"上下文: {context[:500] if context else '无'}\n\n"
            f"请从以下维度分析:\n"
            f"1. 该实体可能关联的已知威胁组织(APT组织、黑产团伙等)\n"
            f"2. 该实体可能参与的攻击活动或战役\n"
            f"3. 归属的置信度评估\n\n"
            f"请以JSON数组格式返回:\n"
            f'[{{"attributed_to": "组织/活动名称", "attribution_type": "actor/campaign/infrastructure", '
            f'"confidence": 0.0-1.0, "reasoning": "判断依据", "indicators": ["指标1"]}}]\n'
            f"如果无法判断归属，返回空数组: []"
        )

        result = await self._llm.generate(
            prompt=prompt,
            system_prompt="你是威胁情报归属分析专家，负责将实体归属到已知的威胁行为者或攻击活动。只返回JSON，不要其他内容。",
            temperature=settings.LLM_TEMPERATURE_CREATIVE,
            max_tokens=settings.LLM_MAX_TOKENS_MEDIUM,
        )

        attributions = []
        try:
            import re
            json_str = result.strip()
            if json_str.startswith("```"):
                json_str = re.sub(r'^```\w*\n?', '', json_str)
                json_str = re.sub(r'\n?```$', '', json_str)
            parsed = json.loads(json_str)
            if isinstance(parsed, list):
                for item in parsed[:5]:
                    if not isinstance(item, dict):
                        continue
                    confidence = min(1.0, max(0.0, float(item.get("confidence", 0.5))))
                    attributions.append({
                        "entity_value": entity_value,
                        "entity_type": entity_type,
                        "attributed_to": item.get("attributed_to", "unknown"),
                        "attribution_type": item.get("attribution_type", "unknown"),
                        "confidence": confidence,
                        "evidence": [item.get("reasoning", "")] + item.get("indicators", []),
                        "source": "llm",
                    })
        except (json.JSONDecodeError, TypeError) as e:
            logger.debug(f"LLM attribution response parse failed: {e}")

        return attributions

    async def find_related_entities(self, entity_value: str, entity_type: str) -> list[dict]:
        results = []

        try:
            for eid, entity in self.knowledge_graph._entities.items():
                if entity.value.lower() == entity_value.lower():
                    neighbors = list(self.knowledge_graph.graph.neighbors(eid))
                    for nid in neighbors[:10]:
                        neighbor = await self.knowledge_graph.get_entity(nid)
                        if neighbor:
                            edge_data = self.knowledge_graph.graph.get_edge_data(eid, nid)
                            rel_type = ""
                            if edge_data:
                                if isinstance(edge_data, dict):
                                    rel_type = edge_data.get("type", edge_data.get("relation_type", ""))
                                else:
                                    for key in edge_data:
                                        rel_type = edge_data[key].get("type", edge_data[key].get("relation_type", ""))
                                        break
                            results.append({
                                "entity_id": nid,
                                "entity_value": neighbor.value,
                                "entity_type": neighbor.type.value if hasattr(neighbor.type, 'value') else str(neighbor.type),
                                "relation_type": rel_type,
                                "confidence": neighbor.confidence,
                                "source": "knowledge_graph",
                            })
                    break
        except Exception as e:
            logger.debug(f"Graph neighbor search failed: {e}")

        try:
            embedding = await self.vector_store.get_embedding(entity_value)
            search_results = await self.vector_store.search(
                collection="entities",
                query_embedding=embedding,
                top_k=10,
            )
            for sr in search_results:
                metadata = sr.get("metadata", {})
                sim = sr.get("distance", 1.0)
                existing_values = {r["entity_value"] for r in results}
                val = metadata.get("value", "")
                if val and val.lower() != entity_value.lower() and val not in existing_values:
                    results.append({
                        "entity_id": sr.get("id", ""),
                        "entity_value": val,
                        "entity_type": metadata.get("type", "unknown"),
                        "relation_type": "similar",
                        "confidence": round(1.0 - sim, 4),
                        "source": "vector_search",
                    })
        except Exception as e:
            logger.debug(f"Vector search failed for related entities: {e}")

        if not results and self._llm:
            try:
                llm_results = await self._llm_find_related(entity_value, entity_type)
                results.extend(llm_results)
            except Exception as e:
                logger.debug(f"LLM related entity search failed: {e}")

        return results

    async def _llm_find_related(self, entity_value: str, entity_type: str) -> list[dict]:
        prompt = (
            f"请根据以下威胁情报实体，推测可能相关的其他实体。\n\n"
            f"实体值: {entity_value}\n"
            f"实体类型: {entity_type}\n\n"
            f"请推测可能相关的实体，包括:\n"
            f"1. 同一威胁组织使用的其他基础设施(IP/域名/URL)\n"
            f"2. 关联的账号(邮箱/IM/社交媒体)\n"
            f"3. 使用的工具或恶意软件\n"
            f"4. 关联的组织或人员\n\n"
            f"请以JSON数组格式返回:\n"
            f'[{{"entity_value": "实体值", "entity_type": "类型", "relation_type": "关系类型", '
            f'"confidence": 0.0-1.0, "reasoning": "推测依据"}}]\\n"\n'
            f"如果无法推测，返回空数组: []"
        )

        result = await self._llm.generate(
            prompt=prompt,
            system_prompt="你是威胁情报关联分析专家。只返回JSON，不要其他内容。",
            temperature=settings.LLM_TEMPERATURE_NARRATIVE,
            max_tokens=settings.LLM_MAX_TOKENS_MEDIUM,
        )

        related = []
        try:
            import re
            json_str = result.strip()
            if json_str.startswith("```"):
                json_str = re.sub(r'^```\w*\n?', '', json_str)
                json_str = re.sub(r'\n?```$', '', json_str)
            parsed = json.loads(json_str)
            if isinstance(parsed, list):
                for item in parsed[:8]:
                    if not isinstance(item, dict):
                        continue
                    confidence = min(1.0, max(0.0, float(item.get("confidence", 0.3))))
                    related.append({
                        "entity_id": "",
                        "entity_value": item.get("entity_value", ""),
                        "entity_type": item.get("entity_type", "unknown"),
                        "relation_type": item.get("relation_type", "inferred"),
                        "confidence": confidence,
                        "source": "llm",
                    })
        except (json.JSONDecodeError, TypeError) as e:
            logger.debug(f"LLM related entity response parse failed: {e}")

        return related

    def score_attribution(self, entity: dict, actor: dict) -> float:
        score = 0.0
        max_score = 0.0

        entity_type = entity.get("type", entity.get("entity_type", ""))
        actor_type = actor.get("type", actor.get("entity_type", ""))

        type_affinity = {
            ("ip_address", "infrastructure"): 0.3,
            ("domain", "infrastructure"): 0.3,
            ("url", "infrastructure"): 0.25,
            ("email", "actor"): 0.35,
            ("malware", "campaign"): 0.3,
            ("tool", "campaign"): 0.25,
            ("person", "actor"): 0.4,
            ("organization", "actor"): 0.45,
        }
        max_score += 0.4
        affinity = type_affinity.get((entity_type, actor_type), 0.05)
        score += affinity

        entity_confidence = entity.get("confidence", 0.5)
        actor_confidence = actor.get("confidence", 0.5)
        max_score += 0.2
        score += min(entity_confidence, actor_confidence) * 0.2

        entity_context = entity.get("context", "") or ""
        actor_context = actor.get("context", "") or ""
        max_score += 0.2
        if entity_context and actor_context:
            entity_words = set(entity_context.lower().split())
            actor_words = set(actor_context.lower().split())
            overlap = entity_words & actor_words
            if overlap:
                jaccard = len(overlap) / max(len(entity_words | actor_words), 1)
                score += jaccard * 0.2

        entity_value = entity.get("value", "")
        actor_value = actor.get("value", "")
        max_score += 0.2
        if entity_value and actor_value:
            try:
                entity_emb = self.vector_store._embedding.embed(entity_value)
                actor_emb = self.vector_store._embedding.embed(actor_value)
                e_norm = np.linalg.norm(entity_emb)
                a_norm = np.linalg.norm(actor_emb)
                if e_norm > 1e-8 and a_norm > 1e-8:
                    cosine_sim = float(np.dot(entity_emb, actor_emb) / (e_norm * a_norm))
                    score += max(0, cosine_sim) * 0.2
            except Exception:
                score += 0.05

        if max_score > 0:
            return round(min(1.0, score / max_score), 4)
        return 0.0

    async def attribute_entity(self, entity_id: str, threshold: float = 0.6) -> List[AttributionResult]:
        return await self._core.attribute_entity(entity_id, threshold)

    def train_from_graph(self):
        self._core.train_from_graph()

    async def build_entity_profile(self, entity_id: str) -> EntityProfile:
        return await self._core.build_entity_profile(entity_id)

    async def compute_behavioral_fingerprint(self, entity_id: str) -> BehavioralFingerprint:
        return await self._core.compute_behavioral_fingerprint(entity_id)

    async def generate_attribution_report(self, entity_id: str) -> Dict:
        return await self._core.generate_attribution_report(entity_id)
