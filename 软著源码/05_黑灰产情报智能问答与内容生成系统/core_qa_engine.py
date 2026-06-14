import asyncio
import json
import math
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from loguru import logger


@dataclass
class RAGResult:
    query: str
    documents: List[Dict[str, Any]]
    context: str
    total_tokens: int = 0
    retrieval_time_ms: float = 0
    relevance_scores: List[float] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "query": self.query,
            "document_count": len(self.documents),
            "context_length": len(self.context),
            "total_tokens": self.total_tokens,
            "retrieval_time_ms": round(self.retrieval_time_ms, 2),
            "relevance_scores": [round(s, 4) for s in self.relevance_scores],
            "documents": [
                {
                    "id": d.get("id", ""),
                    "snippet": d.get("content", "")[:200],
                    "source": d.get("source", ""),
                    "relevance": round(d.get("relevance", 0), 4),
                }
                for d in self.documents
            ],
        }


@dataclass
class Citation:
    source_id: str
    source_type: str
    snippet: str
    relevance_score: float
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "source_id": self.source_id,
            "source_type": self.source_type,
            "snippet": self.snippet[:300],
            "relevance_score": round(self.relevance_score, 4),
            "metadata": self.metadata,
        }


class SemanticRetriever:
    def __init__(self, vector_store=None, llm_service=None, embedding_engine=None):
        self._vector_store = vector_store
        self._llm = llm_service
        self._embedding_engine = embedding_engine

    async def semantic_search(
        self, query: str, top_k: int = 5, collection: Optional[str] = None
    ) -> Tuple[List[Dict], List[float]]:
        documents = []
        scores = []

        if not self._vector_store:
            return documents, scores

        try:
            query_embedding = None
            if self._llm and hasattr(self._llm, "embed"):
                try:
                    query_embedding = await self._llm.embed(query)
                except Exception as exc:
                    logger.warning(f"查询嵌入生成失败: {exc}")

            search_kwargs = {"query": query, "top_k": top_k}
            if collection:
                search_kwargs["collection"] = collection
            if query_embedding is not None:
                search_kwargs["embedding"] = query_embedding

            results = await self._vector_store.search(**search_kwargs)

            if isinstance(results, list):
                for r in results:
                    doc = r if isinstance(r, dict) else {"content": str(r), "relevance": 0.5}
                    documents.append(doc)
                    score = doc.get("relevance", doc.get("score", 0.5))
                    if query_embedding is not None and self._llm and hasattr(self._llm, "embed"):
                        try:
                            content = doc.get("content", "")
                            if content:
                                doc_embedding = await self._llm.embed(content[:500])
                                if doc_embedding is not None:
                                    semantic_sim = self._cosine_similarity(query_embedding, doc_embedding)
                                    score = score * 0.4 + semantic_sim * 0.6
                        except Exception:
                            pass
                    scores.append(score)
        except (ConnectionError, TimeoutError, OSError) as exc:
            logger.warning(f"语义检索网络/IO错误 ({type(exc).__name__}): {exc}")
        except Exception as exc:
            logger.warning(f"语义检索失败 ({type(exc).__name__}): {exc}")

        return documents, scores

    async def keyword_search(
        self, query: str, top_k: int = 5
    ) -> Tuple[List[Dict], List[float]]:
        documents = []
        scores = []

        try:
            from app.db.database import async_session_factory
            from app.db.tables import CleanedIntelligenceTable
            from sqlalchemy import select

            async with async_session_factory() as session:
                keywords = query.split()[:5]
                seen_ids = set()
                for kw in keywords:
                    escaped_kw = kw.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
                    stmt = (
                        select(CleanedIntelligenceTable)
                        .where(CleanedIntelligenceTable.content.ilike(f"%{escaped_kw}%", escape='\\'))
                        .limit(top_k)
                    )
                    result = await session.execute(stmt)
                    for row in result.scalars().all():
                        if row.id in seen_ids:
                            continue
                        seen_ids.add(row.id)
                        content = row.content or ""
                        tfidf_score = self._compute_tfidf_similarity(query, content)
                        documents.append({
                            "id": row.id,
                            "content": content,
                            "source": "cleaned_intelligence",
                            "threat_level": row.threat_level,
                            "relevance": tfidf_score,
                        })
                        scores.append(tfidf_score)

                if not documents:
                    stmt = select(CleanedIntelligenceTable).limit(top_k * 2)
                    result = await session.execute(stmt)
                    for row in result.scalars().all():
                        content = row.content or ""
                        tfidf_score = self._compute_tfidf_similarity(query, content)
                        documents.append({
                            "id": row.id,
                            "content": content,
                            "source": "cleaned_intelligence",
                            "threat_level": row.threat_level,
                            "relevance": tfidf_score,
                        })
                        scores.append(tfidf_score)

        except Exception as exc:
            logger.warning(f"关键词检索失败: {exc}")

        combined = list(zip(documents, scores))
        combined.sort(key=lambda x: x[1], reverse=True)
        documents = [d for d, s in combined[:top_k]]
        scores = [s for d, s in combined[:top_k]]

        return documents, scores

    async def hybrid_search(
        self, query: str, top_k: int = 5, collection: Optional[str] = None
    ) -> Tuple[List[Dict], List[float]]:
        semantic_docs, semantic_scores = await self.semantic_search(
            query, top_k=top_k, collection=collection
        )
        keyword_docs, keyword_scores = await self.keyword_search(
            query, top_k=top_k
        )

        if not semantic_docs and not keyword_docs:
            return [], []

        if not semantic_docs:
            return keyword_docs, keyword_scores

        if not keyword_docs:
            return semantic_docs, semantic_scores

        rrf_k = 60

        doc_rank_map: Dict[str, Dict[str, float]] = {}

        for rank, doc in enumerate(semantic_docs):
            doc_id = doc.get("id", f"sem_{rank}")
            if doc_id not in doc_rank_map:
                doc_rank_map[doc_id] = {"doc": doc, "scores": {}}
            doc_rank_map[doc_id]["scores"]["semantic"] = 1.0 / (rrf_k + rank + 1)

        for rank, doc in enumerate(keyword_docs):
            doc_id = doc.get("id", f"kw_{rank}")
            if doc_id not in doc_rank_map:
                doc_rank_map[doc_id] = {"doc": doc, "scores": {}}
            doc_rank_map[doc_id]["scores"]["keyword"] = 1.0 / (rrf_k + rank + 1)

        weight_semantic = 0.6
        weight_keyword = 0.4

        fused_results = []
        for doc_id, info in doc_rank_map.items():
            rrf_score = (
                weight_semantic * info["scores"].get("semantic", 0.0)
                + weight_keyword * info["scores"].get("keyword", 0.0)
            )
            doc = dict(info["doc"])
            doc["hybrid_score"] = round(rrf_score, 6)
            fused_results.append((doc, rrf_score))

        fused_results.sort(key=lambda x: x[1], reverse=True)
        documents = [d for d, s in fused_results[:top_k]]
        scores = [s for d, s in fused_results[:top_k]]

        return documents, scores

    def _compute_tfidf_similarity(self, query: str, text: str) -> float:
        stop_words = {"的", "了", "是", "在", "我", "有", "和", "就", "不", "人", "都", "一", "一个", "上", "也", "很", "到", "说", "要", "去", "你", "会", "着", "没有", "看", "好", "自己", "这", "他", "她", "它", "们", "那", "些", "什么", "怎么", "如何", "可以", "吗", "呢", "吧", "啊", "the", "a", "an", "is", "are", "was", "were", "be", "been", "being", "have", "has", "had", "do", "does", "did", "will", "would", "could", "should", "may", "might", "shall", "can", "need", "to", "of", "in", "for", "on", "with", "at", "by", "from", "as", "into", "through", "during", "before", "after", "above", "below", "between", "out", "off", "over", "under", "again", "further", "then", "once", "and", "but", "or", "nor", "not", "so", "if", "than", "too", "very", "just", "about"}

        def tokenize(s):
            return [w for w in s.lower().split() if len(w) > 1 and w not in stop_words]

        query_tokens = tokenize(query)
        text_tokens = tokenize(text)

        if not query_tokens or not text_tokens:
            return 0.0

        query_counter = Counter(query_tokens)
        text_counter = Counter(text_tokens)

        all_terms = set(query_counter.keys()) | set(text_counter.keys())
        query_len = len(query_tokens)
        text_len = len(text_tokens)

        dot_product = 0.0
        query_norm = 0.0
        text_norm = 0.0

        for term in all_terms:
            q_tf = query_counter.get(term, 0) / query_len
            t_tf = text_counter.get(term, 0) / text_len
            idf = math.log(2.0 / (1 + (1 if term in text_counter else 0))) + 1.0
            q_tfidf = q_tf * idf
            t_tfidf = t_tf * idf
            dot_product += q_tfidf * t_tfidf
            query_norm += q_tfidf * q_tfidf
            text_norm += t_tfidf * t_tfidf

        if query_norm == 0 or text_norm == 0:
            return 0.0

        return dot_product / (math.sqrt(query_norm) * math.sqrt(text_norm))

    @staticmethod
    def _cosine_similarity(vec_a, vec_b) -> float:
        try:
            if hasattr(vec_a, "tolist"):
                vec_a = vec_a.tolist()
            if hasattr(vec_b, "tolist"):
                vec_b = vec_b.tolist()

            dot = sum(a * b for a, b in zip(vec_a, vec_b))
            norm_a = sum(a * a for a in vec_a) ** 0.5
            norm_b = sum(b * b for b in vec_b) ** 0.5

            if norm_a == 0 or norm_b == 0:
                return 0.0

            return dot / (norm_a * norm_b)
        except Exception as exc:
            logger.warning(f"余弦相似度计算失败: {exc}")
            return 0.0


class LLMIntentAnalyzer:
    def __init__(self, llm_service=None):
        self._llm = llm_service
        self._intent_categories = [
            "查询", "分析", "威胁", "溯源", "趋势", "防御", "情报", "关联"
        ]

    async def analyze_intent(self, content: str) -> Dict[str, Any]:
        if not self._llm:
            return self._keyword_intent_fallback(content)

        try:
            categories = ", ".join(self._intent_categories)
            prompt = (
                f"分析以下用户问题的意图。可能的意图类别: {categories}\n"
                f"用户问题: {content}\n\n"
                f"请以JSON格式返回，包含以下字段:\n"
                f"- primary_intent: 主要意图(从上述类别中选择)\n"
                f"- secondary_intents: 次要意图列表\n"
                f"- confidence: 主要意图的置信度(0-1)\n"
                f"- reasoning: 简短的推理说明\n"
                f"只返回JSON，不要其他内容。"
            )
            response = await self._llm.chat(prompt)
            if isinstance(response, dict):
                text = response.get("content", "")
            elif isinstance(response, str):
                text = response
            else:
                text = str(response)

            try:
                json_str = text.strip()
                if json_str.startswith("```"):
                    lines = json_str.split("\n")
                    json_str = "\n".join(lines[1:-1])
                result = json.loads(json_str)
            except (json.JSONDecodeError, TypeError):
                result = {
                    "primary_intent": self._guess_intent_from_text(content),
                    "secondary_intents": [],
                    "confidence": 0.5,
                    "reasoning": "LLM输出解析失败，使用回退推断",
                }

            result["primary_intent"] = result.get("primary_intent", self._guess_intent_from_text(content))
            result["secondary_intents"] = result.get("secondary_intents", [])
            result["confidence"] = min(1.0, max(0.0, float(result.get("confidence", 0.5))))
            result["reasoning"] = result.get("reasoning", "")

            return result

        except Exception as exc:
            logger.warning(f"LLM意图分析失败 ({type(exc).__name__}): {exc}")
            return self._keyword_intent_fallback(content)

    async def track_intent_chain(self, messages: List[Dict]) -> Dict[str, Any]:
        intents = []
        intent_chain = []

        for msg in messages:
            if msg.get("role") != "user":
                continue
            content = msg.get("content", "")
            if not content:
                continue

            intent_result = await self.analyze_intent(content)
            primary = intent_result["primary_intent"]
            secondary = intent_result.get("secondary_intents", [])
            confidence = intent_result.get("confidence", 0.5)

            intents.append({
                "intent": primary,
                "all_intents": [primary] + secondary,
                "confidence": confidence,
                "query": content[:100],
                "reasoning": intent_result.get("reasoning", ""),
            })

            if not intent_chain or intent_chain[-1] != primary:
                intent_chain.append(primary)

        dominant_intent = None
        if intents:
            intent_counts = Counter(i["intent"] for i in intents)
            dominant_intent = intent_counts.most_common(1)[0][0]

        return {
            "intents": intents,
            "intent_chain": intent_chain,
            "dominant_intent": dominant_intent,
            "intent_transitions": len(intent_chain) - 1 if len(intent_chain) > 1 else 0,
        }

    def _keyword_intent_fallback(self, content: str) -> Dict[str, Any]:
        intent_keywords = {
            "查询": ["查询", "搜索", "查找", "找", "检索", "查", "了解", "看看", "search", "query", "find", "look"],
            "分析": ["分析", "评估", "判断", "解读", "解析", "调查", "analyze", "assess", "evaluate", "investigate"],
            "威胁": ["威胁", "攻击", "漏洞", "恶意", "入侵", "木马", "病毒", "钓鱼", "勒索", "threat", "attack", "vulnerability", "malware", "ransomware"],
            "溯源": ["溯源", "来源", "归因", "追踪", "定位", "谁", "哪个组织", "trace", "attribute", "origin", "source"],
            "趋势": ["趋势", "变化", "发展", "预测", "未来", "动向", "trend", "forecast", "predict", "evolution"],
            "防御": ["防御", "防护", "应对", "处置", "修复", "加固", "建议", "方案", "defend", "protect", "mitigate", "remediate"],
            "情报": ["情报", "信息", "报告", "IOC", "指标", "intel", "intelligence", "indicator", "report"],
            "关联": ["关联", "关系", "联系", "连接", "网络", "关联分析", "correlate", "link", "relationship", "connect"],
        }

        content_lower = content.lower()
        detected = []
        match_counts = {}

        for intent, keywords in intent_keywords.items():
            count = sum(1 for kw in keywords if kw.lower() in content_lower)
            if count > 0:
                detected.append((intent, count))
                match_counts[intent] = count

        if not detected:
            return {
                "primary_intent": "查询",
                "secondary_intents": [],
                "confidence": 0.3,
                "reasoning": "未匹配到明确意图关键词",
            }

        detected.sort(key=lambda x: x[1], reverse=True)
        primary = detected[0][0]
        secondary = [d[0] for d in detected[1:3]]
        max_count = detected[0][1]
        confidence = min(0.9, 0.4 + max_count * 0.15)

        return {
            "primary_intent": primary,
            "secondary_intents": secondary,
            "confidence": confidence,
            "reasoning": f"关键词匹配: {', '.join(f'{k}({v})' for k, v in match_counts.items())}",
        }

    def _guess_intent_from_text(self, text: str) -> str:
        result = self._keyword_intent_fallback(text)
        return result["primary_intent"]


class CrossEncoderReranker:
    def __init__(self, llm_service=None):
        self._llm = llm_service

    async def rerank(
        self, query: str, documents: List[Dict], top_k: int = 5, lambda_diversity: float = 0.3
    ) -> List[Dict]:
        if not documents:
            return []

        scored_docs = await self._score_documents(query, documents)

        if self._llm and hasattr(self._llm, "embed"):
            try:
                query_embedding = await self._llm.embed(query)
                if query_embedding is not None:
                    scored_docs = await self._cross_encoder_score(query_embedding, scored_docs)
            except Exception as exc:
                logger.warning(f"交叉编码器评分失败 ({type(exc).__name__}): {exc}")

        scored_docs.sort(
            key=lambda x: x.get("_cross_score", x.get("_relevance_score", 0)), reverse=True
        )

        result = self._diversity_filter(scored_docs, top_k, lambda_diversity)

        return result

    async def _score_documents(self, query: str, documents: List[Dict]) -> List[Dict]:
        scored = []
        query_words = set(query.lower().split())

        for doc in documents:
            doc_copy = dict(doc)
            content = doc.get("content", "")
            original_score = doc.get("relevance", doc.get("score", 0.5))

            content_words = set(content.lower().split())
            if query_words:
                overlap = len(query_words & content_words) / len(query_words)
            else:
                overlap = 0.0

            content_len = len(content)
            if content_len < 50:
                length_score = 0.3
            elif content_len < 200:
                length_score = 0.7
            elif content_len < 1000:
                length_score = 1.0
            elif content_len < 3000:
                length_score = 0.8
            else:
                length_score = 0.5

            combined_score = original_score * 0.5 + overlap * 0.35 + length_score * 0.15
            doc_copy["_relevance_score"] = round(combined_score, 6)
            scored.append(doc_copy)

        return scored

    async def _cross_encoder_score(self, query_embedding: Any, documents: List[Dict]) -> List[Dict]:
        for doc in documents:
            content = doc.get("content", "")
            if not content:
                doc["_cross_score"] = doc.get("_relevance_score", 0.5)
                continue

            try:
                doc_embedding = await self._llm.embed(content[:500])
                if doc_embedding is not None:
                    similarity = self._cosine_similarity(query_embedding, doc_embedding)
                    relevance_score = doc.get("_relevance_score", 0.5)
                    doc["_cross_score"] = round(relevance_score * 0.35 + similarity * 0.65, 6)
                else:
                    doc["_cross_score"] = doc.get("_relevance_score", 0.5)
            except Exception:
                doc["_cross_score"] = doc.get("_relevance_score", 0.5)

        return documents

    def _diversity_filter(
        self, documents: List[Dict], top_k: int, lambda_diversity: float
    ) -> List[Dict]:
        if not documents:
            return []

        selected = [documents[0]]
        remaining = documents[1:]

        while remaining and len(selected) < top_k:
            best_score = -float("inf")
            best_idx = -1

            for idx, doc in enumerate(remaining):
                relevance = doc.get("_cross_score", doc.get("_relevance_score", 0.5))

                max_sim = 0.0
                doc_words = set(doc.get("content", "").lower().split())
                for sel_doc in selected:
                    sel_words = set(sel_doc.get("content", "").lower().split())
                    union = len(doc_words | sel_words)
                    if union > 0:
                        sim = len(doc_words & sel_words) / union
                        max_sim = max(max_sim, sim)

                diversity_score = relevance - lambda_diversity * max_sim
                if diversity_score > best_score:
                    best_score = diversity_score
                    best_idx = idx

            if best_idx >= 0:
                selected.append(remaining.pop(best_idx))
            else:
                break

        result = []
        for doc in selected:
            doc_copy = dict(doc)
            final_score = doc_copy.pop("_cross_score", doc_copy.pop("_relevance_score", 0.5))
            doc_copy["rerank_score"] = round(final_score, 4)
            doc_copy.pop("_relevance_score", None)
            result.append(doc_copy)

        return result

    @staticmethod
    def _cosine_similarity(vec_a, vec_b) -> float:
        try:
            if hasattr(vec_a, "tolist"):
                vec_a = vec_a.tolist()
            if hasattr(vec_b, "tolist"):
                vec_b = vec_b.tolist()

            dot = sum(a * b for a, b in zip(vec_a, vec_b))
            norm_a = sum(a * a for a in vec_a) ** 0.5
            norm_b = sum(b * b for b in vec_b) ** 0.5

            if norm_a == 0 or norm_b == 0:
                return 0.0

            return dot / (norm_a * norm_b)
        except Exception as exc:
            logger.warning(f"余弦相似度计算失败: {exc}")
            return 0.0


class LLMCitationValidator:
    def __init__(self, llm_service=None):
        self._llm = llm_service

    async def validate_citation(
        self, response_text: str, citation: Citation
    ) -> Dict[str, Any]:
        if not self._llm:
            return {
                "is_valid": True,
                "credibility": citation.relevance_score,
                "support_type": "关键词匹配",
                "reasoning": "",
            }

        try:
            prompt = (
                f"判断以下引用是否真正支持回答中的结论。\n\n"
                f"回答摘要: {response_text[:800]}\n\n"
                f"引用内容: {citation.snippet[:500]}\n\n"
                f"请以JSON格式返回:\n"
                f"- is_valid: 是否有效支持(true/false)\n"
                f"- credibility: 可信度评分(0-1)\n"
                f"- support_type: 支持类型(直接证据/间接支撑/背景信息/无关)\n"
                f"- reasoning: 简短推理\n"
                f"只返回JSON。"
            )
            response = await self._llm.chat(prompt)
            if isinstance(response, dict):
                text = response.get("content", "")
            elif isinstance(response, str):
                text = response
            else:
                text = str(response)

            try:
                json_str = text.strip()
                if json_str.startswith("```"):
                    lines = json_str.split("\n")
                    json_str = "\n".join(lines[1:-1])
                result = json.loads(json_str)
            except (json.JSONDecodeError, TypeError):
                result = {
                    "is_valid": True,
                    "credibility": citation.relevance_score,
                    "support_type": "间接支撑",
                    "reasoning": "LLM输出解析失败",
                }

            result["is_valid"] = result.get("is_valid", True)
            result["credibility"] = min(1.0, max(0.0, float(result.get("credibility", citation.relevance_score))))
            result["support_type"] = result.get("support_type", "间接支撑")
            result["reasoning"] = result.get("reasoning", "")

            return result

        except Exception as exc:
            logger.warning(f"LLM引用验证失败 ({type(exc).__name__}): {exc}")
            return {
                "is_valid": True,
                "credibility": citation.relevance_score,
                "support_type": "间接支撑",
                "reasoning": "",
            }

    async def validate_citations(
        self, response_text: str, citations: List[Citation]
    ) -> List[Dict[str, Any]]:
        results = []
        for citation in citations:
            validation = await self.validate_citation(response_text, citation)
            results.append({
                "source_id": citation.source_id,
                "source_type": citation.source_type,
                "is_valid": validation["is_valid"],
                "credibility": validation["credibility"],
                "support_type": validation["support_type"],
                "reasoning": validation["reasoning"],
            })
        return results

    async def generate_evidence_chain(
        self, response_text: str, citations: List[Citation]
    ) -> Dict[str, Any]:
        if not citations:
            return {"chain": [], "total_steps": 0, "confidence": 0.0}

        validations = await self.validate_citations(response_text, citations)

        valid_citations = []
        for citation, validation in zip(citations, validations):
            if validation["is_valid"]:
                valid_citations.append((citation, validation))

        valid_citations.sort(key=lambda x: x[1]["credibility"], reverse=True)

        if self._llm:
            try:
                chain = await self._llm_evidence_chain(response_text, valid_citations)
                return chain
            except Exception as exc:
                logger.warning(f"LLM证据链生成失败 ({type(exc).__name__}): {exc}")

        return self._keyword_evidence_chain(response_text, valid_citations)

    async def _llm_evidence_chain(
        self, response_text: str, citations_with_validation: List[Tuple[Citation, Dict]]
    ) -> Dict[str, Any]:
        evidence_summary = []
        for idx, (citation, validation) in enumerate(citations_with_validation):
            evidence_summary.append(
                f"[{idx + 1}] 类型:{validation['support_type']}, "
                f"可信度:{validation['credibility']:.2f}, "
                f"内容:{citation.snippet[:200]}"
            )

        prompt = (
            f"基于以下回答和证据，生成从情报源到结论的推理路径。\n\n"
            f"回答: {response_text[:600]}\n\n"
            f"证据列表:\n" + "\n".join(evidence_summary) + "\n\n"
            f"请以JSON格式返回:\n"
            f"- chain: 推理步骤数组，每个步骤包含 step(序号), source_id, reasoning_step(推理说明), "
            f"evidence_role(证据角色:前提/推论/佐证/结论支撑), confidence(0-1)\n"
            f"- overall_confidence: 整体置信度(0-1)\n"
            f"- reasoning_summary: 推理路径概述\n"
            f"只返回JSON。"
        )

        response = await self._llm.chat(prompt)
        if isinstance(response, dict):
            text = response.get("content", "")
        elif isinstance(response, str):
            text = response
        else:
            text = str(response)

        try:
            json_str = text.strip()
            if json_str.startswith("```"):
                lines = json_str.split("\n")
                json_str = "\n".join(lines[1:-1])
            result = json.loads(json_str)
        except (json.JSONDecodeError, TypeError):
            return self._keyword_evidence_chain(response_text, citations_with_validation)

        chain_steps = result.get("chain", [])
        for step in chain_steps:
            step.setdefault("step", 0)
            step.setdefault("source_id", "")
            step.setdefault("reasoning_step", "")
            step.setdefault("evidence_role", "佐证")
            step.setdefault("confidence", 0.5)

        overall_confidence = min(1.0, max(0.0, float(result.get("overall_confidence", 0.5))))

        return {
            "chain": chain_steps,
            "total_steps": len(chain_steps),
            "overall_confidence": round(overall_confidence, 4),
            "reasoning_summary": result.get("reasoning_summary", ""),
        }

    def _keyword_evidence_chain(
        self, response_text: str, citations_with_validation: List[Tuple[Citation, Dict]]
    ) -> Dict[str, Any]:
        role_mapping = {
            "威胁": "威胁识别",
            "攻击": "攻击确认",
            "漏洞": "漏洞佐证",
            "恶意": "恶意行为标注",
            "钓鱼": "钓鱼攻击验证",
            "勒索": "勒索行为确认",
            "溯源": "溯源依据",
            "IOC": "指标关联",
            "情报": "情报支撑",
            "数据": "数据佐证",
        }

        chain = []
        for idx, (citation, validation) in enumerate(citations_with_validation):
            snippet = citation.snippet.lower()
            role = "信息支撑"
            for keyword, mapped_role in role_mapping.items():
                if keyword.lower() in snippet:
                    role = mapped_role
                    break

            support_type = validation.get("support_type", "间接支撑")
            if support_type == "直接证据":
                evidence_role = "前提"
            elif support_type == "间接支撑":
                evidence_role = "推论"
            elif support_type == "背景信息":
                evidence_role = "佐证"
            else:
                evidence_role = "佐证"

            chain_step = {
                "step": idx + 1,
                "source_id": citation.source_id,
                "source_type": citation.source_type,
                "reasoning_step": f"通过{role}提供{support_type}",
                "evidence_role": evidence_role,
                "confidence": round(validation.get("credibility", citation.relevance_score), 4),
                "support_role": role,
                "evidence_snippet": citation.snippet[:200],
                "metadata": citation.metadata,
            }
            chain.append(chain_step)

        strong_count = sum(1 for s in chain if s["confidence"] >= 0.7)
        medium_count = sum(1 for s in chain if 0.4 <= s["confidence"] < 0.7)
        confidence = min(1.0, (strong_count * 0.5 + medium_count * 0.3 + len(chain) * 0.1))

        return {
            "chain": chain,
            "total_steps": len(chain),
            "strong_evidence": strong_count,
            "medium_evidence": medium_count,
            "weak_evidence": len(chain) - strong_count - medium_count,
            "overall_confidence": round(confidence, 4),
        }


class RAGEngine:
    def __init__(self, vector_store=None, llm_service=None, embedding_engine=None):
        self._vector_store = vector_store
        self._llm = llm_service
        self._embedding_engine = embedding_engine
        self._max_context_tokens = 4000
        self._top_k = 5
        self._relevance_threshold = 0.3
        self._current_collection = None
        self._semantic_retriever = SemanticRetriever(
            vector_store=vector_store,
            llm_service=llm_service,
            embedding_engine=embedding_engine,
        )

    def set_collection(self, collection_name: str):
        self._current_collection = collection_name

    async def query_with_rag(
        self,
        query: str,
        industry: str = None,
        top_k: int = 5,
    ) -> Dict[str, Any]:
        import time
        start = time.time()

        collection = self._current_collection
        if industry:
            collection = industry

        rag_result = await self.retrieve(
            query=query, top_k=top_k, collection=collection
        )

        documents = rag_result.documents
        reranked = await self.rerank(query=query, documents=documents, top_k=top_k)

        context, context_stats = self.optimize_context_window(
            documents=reranked, max_tokens=self._max_context_tokens
        )

        elapsed = (time.time() - start) * 1000

        return {
            "query": query,
            "industry": industry,
            "collection": collection,
            "context": context,
            "documents": reranked,
            "retrieval_time_ms": round(elapsed, 2),
            "context_stats": context_stats,
            "relevance_scores": rag_result.relevance_scores,
            "total_tokens": context_stats.get("total_tokens", 0),
        }

    async def retrieve(
        self,
        query: str,
        top_k: int = 5,
        filters: Optional[Dict] = None,
        collection: Optional[str] = None,
    ) -> RAGResult:
        import time
        start = time.time()

        documents = []
        relevance_scores = []

        if self._vector_store:
            try:
                documents, relevance_scores = await self._semantic_retriever.hybrid_search(
                    query=query, top_k=top_k, collection=collection
                )
            except Exception as exc:
                logger.warning(f"混合检索失败 ({type(exc).__name__}): {exc}")

        if not documents:
            documents, relevance_scores = await self._fallback_search(query, top_k)

        filtered_docs = []
        filtered_scores = []
        for doc, score in zip(documents, relevance_scores):
            if score >= self._relevance_threshold:
                filtered_docs.append(doc)
                filtered_scores.append(score)

        context = self._build_context(filtered_docs)

        retrieval_time = (time.time() - start) * 1000

        return RAGResult(
            query=query,
            documents=filtered_docs,
            context=context,
            total_tokens=len(context) // 4,
            retrieval_time_ms=retrieval_time,
            relevance_scores=filtered_scores,
        )

    async def hybrid_search(
        self, query: str, top_k: int = 5, collection: Optional[str] = None
    ) -> Tuple[List[Dict], List[float]]:
        return await self._semantic_retriever.hybrid_search(
            query=query, top_k=top_k, collection=collection
        )

    async def _fallback_search(
        self, query: str, top_k: int
    ) -> Tuple[List[Dict], List[float]]:
        return await self._semantic_retriever.keyword_search(query=query, top_k=top_k)

    def _simple_similarity(self, query: str, text: str) -> float:
        return self._semantic_retriever._compute_tfidf_similarity(query, text)

    def _build_context(self, documents: List[Dict]) -> str:
        context_parts = []
        total_chars = 0
        max_chars = self._max_context_tokens * 4

        for i, doc in enumerate(documents):
            content = doc.get("content", "")
            source = doc.get("source", "unknown")
            snippet = content[:500]
            entry = f"[来源{i + 1}] ({source})\n{snippet}\n"

            if total_chars + len(entry) > max_chars:
                break

            context_parts.append(entry)
            total_chars += len(entry)

        return "\n---\n".join(context_parts) if context_parts else "无相关上下文信息"

    async def rerank(self, query: str, documents: List[Dict], top_k: int = 5) -> List[Dict]:
        if not documents:
            return []

        reranker = CrossEncoderReranker(llm_service=self._llm)
        return await reranker.rerank(query=query, documents=documents, top_k=top_k)

    def optimize_context_window(self, documents: List[Dict], max_tokens: int = 4000) -> Tuple[str, Dict]:
        if not documents:
            return "", {"total_docs": 0, "used_docs": 0, "total_tokens": 0, "truncated": False}

        sorted_docs = sorted(
            documents,
            key=lambda d: d.get("relevance", d.get("rerank_score", d.get("score", 0.5))),
            reverse=True,
        )

        max_chars = max_tokens * 4
        context_parts = []
        total_chars = 0
        used_count = 0

        for i, doc in enumerate(sorted_docs):
            content = doc.get("content", "")
            source = doc.get("source", "unknown")
            relevance = doc.get("relevance", doc.get("rerank_score", doc.get("score", 0)))
            snippet = content[:600]
            entry = f"[来源{i + 1}] ({source}, 相关度:{relevance:.2f})\n{snippet}\n"

            if total_chars + len(entry) > max_chars:
                if used_count == 0:
                    truncated_entry = entry[:max_chars]
                    context_parts.append(truncated_entry)
                    total_chars += len(truncated_entry)
                    used_count += 1
                break

            context_parts.append(entry)
            total_chars += len(entry)
            used_count += 1

        context = "\n---\n".join(context_parts) if context_parts else ""
        stats = {
            "total_docs": len(documents),
            "used_docs": used_count,
            "total_tokens": total_chars // 4,
            "truncated": used_count < len(sorted_docs),
        }

        return context, stats


class DialogueManager:
    def __init__(self, llm_service=None, max_context_messages: int = 20):
        self._llm = llm_service
        self._vector_store = None
        self._max_context_messages = max_context_messages
        self._intent_analyzer = LLMIntentAnalyzer(llm_service=llm_service)
        self._system_prompts = {
            "default": "你是黑灰产情报自动化分析助手，基于DeepSeek大模型，专注于威胁情报的分析、解读和建议。你可以分析多源渠道汇聚的情报，完成清洗去重、高危意图分类、关键实体抽取、犯罪模式分析、技术链路还原。你的核心能力包括：1)黑话识别与解码（跑分/杀猪盘/四件套/猫池等）；2)威胁等级研判（critical/high/medium/low/info）；3)IoC指标提取（IP/域名/URL/Hash/邮箱）；4)攻击链路还原（引流→接触→信任建立→诱导→收割→洗钱）；5)犯罪模式识别与组织架构分析。请基于提供的上下文信息回答问题，标注信息来源，并在涉及高危威胁时主动给出预警建议。",
            "manufacturing": "你是智能制造领域黑灰产情报分析专家，基于DeepSeek大模型。你专注于分析针对工控系统(SCADA/PLC/HMI)的攻击情报、供应链安全威胁、制造业勒索软件、商业间谍活动。识别工控恶意代码、固件篡改、OT网络入侵、知识产权窃取、设备篡改等威胁模式。",
            "education": "你是智慧教育领域黑灰产情报分析专家，基于DeepSeek大模型。你专注于分析考试作弊产业链、论文代写黑灰产、学历造假网络、学生数据泄露、在线教育平台欺诈等威胁。识别代考枪手组织、题库泄露渠道、作弊工具传播链路、在线代考平台。",
            "healthcare": "你是医疗健康领域黑灰产情报分析专家，基于DeepSeek大模型。你专注于分析医疗数据泄露与贩卖、假药流通网络、医保欺诈模式、患者隐私信息贩卖、医疗设备安全漏洞、处方药非法销售等威胁。识别HIS系统入侵、处方数据倒卖、假药供应链。",
            "finance": "你是金融服务领域黑灰产情报分析专家，基于DeepSeek大模型。你专注于分析电信网络诈骗、洗钱网络、支付欺诈、信用卡盗刷、非法集资、虚拟货币洗钱、套路贷、裸贷等威胁。识别跑分平台、四件套贩卖、杀猪盘模式、资金盘骗局。",
        }

    def get_system_prompt(self, industry: Optional[str] = None) -> str:
        if industry and industry in self._system_prompts:
            return self._system_prompts[industry]
        return self._system_prompts["default"]

    def set_industry_prompt(self, prompt: str) -> bool:
        self._system_prompts["default"] = prompt
        self._industry_prompt = prompt
        return True

    async def query_with_industry(
        self,
        query: str,
        industry: str,
        system_prompt: str = None,
        context: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        if system_prompt:
            self.set_industry_prompt(system_prompt)
        rag_context = ""
        if context and isinstance(context, dict):
            rag_context = context.get("rag_context", context.get("context", ""))
        messages = self.build_messages(
            history=[], current_query=query, rag_context=rag_context, industry=industry
        )
        response = await self.generate_response(messages=messages)
        return {
            "content": response["content"],
            "industry": industry,
            "model": response["model"],
            "tokens_used": response["tokens_used"],
        }

    def build_messages(
        self,
        history: List[Dict[str, Any]],
        current_query: str,
        rag_context: str = "",
        industry: Optional[str] = None,
    ) -> List[Dict[str, str]]:
        messages = []

        system_prompt = self.get_system_prompt(industry)
        if rag_context:
            system_prompt += f"\n\n参考信息:\n{rag_context}"
        messages.append({"role": "system", "content": system_prompt})

        recent_history = history[-self._max_context_messages:]
        for msg in recent_history:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            if role in ("user", "assistant") and content:
                messages.append({"role": role, "content": content})

        messages.append({"role": "user", "content": current_query})

        return messages

    async def generate_response(
        self,
        messages: List[Dict[str, str]],
        model_id: Optional[str] = None,
        temperature: float = 0.3,
        max_tokens: int = 2048,
    ) -> Dict[str, Any]:
        if not self._llm:
            return {
                "content": "LLM服务未配置，无法生成响应。",
                "model": "none",
                "tokens_used": 0,
            }

        try:
            prompt = messages[-1]["content"] if messages else ""
            system_msg = ""
            for m in messages:
                if m["role"] == "system":
                    system_msg = m["content"]
                    break

            full_prompt = f"{system_msg}\n\n用户问题: {prompt}" if system_msg else prompt

            try:
                response = await asyncio.wait_for(
                    self._llm.chat(full_prompt),
                    timeout=120.0,
                )
            except asyncio.TimeoutError:
                logger.error("LLM响应超时 (120s)")
                return {
                    "content": "AI服务响应超时，请稍后重试",
                    "model": model_id or "unknown",
                    "tokens_used": 0,
                }

            if isinstance(response, dict):
                content = response.get("content", "")
                tokens = response.get("usage", {}).get("total_tokens", 0)
                model = response.get("model", model_id or "unknown")
            elif isinstance(response, str):
                content = response
                tokens = len(content) // 4
                model = model_id or "unknown"
            else:
                content = str(response)
                tokens = 0
                model = "unknown"

            return {
                "content": content,
                "model": model,
                "tokens_used": tokens,
            }

        except Exception as exc:
            logger.error(f"LLM响应生成失败: {exc}")
            return {
                "content": "生成响应时出错，请稍后重试",
                "model": "error",
                "tokens_used": 0,
            }

    async def summarize_history(self, messages: List[Dict[str, Any]]) -> str:
        if not messages:
            return ""

        user_msgs = [m for m in messages if m.get("role") == "user"]
        if not user_msgs:
            return ""

        if self._llm:
            try:
                conversation_text = "\n".join(
                    m.get("content", "")[:200] for m in user_msgs[-5:]
                )
                prompt = f"请对以下用户问题进行简洁摘要，保留核心主题，不超过100字:\n\n{conversation_text[:2000]}"
                response = await self._llm.chat(prompt)
                if isinstance(response, dict):
                    summary = response.get("content", "")
                elif isinstance(response, str):
                    summary = response
                else:
                    summary = str(response)
                if summary:
                    return summary
            except Exception as exc:
                logger.warning(f"LLM历史摘要失败 ({type(exc).__name__}): {exc}")

        topics = []
        for m in user_msgs[-5:]:
            content = m.get("content", "")
            if content:
                topics.append(content[:100])

        return f"之前讨论了: {'; '.join(topics)}"

    async def compress_history(self, messages: List[Dict], keep_recent: int = 4) -> List[Dict]:
        if len(messages) <= keep_recent:
            return messages

        recent = messages[-keep_recent:]
        older = messages[:-keep_recent]

        if not older:
            return recent

        older_text_parts = []
        for msg in older:
            role = msg.get("role", "")
            content = msg.get("content", "")
            if content:
                older_text_parts.append(f"{role}: {content}")

        older_text = "\n".join(older_text_parts)

        if self._llm:
            try:
                summary_prompt = f"请对以下对话历史进行简洁摘要，保留关键信息和要点，不超过200字:\n\n{older_text[:3000]}"
                response = await self._llm.chat(summary_prompt)
                if isinstance(response, dict):
                    summary = response.get("content", "")
                elif isinstance(response, str):
                    summary = response
                else:
                    summary = str(response)
            except Exception as exc:
                logger.warning(f"LLM历史摘要失败，使用关键词提取: {exc}")
                summary = self._extract_keywords(older_text)
        else:
            summary = self._extract_keywords(older_text)

        compressed = [{"role": "system", "content": f"[对话历史摘要] {summary}"}]
        compressed.extend(recent)

        return compressed

    def _extract_keywords(self, text: str) -> str:
        stop_words = {"的", "了", "是", "在", "我", "有", "和", "就", "不", "人", "都", "一", "一个", "上", "也", "很", "到", "说", "要", "去", "你", "会", "着", "没有", "看", "好", "自己", "这", "他", "她", "它", "们", "那", "些", "什么", "怎么", "如何", "可以", "吗", "呢", "吧", "啊", "the", "a", "an", "is", "are", "was", "were", "be", "been", "being", "have", "has", "had", "do", "does", "did", "will", "would", "could", "should", "may", "might", "shall", "can", "need", "dare", "ought", "used", "to", "of", "in", "for", "on", "with", "at", "by", "from", "as", "into", "through", "during", "before", "after", "above", "below", "between", "out", "off", "over", "under", "again", "further", "then", "once", "and", "but", "or", "nor", "not", "so", "if", "than", "too", "very", "just", "about"}
        words = text.lower().split()
        freq = {}
        for w in words:
            w = w.strip(".,!?;:\"'()[]{}")
            if len(w) > 1 and w not in stop_words:
                freq[w] = freq.get(w, 0) + 1
        top_keywords = sorted(freq.items(), key=lambda x: x[1], reverse=True)[:15]
        keywords_str = ", ".join(k for k, _ in top_keywords)
        return f"早期对话涉及: {keywords_str}"

    async def track_intent(self, messages: List[Dict]) -> Dict[str, Any]:
        return await self._intent_analyzer.track_intent_chain(messages)

    async def retrieve_with_rag(self, query: str, top_k: int = 5) -> List[Dict]:
        if not self._vector_store:
            return []

        try:
            query_embedding = None
            if self._llm and hasattr(self._llm, "embed"):
                try:
                    query_embedding = await self._llm.embed(query)
                except Exception as exc:
                    logger.warning(f"查询嵌入生成失败: {exc}")

            search_kwargs = {"query": query, "top_k": top_k}
            if query_embedding is not None:
                search_kwargs["embedding"] = query_embedding

            results = await self._vector_store.search(**search_kwargs)

            if not isinstance(results, list):
                return []

            documents = []
            for r in results:
                doc = r if isinstance(r, dict) else {"content": str(r), "relevance": 0.5}
                documents.append(doc)

            if query_embedding is not None and documents:
                documents = await self._cross_encoder_rerank(query_embedding, documents)

            documents = self._rerank_results(query, documents)

            return documents[:top_k]

        except Exception as exc:
            logger.error(f"RAG检索失败: {exc}")
            return []

    async def _cross_encoder_rerank(
        self, query_embedding, documents: List[Dict]
    ) -> List[Dict]:
        if not self._llm or not hasattr(self._llm, "embed"):
            return documents

        try:
            for doc in documents:
                content = doc.get("content", "")
                if not content:
                    doc["cross_encoder_score"] = 0.0
                    continue

                doc_embedding = await self._llm.embed(content[:500])
                if doc_embedding is not None and query_embedding is not None:
                    similarity = self._cosine_similarity(query_embedding, doc_embedding)
                    original_score = doc.get("relevance", doc.get("score", 0.5))
                    doc["cross_encoder_score"] = round(
                        original_score * 0.4 + similarity * 0.6, 4
                    )
                else:
                    doc["cross_encoder_score"] = doc.get(
                        "relevance", doc.get("score", 0.5)
                    )

            documents.sort(
                key=lambda d: d.get("cross_encoder_score", 0), reverse=True
            )
        except Exception as exc:
            logger.warning(f"交叉编码器重排失败 ({type(exc).__name__}): {exc}")

        return documents

    @staticmethod
    def _cosine_similarity(vec_a, vec_b) -> float:
        try:
            if hasattr(vec_a, "tolist"):
                vec_a = vec_a.tolist()
            if hasattr(vec_b, "tolist"):
                vec_b = vec_b.tolist()

            dot = sum(a * b for a, b in zip(vec_a, vec_b))
            norm_a = sum(a * a for a in vec_a) ** 0.5
            norm_b = sum(b * b for b in vec_b) ** 0.5

            if norm_a == 0 or norm_b == 0:
                return 0.0

            return dot / (norm_a * norm_b)
        except Exception as exc:
            logger.warning(f"余弦相似度计算失败: {exc}")
            return 0.0

    def _rerank_results(self, query: str, results: List[Dict]) -> List[Dict]:
        if not results:
            return []

        query_words = set(query.lower().split())
        reranked = []

        for idx, doc in enumerate(results):
            content = doc.get("content", "")
            original_score = doc.get(
                "cross_encoder_score",
                doc.get("relevance", doc.get("score", 0.5)),
            )

            content_len = len(content)
            if content_len < 50:
                length_score = 0.3
            elif content_len < 200:
                length_score = 0.7
            elif content_len < 1000:
                length_score = 1.0
            elif content_len < 3000:
                length_score = 0.8
            else:
                length_score = 0.5

            content_words = set(content.lower().split())
            if query_words:
                overlap = len(query_words & content_words) / len(query_words)
            else:
                overlap = 0.0

            position_score = 1.0 / (1.0 + idx * 0.1)

            final_score = (
                original_score * 0.5
                + length_score * 0.15
                + overlap * 0.25
                + position_score * 0.1
            )

            doc_copy = dict(doc)
            doc_copy["rerank_score"] = round(final_score, 4)
            reranked.append(doc_copy)

        reranked.sort(key=lambda d: d["rerank_score"], reverse=True)
        return reranked

    async def answer_with_citations(
        self,
        query: str,
        conversation_id: Optional[str] = None,
        top_k: int = 5,
    ) -> Dict:
        documents = await self.retrieve_with_rag(query, top_k=top_k)

        context_parts = []
        for i, doc in enumerate(documents):
            content = doc.get("content", "")
            source = doc.get("source", "unknown")
            score = doc.get("rerank_score", doc.get("relevance", 0))
            snippet = content[:500]
            context_parts.append(
                f"[{i + 1}] (来源: {source}, 相关度: {score:.2f})\n{snippet}"
            )

        rag_context = "\n---\n".join(context_parts) if context_parts else ""

        system_prompt = self.get_system_prompt()
        if rag_context:
            system_prompt += (
                "\n\n请基于以下参考信息回答问题。在回答中引用信息来源时，"
                "请使用 [1], [2] 等标注对应参考编号。"
                "如果参考信息不足以回答问题，请明确说明。\n\n"
                f"参考信息:\n{rag_context}"
            )

        messages = [{"role": "system", "content": system_prompt}]
        messages.append({"role": "user", "content": query})

        response = await self.generate_response(messages=messages)
        answer_text = response.get("content", "")
        model_used = response.get("model", "unknown")

        citations = []
        for i, doc in enumerate(documents):
            citation_marker = f"[{i + 1}]"
            if citation_marker in answer_text:
                citations.append(
                    {
                        "doc_id": doc.get("id", ""),
                        "content_preview": doc.get("content", "")[:200],
                        "source": doc.get("source", "unknown"),
                        "score": doc.get("rerank_score", doc.get("relevance", 0)),
                    }
                )

        if conversation_id is None:
            conversation_id = uuid.uuid4().hex

        return {
            "answer": answer_text,
            "citations": citations,
            "conversation_id": conversation_id,
            "model": model_used,
        }

    async def multi_turn_query(
        self,
        conversation_id: str,
        query: str,
        db_session=None,
    ) -> Dict:
        history = []

        if db_session is not None:
            try:
                from app.db.tables import QAConversationTable
                from sqlalchemy import select

                result = await db_session.execute(
                    select(QAConversationTable).where(
                        QAConversationTable.id == conversation_id
                    )
                )
                row = result.scalar_one_or_none()
                if row and row.messages_json:
                    try:
                        all_messages = json.loads(row.messages_json)
                    except (json.JSONDecodeError, TypeError):
                        all_messages = []

                    user_assistant_msgs = [
                        m for m in all_messages if m.get("role") in ("user", "assistant")
                    ]
                    history = user_assistant_msgs[-10:]
            except Exception as exc:
                logger.warning(f"加载对话历史失败: {exc}")

        rag_context = ""
        documents = await self.retrieve_with_rag(query, top_k=5)
        if documents:
            context_parts = []
            for i, doc in enumerate(documents):
                content = doc.get("content", "")
                source = doc.get("source", "unknown")
                snippet = content[:500]
                context_parts.append(f"[{i + 1}] ({source})\n{snippet}")
            rag_context = "\n---\n".join(context_parts)

        messages = self.build_messages(
            history=history,
            current_query=query,
            rag_context=rag_context,
        )

        response = await self.generate_response(messages=messages)
        answer_text = response.get("content", "")
        model_used = response.get("model", "unknown")

        if db_session is not None:
            try:
                from app.db.tables import QAConversationTable
                from sqlalchemy import select

                result = await db_session.execute(
                    select(QAConversationTable).where(
                        QAConversationTable.id == conversation_id
                    )
                )
                row = result.scalar_one_or_none()
                if row:
                    existing = []
                    try:
                        existing = json.loads(row.messages_json) if row.messages_json else []
                    except (json.JSONDecodeError, TypeError):
                        existing = []

                    user_msg = {
                        "role": "user",
                        "content": query,
                        "created_at": datetime.now(timezone.utc).isoformat(),
                    }
                    assistant_msg = {
                        "role": "assistant",
                        "content": answer_text,
                        "created_at": datetime.now(timezone.utc).isoformat(),
                    }
                    existing.extend([user_msg, assistant_msg])
                    row.messages_json = json.dumps(existing, ensure_ascii=False, default=str)
                    row.updated_at = datetime.now(timezone.utc)
                    await db_session.commit()
            except Exception as exc:
                logger.warning(f"保存对话消息失败 (conversation_id={conversation_id}, query={query[:50]}): {exc}")

        return {
            "answer": answer_text,
            "conversation_id": conversation_id,
            "model": model_used,
        }


class CitationTracker:
    def __init__(self, llm_service=None):
        self._citation_map: Dict[str, List[Citation]] = {}
        self._citation_validator = LLMCitationValidator(llm_service=llm_service)

    async def track_citations(
        self,
        response_text: str,
        source_documents: List[Dict[str, Any]],
    ) -> List[Citation]:
        citations = []

        for doc in source_documents:
            doc_id = doc.get("id", "")
            content = doc.get("content", "")
            source = doc.get("source", "unknown")
            relevance = doc.get("relevance", 0.0)

            cited = False
            snippet = ""
            match_count = 0
            if content:
                content_lower = content.lower()
                keywords = response_text.lower().split()[:20]
                match_count = sum(1 for kw in keywords if len(kw) > 2 and kw in content_lower)
                if match_count >= 3 or relevance > 0.7:
                    cited = True
                    start = 0
                    for kw in keywords:
                        idx = content_lower.find(kw)
                        if idx >= 0:
                            start = max(0, idx - 50)
                            break
                    snippet = content[start:start + 300]

            if cited:
                citation = Citation(
                    source_id=doc_id,
                    source_type=source,
                    snippet=snippet,
                    relevance_score=relevance,
                    metadata={
                        "threat_level": doc.get("threat_level", ""),
                        "matched_keywords": match_count,
                    },
                )
                citations.append(citation)

        if citations and self._citation_validator._llm:
            try:
                validations = await self._citation_validator.validate_citations(
                    response_text, citations
                )
                validated_citations = []
                for citation, validation in zip(citations, validations):
                    if validation.get("is_valid", True):
                        citation.relevance_score = validation.get(
                            "credibility", citation.relevance_score
                        )
                        citation.metadata["support_type"] = validation.get("support_type", "")
                        citation.metadata["validation_reasoning"] = validation.get("reasoning", "")
                        validated_citations.append(citation)
                    else:
                        citation.relevance_score *= 0.5
                        citation.metadata["support_type"] = "无关"
                        citation.metadata["validation_reasoning"] = validation.get("reasoning", "")
                        validated_citations.append(citation)
                citations = validated_citations
            except Exception as exc:
                logger.warning(f"LLM引用验证失败 ({type(exc).__name__}): {exc}")

        return citations

    def format_citations(self, citations: List[Citation]) -> str:
        if not citations:
            return ""

        parts = ["\n\n📎 **引用来源:**"]
        for i, c in enumerate(citations, 1):
            parts.append(
                f"{i}. [{c.source_type}] {c.snippet[:150]}... (相关度: {c.relevance_score:.1%})"
            )

        return "\n".join(parts)

    async def compute_credibility(self, citations: List[Citation]) -> float:
        if not citations:
            return 0.0

        if self._citation_validator._llm:
            try:
                validations = await self._citation_validator.validate_citations("", citations)
                credibility_scores = [
                    v.get("credibility", c.relevance_score)
                    for v, c in zip(validations, citations)
                ]
                if credibility_scores:
                    avg_credibility = sum(credibility_scores) / len(credibility_scores)
                    coverage_bonus = min(1.0, len(citations) / 3)
                    return round(avg_credibility * 0.7 + coverage_bonus * 0.3, 4)
            except Exception as exc:
                logger.warning(f"LLM可信度计算失败 ({type(exc).__name__}): {exc}")

        scores = [c.relevance_score for c in citations]
        avg_relevance = sum(scores) / len(scores)
        coverage_bonus = min(1.0, len(citations) / 3)

        return round(avg_relevance * 0.7 + coverage_bonus * 0.3, 4)

    async def generate_evidence_chain(self, response_text: str, citations: List) -> Dict[str, Any]:
        if not citations:
            return {"chain": [], "total_steps": 0, "confidence": 0.0}

        citation_objects = []
        for c in citations:
            if isinstance(c, Citation):
                citation_objects.append(c)
            else:
                citation_objects.append(Citation(
                    source_id=c.get("source_id", c.get("id", "")),
                    source_type=c.get("source_type", c.get("source", "unknown")),
                    snippet=c.get("snippet", c.get("content", "")),
                    relevance_score=c.get("relevance_score", c.get("relevance", 0.0)),
                    metadata=c.get("metadata", {}),
                ))

        return await self._citation_validator.generate_evidence_chain(response_text, citation_objects)


class QAEngine:
    def __init__(self, llm_service=None, vector_store=None, embedding_engine=None):
        self._llm = llm_service
        self._vector_store = vector_store
        self._embedding_engine = embedding_engine
        self._rag_engine = RAGEngine(
            vector_store=vector_store,
            llm_service=llm_service,
            embedding_engine=embedding_engine,
        )
        self._dialogue_manager = DialogueManager(llm_service=llm_service)
        self._citation_tracker = CitationTracker(llm_service=llm_service)

    async def query(
        self,
        query: str,
        conversation_id: Optional[str] = None,
        industry: Optional[str] = None,
        rag_enabled: bool = True,
        model_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        rag_result = None
        rag_context = ""
        source_documents = []

        if rag_enabled:
            try:
                rag_result = await self._rag_engine.retrieve(query=query, top_k=5)
                rag_context = rag_result.context
                source_documents = rag_result.documents
            except (ConnectionError, TimeoutError, OSError) as exc:
                logger.warning(f"RAG检索网络/IO错误 ({type(exc).__name__}): {exc}")
                rag_context = ""
                source_documents = []
            except (ValueError, KeyError, AttributeError) as exc:
                logger.warning(f"RAG检索数据错误 ({type(exc).__name__}): {exc}")
                rag_context = ""
                source_documents = []
            except Exception as exc:
                logger.error(f"RAG检索未知异常 ({type(exc).__name__}): {exc}")
                rag_context = ""
                source_documents = []

        history = []
        if conversation_id:
            try:
                conv = await self.load_conversation(conversation_id)
                history = conv.get("messages", [])
                if not industry:
                    industry = conv.get("industry")
                if not model_id:
                    model_id = conv.get("model_id")
            except Exception as exc:
                logger.warning(f"加载对话历史失败: {exc}")

        llm_messages = self._dialogue_manager.build_messages(
            history=history,
            current_query=query,
            rag_context=rag_context,
            industry=industry,
        )

        assistant_content = ""
        model_used = "none"
        tokens_used = 0

        if self._llm:
            try:
                response = await self._dialogue_manager.generate_response(
                    messages=llm_messages,
                    model_id=model_id,
                    temperature=0.7,
                    max_tokens=2048,
                )
                assistant_content = response.get("content", "")
                model_used = response.get("model", "unknown")
                tokens_used = response.get("tokens_used", 0)
            except Exception as exc:
                logger.error(f"LLM生成失败: {exc}")
                assistant_content = "AI服务暂时不可用，请稍后重试"
        else:
            if rag_context:
                assistant_content = f"基于检索到的相关情报数据，针对「{query}」的摘要：\n{rag_context[:500]}"
            else:
                assistant_content = f"当前AI服务未启动，无法生成智能回复。请检查LLM服务配置。"

        citations = await self._citation_tracker.track_citations(
            response_text=assistant_content,
            source_documents=source_documents,
        )

        references = [c.to_dict() for c in citations]
        confidence_score = 0.0
        if citations:
            confidence_score = await self._citation_tracker.compute_credibility(citations)

        citation_text = self._citation_tracker.format_citations(citations)
        if citation_text:
            assistant_content += citation_text

        result = {
            "content": assistant_content,
            "model_used": model_used,
            "tokens_used": tokens_used,
            "citations": references,
            "confidence_score": round(confidence_score, 4),
            "rag_enabled": rag_enabled,
            "industry": industry,
        }

        if rag_result:
            result["retrieval_info"] = rag_result.to_dict()

        if conversation_id:
            user_msg = {
                "role": "user",
                "content": query,
                "references": [],
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            assistant_msg = {
                "role": "assistant",
                "content": assistant_content,
                "references": references,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            try:
                await self.append_conversation_messages(
                    conversation_id, [user_msg, assistant_msg]
                )
            except Exception as exc:
                logger.warning(f"保存对话消息失败: {exc}")

        return result

    async def query_with_industry(
        self,
        query: str,
        industry: str,
        system_prompt: str,
        context: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        return await self._dialogue_manager.query_with_industry(
            query=query,
            industry=industry,
            system_prompt=system_prompt,
            context=context,
        )

    def set_industry_prompt(self, prompt: str) -> bool:
        return self._dialogue_manager.set_industry_prompt(prompt)

    async def add_to_knowledge_base(
        self,
        kb_id: str,
        title: str,
        content: str,
        source: str = "",
        metadata: str = "{}",
    ) -> bool:
        try:
            meta = {}
            if metadata:
                try:
                    meta = json.loads(metadata) if isinstance(metadata, str) else metadata
                except (json.JSONDecodeError, TypeError):
                    meta = {}

            doc = {
                "id": uuid.uuid4().hex,
                "title": title,
                "content": content,
                "source": source or "manual",
                "kb_id": kb_id,
                **meta,
            }

            if self._vector_store:
                try:
                    await self._vector_store.add(
                        documents=[doc],
                        collection=kb_id,
                    )
                except Exception as exc:
                    logger.warning(f"向量存储添加失败，尝试默认集合: {exc}")
                    try:
                        await self._vector_store.add(documents=[doc])
                    except Exception as exc2:
                        logger.warning(f"默认集合添加也失败: {exc2}")

            logger.info(f"知识条目已添加: kb_id={kb_id}, title={title}")
            return True
        except (ConnectionError, TimeoutError, OSError) as exc:
            logger.error(f"添加知识条目网络/存储错误 ({type(exc).__name__}, kb_id={kb_id}): {exc}")
            return False
        except Exception as exc:
            logger.error(f"添加知识条目失败 ({type(exc).__name__}, kb_id={kb_id}): {exc}")
            return False

    async def load_conversation(self, conversation_id: str, db_session=None) -> Dict[str, Any]:
        from app.db.tables import QAConversationTable
        from sqlalchemy import select

        async def _do(session):
            result = await session.execute(
                select(QAConversationTable).where(QAConversationTable.id == conversation_id)
            )
            row = result.scalar_one_or_none()
            if not row:
                return {}

            messages = []
            try:
                messages = json.loads(row.messages_json) if row.messages_json else []
            except (json.JSONDecodeError, TypeError) as exc:
                logger.warning(f"对话消息JSON解析失败: {exc}")
                messages = []

            return {
                "id": row.id,
                "title": row.title,
                "messages": messages,
                "industry": row.industry,
                "rag_enabled": row.rag_enabled,
                "model_id": row.model_id,
                "created_at": row.created_at.isoformat() if row.created_at else None,
                "updated_at": row.updated_at.isoformat() if row.updated_at else None,
            }

        if db_session is not None:
            return await _do(db_session)
        from app.db.database import async_session_factory
        async with async_session_factory() as session:
            return await _do(session)

    async def append_conversation_messages(
        self, conversation_id: str, new_messages: List[Dict], db_session=None
    ) -> None:
        from app.db.tables import QAConversationTable
        from sqlalchemy import select

        async def _do(session):
            result = await session.execute(
                select(QAConversationTable).where(QAConversationTable.id == conversation_id)
            )
            row = result.scalar_one_or_none()
            if not row:
                return

            existing = []
            try:
                existing = json.loads(row.messages_json) if row.messages_json else []
            except (json.JSONDecodeError, TypeError):
                existing = []

            existing.extend(new_messages)
            row.messages_json = json.dumps(existing, ensure_ascii=False, default=str)
            row.updated_at = datetime.now(timezone.utc)
            await session.commit()

        if db_session is not None:
            return await _do(db_session)
        from app.db.database import async_session_factory
        async with async_session_factory() as session:
            return await _do(session)

    async def create_conversation(
        self,
        title: str,
        industry: Optional[str],
        rag_enabled: bool,
        model_id: Optional[str],
        db_session=None,
    ) -> str:
        from app.db.tables import QAConversationTable

        conv_id = uuid.uuid4().hex

        async def _do(session):
            row = QAConversationTable(
                id=conv_id,
                title=title,
                messages_json="[]",
                industry=industry,
                rag_enabled=rag_enabled,
                model_id=model_id,
                created_by="qa_engine",
            )
            session.add(row)
            await session.commit()

        if db_session is not None:
            await _do(db_session)
        else:
            from app.db.database import async_session_factory
            async with async_session_factory() as session:
                await _do(session)
        return conv_id

    async def update_conversation(
        self, conversation_id: str, messages: List[Dict], db_session=None
    ) -> bool:
        from app.db.tables import QAConversationTable
        from sqlalchemy import select

        async def _do(session):
            result = await session.execute(
                select(QAConversationTable).where(QAConversationTable.id == conversation_id)
            )
            row = result.scalar_one_or_none()
            if not row:
                return False

            row.messages_json = json.dumps(messages, ensure_ascii=False, default=str)
            row.updated_at = datetime.now(timezone.utc)
            await session.commit()
            return True

        if db_session is not None:
            return await _do(db_session)
        from app.db.database import async_session_factory
        async with async_session_factory() as session:
            return await _do(session)

