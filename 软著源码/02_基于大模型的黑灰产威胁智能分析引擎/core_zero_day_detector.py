import asyncio
import hashlib
import json
import os
import pickle
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import numpy as np
from loguru import logger

from app.core.blacktalk_engine import BlackTalkEngine
from app.core.vector_store import VectorStore


class ZeroDayTerm:
    __slots__ = ("term", "normal_meaning", "criminal_meaning", "confidence", "context", "category", "is_truly_new")

    def __init__(self, term: str, normal_meaning: str, criminal_meaning: str, confidence: float, context: str, category: str, is_truly_new: bool):
        self.term = term
        self.normal_meaning = normal_meaning
        self.criminal_meaning = criminal_meaning
        self.confidence = confidence
        self.context = context
        self.category = category
        self.is_truly_new = is_truly_new

    def to_dict(self) -> dict:
        return {
            "term": self.term,
            "normal_meaning": self.normal_meaning,
            "criminal_meaning": self.criminal_meaning,
            "confidence": self.confidence,
            "context": self.context,
            "category": self.category,
            "is_truly_new": self.is_truly_new,
        }


@np.errstate(divide="ignore", invalid="ignore")
def _safe_kl(p: np.ndarray, q: np.ndarray) -> float:
    p = np.clip(p, 1e-10, None)
    q = np.clip(q, 1e-10, None)
    return float(np.sum(p * np.log(p / q)))


class SkipGramModel:
    def __init__(self, vocab_size: int, embed_dim: int = 64):
        self.vocab_size = vocab_size
        self.embed_dim = embed_dim
        scale = 0.5 / embed_dim
        self.W_in = np.random.uniform(-scale, scale, (vocab_size, embed_dim))
        self.W_out = np.random.uniform(-scale, scale, (vocab_size, embed_dim))

    def get_embedding(self, word_idx: int) -> np.ndarray:
        return self.W_in[word_idx]

    def save(self, path: str):
        np.savez(path, W_in=self.W_in, W_out=self.W_out)

    @classmethod
    def load(cls, path: str) -> "SkipGramModel":
        data = np.load(path)
        model = cls(vocab_size=data["W_in"].shape[0], embed_dim=data["W_in"].shape[1])
        model.W_in = data["W_in"]
        model.W_out = data["W_out"]
        return model


class SemanticDriftResult:
    def __init__(self, term: str, original_meaning: str, current_meaning: str,
                 drift_timeline: list, drift_velocity: float):
        self.term = term
        self.original_meaning = original_meaning
        self.current_meaning = current_meaning
        self.drift_timeline = drift_timeline
        self.drift_velocity = drift_velocity

    def to_dict(self):
        return {
            "term": self.term,
            "original_meaning": self.original_meaning,
            "current_meaning": self.current_meaning,
            "drift_timeline": self.drift_timeline,
            "drift_velocity": self.drift_velocity,
        }


class MigrationResult:
    def __init__(self, term: str, origin_platform: str, migration_path: list,
                 current_platforms: list, spread_speed: float):
        self.term = term
        self.origin_platform = origin_platform
        self.migration_path = migration_path
        self.current_platforms = current_platforms
        self.spread_speed = spread_speed

    def to_dict(self):
        return {
            "term": self.term,
            "origin_platform": self.origin_platform,
            "migration_path": self.migration_path,
            "current_platforms": self.current_platforms,
            "spread_speed": self.spread_speed,
        }


class LLMTermAnalyzer:
    LLM_CALL_TIMEOUT = 8.0

    def __init__(self, llm_service=None):
        self._llm = llm_service

    @property
    def _llm_available(self) -> bool:
        if not self._llm:
            return False
        if hasattr(self._llm, 'is_available'):
            return self._llm.is_available
        return True

    async def infer_term_meaning(self, term: str, context: str) -> Dict[str, str]:
        if not self._llm_available:
            return {"normal_meaning": "", "criminal_meaning": ""}
        try:
            prompt = (
                f"请分析以下术语在黑灰产语境中的含义。\n\n"
                f"术语：{term}\n"
                f"上下文：{context[:500]}\n\n"
                f"请用JSON格式返回，包含以下字段：\n"
                f"- normal_meaning: 该术语在常规/合法语境中的含义（如无常规含义则填'无'）\n"
                f"- criminal_meaning: 该术语在黑灰产语境中的具体含义\n\n"
                f"只返回JSON，不要其他内容。"
            )
            result = await asyncio.wait_for(
                self._llm.generate_json(
                    prompt=prompt,
                    system_prompt="你是黑灰产情报分析专家，擅长解读黑话暗语。只返回JSON格式。",
                    temperature=0.3,
                ),
                timeout=self.LLM_CALL_TIMEOUT,
            )
            return {
                "normal_meaning": result.get("normal_meaning", ""),
                "criminal_meaning": result.get("criminal_meaning", ""),
            }
        except asyncio.TimeoutError:
            logger.warning(f"LLM infer_term_meaning timed out for '{term}'")
            return {"normal_meaning": "", "criminal_meaning": ""}
        except Exception as exc:
            logger.warning(f"LLM infer_term_meaning failed for '{term}': {exc}")
            return {"normal_meaning": "", "criminal_meaning": ""}

    async def classify_term_category(self, term: str, context: str) -> str:
        if not self._llm_available:
            return ""
        try:
            prompt = (
                f"请将以下黑灰产术语分类到最匹配的领域。\n\n"
                f"术语：{term}\n"
                f"上下文：{context[:500]}\n\n"
                f"可选类别：money_laundering, fraud, gambling, hacking, drug, general\n\n"
                f"只返回类别名称，不要其他内容。"
            )
            result = await asyncio.wait_for(
                self._llm.generate(
                    prompt=prompt,
                    system_prompt="你是黑灰产情报分类专家。只返回类别名称。",
                    temperature=0.1,
                    max_tokens=20,
                ),
                timeout=self.LLM_CALL_TIMEOUT,
            )
            category = result.strip().lower()
            valid = {"money_laundering", "fraud", "gambling", "hacking", "drug", "general"}
            if category in valid:
                return category
            for v in valid:
                if v in category:
                    return v
            return ""
        except asyncio.TimeoutError:
            logger.warning(f"LLM classify_term_category timed out for '{term}'")
            return ""
        except Exception as exc:
            logger.warning(f"LLM classify_term_category failed for '{term}': {exc}")
            return ""

    async def assess_term_novelty(self, term: str, context: str) -> Dict[str, float]:
        if not self._llm_available:
            return {"novelty_score": 0.0, "confidence": 0.0}
        try:
            prompt = (
                f"请评估以下术语的新颖程度。\n\n"
                f"术语：{term}\n"
                f"上下文：{context[:500]}\n\n"
                f"评估维度：\n"
                f"1. 该术语是否为近期新出现的黑灰产暗语？\n"
                f"2. 该术语是否是对已有术语的变体或衍生？\n"
                f"3. 该术语在黑灰产圈子的流行程度预估\n\n"
                f"请用JSON格式返回：\n"
                f"- novelty_score: 新颖度评分(0-1，1表示全新未知)\n"
                f"- confidence: 评估置信度(0-1)\n\n"
                f"只返回JSON，不要其他内容。"
            )
            result = await asyncio.wait_for(
                self._llm.generate_json(
                    prompt=prompt,
                    system_prompt="你是黑灰产情报分析专家。只返回JSON格式。",
                    temperature=0.3,
                ),
                timeout=self.LLM_CALL_TIMEOUT,
            )
            return {
                "novelty_score": float(result.get("novelty_score", 0.0)),
                "confidence": float(result.get("confidence", 0.0)),
            }
        except asyncio.TimeoutError:
            logger.warning(f"LLM assess_term_novelty timed out for '{term}'")
            return {"novelty_score": 0.0, "confidence": 0.0}
        except Exception as exc:
            logger.warning(f"LLM assess_term_novelty failed for '{term}': {exc}")
            return {"novelty_score": 0.0, "confidence": 0.0}

    async def analyze_semantic_drift(self, term: str, historical_contexts: List[Dict]) -> Dict:
        if not self._llm_available or not historical_contexts:
            return {"drift_analysis": "", "predicted_direction": "", "timeline_detail": []}
        try:
            contexts_summary = []
            for i, h in enumerate(historical_contexts[:10]):
                ts = h.get("timestamp", "未知时间")
                content = h.get("content", "")[:200]
                contexts_summary.append(f"[{ts}] {content}")
            contexts_text = "\n".join(contexts_summary)

            prompt = (
                f"请分析以下术语的语义漂移情况。\n\n"
                f"术语：{term}\n\n"
                f"历史使用记录：\n{contexts_text}\n\n"
                f"请用JSON格式返回：\n"
                f"- drift_analysis: 语义漂移的详细分析（术语含义如何随时间变化）\n"
                f"- predicted_direction: 预测该术语未来含义可能的变化方向\n"
                f"- timeline_detail: 数组，每个元素包含 date(日期)、meaning_shift(含义变化描述)、significance(重要性0-1)\n\n"
                f"只返回JSON，不要其他内容。"
            )
            result = await asyncio.wait_for(
                self._llm.generate_json(
                    prompt=prompt,
                    system_prompt="你是黑灰产情报分析专家，擅长追踪术语语义演变。只返回JSON格式。",
                    temperature=0.3,
                ),
                timeout=self.LLM_CALL_TIMEOUT,
            )
            return {
                "drift_analysis": result.get("drift_analysis", ""),
                "predicted_direction": result.get("predicted_direction", ""),
                "timeline_detail": result.get("timeline_detail", []),
            }
        except asyncio.TimeoutError:
            logger.warning(f"LLM analyze_semantic_drift timed out for '{term}'")
            return {"drift_analysis": "", "predicted_direction": "", "timeline_detail": []}
        except Exception as exc:
            logger.warning(f"LLM analyze_semantic_drift failed for '{term}': {exc}")
            return {"drift_analysis": "", "predicted_direction": "", "timeline_detail": []}


class TermPropagationAnalyzer:
    PLATFORM_HIERARCHY = {
        "dark_web_forum": 1,
        "telegram": 2,
        "underground_chat": 2,
        "dark_web_market": 2,
        "social_media": 3,
        "forum": 3,
        "chat_group": 3,
        "public_forum": 4,
        "news": 5,
        "security_report": 5,
    }

    DANGER_WEIGHTS = {
        "origin_depth": 0.3,
        "spread_speed": 0.3,
        "platform_diversity": 0.2,
        "usage_volume": 0.2,
    }

    def __init__(self, vector_store: VectorStore):
        self._vector_store = vector_store

    async def analyze_propagation(self, term: str) -> Dict:
        platform_uses = await self._collect_platform_data(term)
        if not platform_uses:
            return {
                "term": term,
                "origin_platform": "unknown",
                "diffusion_path": [],
                "spread_speed": 0.0,
                "influence_radius": 0.0,
                "danger_level": "low",
            }

        origin = self._identify_origin(platform_uses)
        diffusion_path = self._build_diffusion_path(platform_uses)
        speed = self._compute_spread_speed(platform_uses)
        radius = self._compute_influence_radius(platform_uses)
        danger = self._assess_danger_level(origin, speed, platform_uses)

        return {
            "term": term,
            "origin_platform": origin,
            "diffusion_path": diffusion_path,
            "spread_speed": speed,
            "influence_radius": radius,
            "danger_level": danger,
        }

    async def _collect_platform_data(self, term: str) -> Dict[str, List[Dict]]:
        results = await self._vector_store.search_intelligence(term, n_results=50)
        platform_data: Dict[str, List[Dict]] = {}
        for result in results:
            metadata = result.get("metadata", {})
            source = metadata.get("source", "unknown")
            if source not in platform_data:
                platform_data[source] = []
            platform_data[source].append({
                "content": result.get("document", "")[:300],
                "timestamp": metadata.get("collected_at", metadata.get("timestamp", "")),
                "id": result.get("id", ""),
            })
        for platform in platform_data:
            platform_data[platform].sort(key=lambda u: u.get("timestamp", "") or "")
        return platform_data

    def _identify_origin(self, platform_uses: Dict[str, List[Dict]]) -> str:
        earliest_time = None
        earliest_platform = "unknown"
        for platform, uses in platform_uses.items():
            if uses:
                first_seen = uses[0].get("timestamp", "")
                if first_seen and (earliest_time is None or first_seen < earliest_time):
                    earliest_time = first_seen
                    earliest_platform = platform
        return earliest_platform

    def _build_diffusion_path(self, platform_uses: Dict[str, List[Dict]]) -> List[Dict]:
        platform_first_seen = []
        for platform, uses in platform_uses.items():
            if uses:
                first_seen = uses[0].get("timestamp", "")
                count = len(uses)
                depth = self.PLATFORM_HIERARCHY.get(platform, 3)
                platform_first_seen.append({
                    "platform": platform,
                    "first_seen": first_seen,
                    "count": count,
                    "depth": depth,
                })
        platform_first_seen.sort(key=lambda p: p.get("first_seen", "") or "")
        return platform_first_seen

    def _compute_spread_speed(self, platform_uses: Dict[str, List[Dict]]) -> float:
        num_platforms = len(platform_uses)
        total_uses = sum(len(uses) for uses in platform_uses.values())
        timestamps = []
        for uses in platform_uses.values():
            for u in uses:
                ts = u.get("timestamp", "")
                if ts:
                    timestamps.append(ts)
        if len(timestamps) < 2:
            return min(num_platforms / 5.0, 1.0) * min(total_uses / 10.0, 1.0)
        timestamps.sort()
        try:
            t_start = datetime.fromisoformat(timestamps[0].replace("Z", "+00:00"))
            t_end = datetime.fromisoformat(timestamps[-1].replace("Z", "+00:00"))
            duration_days = max((t_end - t_start).total_seconds() / 86400.0, 1.0)
            platform_rate = num_platforms / duration_days
            volume_rate = total_uses / duration_days
            speed = min(platform_rate * 10.0, 1.0) * 0.5 + min(volume_rate / 5.0, 1.0) * 0.5
            return min(speed, 1.0)
        except (ValueError, TypeError):
            return min(num_platforms / 5.0, 1.0) * min(total_uses / 10.0, 1.0)

    def _compute_influence_radius(self, platform_uses: Dict[str, List[Dict]]) -> float:
        num_platforms = len(platform_uses)
        total_uses = sum(len(uses) for uses in platform_uses.values())
        platform_diversity = min(num_platforms / 8.0, 1.0)
        volume_factor = min(total_uses / 20.0, 1.0)
        depth_levels = set()
        for platform in platform_uses:
            depth_levels.add(self.PLATFORM_HIERARCHY.get(platform, 3))
        depth_factor = min(len(depth_levels) / 5.0, 1.0)
        return platform_diversity * 0.4 + volume_factor * 0.3 + depth_factor * 0.3

    def _assess_danger_level(self, origin: str, speed: float, platform_uses: Dict[str, List[Dict]]) -> str:
        origin_depth = self.PLATFORM_HIERARCHY.get(origin, 3)
        depth_score = 1.0 - (origin_depth - 1) / 4.0
        num_platforms = len(platform_uses)
        total_uses = sum(len(uses) for uses in platform_uses.values())
        diversity_score = min(num_platforms / 5.0, 1.0)
        volume_score = min(total_uses / 10.0, 1.0)
        danger_score = (
            depth_score * self.DANGER_WEIGHTS["origin_depth"]
            + speed * self.DANGER_WEIGHTS["spread_speed"]
            + diversity_score * self.DANGER_WEIGHTS["platform_diversity"]
            + volume_score * self.DANGER_WEIGHTS["usage_volume"]
        )
        if danger_score >= 0.7:
            return "critical"
        elif danger_score >= 0.5:
            return "high"
        elif danger_score >= 0.3:
            return "medium"
        return "low"


class ZeroDayDetector:
    CONFIDENCE_THRESHOLD = 0.5
    DRIFT_THRESHOLD = 0.3
    EMBED_DIM = 64
    WINDOW_SIZE = 3
    NEGATIVE_SAMPLES = 5
    LEARNING_RATE = 0.025
    MIN_COUNT = 1

    _COMMON_ENGLISH_WORDS = frozenset({
        "the", "be", "to", "of", "and", "a", "in", "that", "have", "i",
        "it", "for", "not", "on", "with", "he", "as", "you", "do", "at",
        "this", "but", "his", "by", "from", "they", "we", "say", "her", "she",
        "or", "an", "will", "my", "one", "all", "would", "there", "their",
        "what", "so", "up", "out", "if", "about", "who", "get", "which", "go",
        "me", "when", "make", "can", "like", "time", "no", "just", "him",
        "know", "take", "people", "into", "year", "your", "good", "some",
        "could", "them", "see", "other", "than", "then", "now", "look",
        "only", "come", "its", "over", "think", "also", "back", "after",
        "use", "two", "how", "our", "work", "first", "well", "way", "even",
        "new", "want", "because", "any", "these", "give", "day", "most",
        "us", "is", "are", "was", "were", "been", "has", "had", "did",
        "does", "am", "being", "very", "much", "more", "such", "each",
        "own", "should", "may", "must", "might", "still", "through",
        "where", "while", "here", "between", "both", "under", "never",
        "same", "another", "before", "off", "too", "down",
        "really", "need", "right", "long", "big", "high", "old", "small",
        "large", "next", "early", "young", "important", "few", "public",
        "bad", "able", "free", "full", "sure", "real", "top",
        "best", "last", "left", "end", "run", "hand", "place",
        "case", "week", "plan", "point", "home", "room",
        "area", "money", "story", "fact", "month", "lot", "study",
        "book", "eye", "job", "word", "business", "issue", "side", "kind",
        "head", "house", "service", "friend", "father", "power", "hour",
        "game", "line", "member", "law", "car", "city", "community",
        "name", "president", "team", "minute", "idea", "body", "info",
        "parent", "face", "level", "office", "door", "health",
        "person", "art", "war", "history", "party", "result", "change",
        "morning", "reason", "research", "girl", "guy", "moment", "air",
        "teacher", "force", "education", "foot", "boy", "age", "policy",
        "process", "music", "market", "sense", "thing", "class", "action",
        "example", "world", "technology", "data", "code", "network",
        "security", "attack", "threat", "vulnerability", "exploit", "malware",
        "crypto", "novel", "zero", "day", "remote", "access", "tool",
        "server", "client", "web", "application", "software", "hardware",
        "user", "admin", "root", "shell", "script", "file",
        "password", "token", "key", "cert", "sign", "log", "event",
        "alert", "report", "scan", "probe", "check", "test", "debug",
        "proxy", "tunnel", "port", "host", "domain", "email", "phone",
        "bank", "card", "account", "payment", "transfer", "wallet",
        "bitcoin", "ethereum", "block", "chain", "miner", "exchange",
        "dark", "forum", "chat", "channel", "group",
        "post", "thread", "message", "link", "site", "page", "search",
        "download", "upload", "share", "sell", "buy", "price", "cost",
        "sale", "offer", "deal", "trade", "support", "help",
        "about", "above", "across", "again", "against", "along", "already",
        "always", "among", "around", "away", "became", "become", "becomes",
        "behind", "below", "beside", "besides", "beyond", "brought",
        "called", "certain", "clear", "close", "common", "company",
        "country", "course", "different", "done", "during", "enough",
        "every", "found", "general", "great", "group", "having",
        "however", "itself", "known", "later", "least", "less",
        "let", "likely", "little", "looked", "made", "many",
        "may", "means", "might", "million", "must", "nothing", "often",
        "order", "others", "part", "per", "perhaps", "possible",
        "probably", "quite", "rather", "said", "set", "since",
        "something", "sometimes", "state", "still", "taken", "tell",
        "though", "today", "together", "toward", "turned", "upon",
        "using", "usually", "without", "within", "yet",
        "variant", "version", "type", "form", "method", "based",
        "via", "using", "against", "through", "across", "within",
        "associated", "related", "involved", "targeted", "affected",
        "detected", "discovered", "reported", "observed", "identified",
        "analyzed", "described", "considered", "believed", "suspected",
        "appears", "contains", "includes", "requires", "provides",
        "allows", "enables", "supports", "creates", "generates",
        "performs", "operates", "functions", "works", "runs",
        "unknown", "ransomware", "double", "extortion", "backdoor",
        "botnet", "phishing", "trojan", "worm", "virus", "ransom",
        "stealer", "drainer", "loader", "dropper", "implant", "beacon",
        "exfiltration", "lateral", "persistence", "privilege",
        "escalation", "evasion", "obfuscation", "detection", "bypass",
        "infection", "propagation", "spreading", "campaign",
        "operation", "actor", "group", "apt", "advanced", "persistent",
        "command", "control", "infection", "payload", "inject",
        "encrypt", "decrypt", "encode", "decode", "obfuscate",
        "exfiltrate", "penetrate", "compromise", "breach", "intrude",
        "weaponize", "deliver", "execute", "install", "persist",
        "communicate", "exfill", "spread", "propagate", "scan",
        "recon", "reconnaissance", "enumerate", "fingerprint",
        "initial", "access", "execution", "collection", "exfiltration",
        "impact", "disruption", "destroy", "deface", "deface",
        "fraud", "scam", "scheme", "plot", "conspiracy",
        "indicators", "compromise", "artifact", "observable",
        "infrastructure", "capability", "toolset", "toolkit",
        "framework", "platform", "ecosystem", "marketplace",
        "underground", "illicit", "clandestine", "covert",
        "sophisticated", "complex", "elaborate", "intricate",
        "emerging", "evolving", "shifting", "adapting",
        "targeting", "victim", "organization", "enterprise",
        "sector", "industry", "vertical", "region", "country",
        "government", "financial", "healthcare", "energy",
        "supply", "chain", "third", "party", "vendor",
        "update", "patch", "mitigation", "remediation",
        "defense", "defender", "protection", "prevention",
        "response", "incident", "forensic", "investigation",
    })

    _CHINESE_COMMON_WORDS = frozenset({
        "出现", "新的", "可以", "通过", "利用", "进行", "发现", "攻击",
        "漏洞", "系统", "网络", "数据", "安全", "软件", "服务器", "网站",
        "用户", "信息", "技术", "问题", "方法", "功能", "服务", "平台",
        "管理", "研究", "分析", "报告", "发展", "情况", "状态", "结果",
        "影响", "原因", "条件", "环境", "资源", "目标", "过程", "关系",
        "方面", "部分", "领域", "结构", "模式", "机制", "措施", "方案",
        "政策", "制度", "标准", "规范", "要求", "原则", "理论", "概念",
        "观点", "态度", "立场", "意见", "建议", "决定", "选择", "判断",
        "评价", "认识", "理解", "思考", "讨论", "交流", "合作", "竞争",
        "冲突", "矛盾", "变化", "进步", "提高", "增加", "扩大", "加强",
        "改善", "优化", "调整", "改革", "创新", "突破", "超越", "领先",
        "优势", "特色", "差异", "相同", "类似", "相关", "重要", "关键",
        "主要", "基本", "核心", "重点", "难点", "热点", "焦点", "亮点",
        "特点", "缺点", "优点", "弱点", "起点", "终点", "角度", "层面",
        "维度", "深度", "广度", "高度", "速度", "力度", "程度", "范围",
        "规模", "水平", "质量", "效率", "效果", "成果", "成本", "风险",
        "机遇", "挑战", "困难", "障碍", "威胁", "危害", "损失", "伤害",
        "破坏", "后果", "责任", "义务", "权利", "利益", "价值", "意义",
        "作用", "目的", "动机", "背景", "基础", "前提", "因素", "现象",
        "本质", "规律", "趋势", "方向", "前景", "未来", "历史", "现状",
        "状况", "形势", "局面", "格局", "态势", "动态", "演变", "转变",
        "转化", "更新", "升级", "迭代", "替代", "取代", "淘汰", "兴起",
        "崛起", "繁荣", "衰落", "复苏", "恢复", "重建", "整合", "融合",
        "协同", "联动", "互动", "互通", "互联", "共享", "共建", "共赢",
        "互利", "互补", "协作", "配合", "支持", "帮助", "保护", "维护",
        "保障", "保证", "确保", "防范", "预防", "预警", "监控", "监测",
        "检测", "识别", "确认", "验证", "认证", "授权", "许可", "批准",
        "同意", "允许", "接受", "认可", "承认", "肯定", "否定", "拒绝",
        "反对", "抵抗", "应对", "处理", "解决", "面对", "重视", "关注",
        "关心", "担忧", "担心", "害怕", "恐惧", "紧张", "紧急", "危险",
        "严重", "恶劣", "失败", "挫折", "打击", "冲击", "震惊", "惊讶",
        "意外", "突然", "瞬间", "短暂", "暂时", "临时", "时候", "时刻",
        "时间", "日期", "年份", "月份", "周期", "阶段", "时期", "时代",
        "今天", "明天", "昨天", "早上", "中午", "下午", "晚上", "白天",
        "天气", "气候", "温度", "空气", "污染", "治理", "增强", "巩固",
        "稳定", "平稳", "安定", "和平", "和谐", "恰当", "适当", "合适",
        "正确", "准确", "精确", "真实", "客观", "公正", "公平", "公开",
        "透明", "清晰", "明确", "具体", "详细", "完整", "全面", "彻底",
        "深入", "细致", "仔细", "认真", "严谨", "严格", "严厉", "严肃",
        "慎重", "谨慎", "小心", "耐心", "决心", "信心", "信念", "理想",
        "追求", "梦想", "道路", "途径", "方式", "手段", "步骤", "程序",
        "流程", "环节", "操作", "执行", "实施", "落实", "推进", "推动",
        "促进", "带动", "引领", "引导", "指导", "培训", "教育", "学习",
        "探索", "探讨", "沟通", "对话", "协商", "谈判", "商量", "争论",
        "辩论", "争议", "分歧", "区别", "差距", "距离", "空间", "地方",
        "地区", "区域", "地带", "界限", "边界", "边缘", "中心", "要点",
        "要素", "源头", "起源", "来源", "出处", "渠道", "路径", "通道",
        "入口", "出口", "门户", "窗口", "载体", "媒体", "工具", "设备",
        "形式", "形态", "走向", "动向", "展望", "预期", "预测", "估计",
        "推测", "猜测", "评估", "鉴定", "鉴别", "辨别", "区分", "分类",
        "归类", "整理", "归纳", "总结", "概括", "提炼", "提取", "获取",
        "收集", "采集", "编辑", "编写", "编制", "撰写", "起草", "拟定",
        "制定", "出台", "发布", "公布", "宣布", "通告", "通知", "通报",
        "公告", "声明", "决策", "裁决", "判决", "裁定", "认定", "核实",
        "查证", "调查", "调研", "考察", "视察", "检查", "检验", "测试",
        "试验", "实验", "实践", "实行", "贯彻", "加快", "加速", "深化",
        "拓展", "延伸", "拓宽", "开拓", "开发", "开放", "解放", "释放",
        "激发", "激活", "启动", "开始", "开启", "发起", "发动", "组织",
        "安排", "部署", "布置", "分配", "调配", "调度", "协调", "统筹",
        "规划", "计划", "设计", "策划", "谋划", "筹备", "准备", "防备",
        "防护", "保卫", "守护", "监督", "监管", "整治", "整顿", "改造",
        "改良", "改进", "完善", "提升", "强化", "细化", "量化",
        "不同", "普遍", "特殊", "一般", "抽象", "主观", "积极", "消极",
        "主动", "被动", "直接", "间接", "内部", "外部", "正式", "公开",
        "合法", "非法", "正常", "异常", "有效", "无效", "成功",
        "错误", "虚假", "局部", "动态", "静态", "固定", "灵活",
        "传统", "现代", "新型", "高级", "低级", "中等", "优先",
        "常规", "长期", "短期", "持续", "频繁", "偶尔", "大量",
        "少量", "单一", "多样", "综合", "专业", "通用", "特定",
        "广泛", "开放", "封闭", "隐蔽", "可见", "隐藏",
        "因为", "所以", "但是", "然而", "虽然", "尽管", "如果",
        "假如", "只要", "只有", "无论", "不管", "除了", "除非",
        "而且", "并且", "或者", "还是", "由于", "基于", "根据",
        "按照", "随着", "关于", "对于", "至于", "相比", "相对",
        "针对", "面向", "为了", "以便", "以免", "导致", "引起",
        "造成", "使得", "已经", "曾经", "正在", "将要", "即将",
        "一直", "始终", "从来", "往往", "经常", "常常", "时常",
        "有时", "很少", "并不", "并非", "不再", "还没", "尚未",
        "未必", "非常", "十分", "特别", "尤其", "极其", "相当",
        "比较", "稍微", "更加", "越来越", "逐渐", "逐步", "迅速",
        "快速", "立即", "马上", "终于", "刚刚", "快要",
        "这个", "那个", "什么", "怎么", "为什么", "哪里", "谁",
        "多少", "怎样", "如何", "自己", "他们", "我们", "你们",
        "它们", "大家", "彼此", "相互", "所有", "每个", "一些",
        "任何", "其他", "另外", "分别", "各自",
        "变种", "传播", "供应链", "感染", "防御", "防护",
        "渗透", "响应", "处置", "溯源", "取证", "应急",
        "木马", "勒索", "后门", "僵尸", "钓鱼", "间谍",
        "蠕虫", "病毒", "恶意", "劫持", "篡改", "窃取",
        "盗取", "拦截", "伪造", "冒充", "欺骗", "诱骗",
        "操控", "控制", "远程", "指令", "通信", "回连",
        "注入", "执行", "提权", "横向", "持久", "驻留",
        "免杀", "混淆", "加密", "解密", "编码", "解码",
        "代理", "转发", "隧道", "反弹", "映射", "探测",
        "扫描", "爆破", "绕过", "突破", "规避", "逃逸",
        "释放", "加载", "注入", "挂钩", "回调", "劫持",
        "挖矿", "劫持", "DDoS", "CC攻击",
        "暗网", "黑产", "灰产", "诈骗", "出售", "贩卖",
        "交易", "黑市", "地下", "招募", "求购", "佣金",
        "价格", "套现", "走账", "洗白", "过桥",
        "供应链攻击", "暴力破解",
        "手法", "不少", "骗了", "很好", "很多", "很大", "很小",
        "很远", "很近", "很难", "很黑", "很白", "很红", "很快",
        "骗人", "骗取", "忽悠", "欺负", "压迫", "剥削", "敲诈",
        "恐吓", "胁迫", "强迫", "逼迫", "强制", "盗窃", "偷盗",
        "抢劫", "掠夺", "侵犯", "侵害", "损害", "损伤",
        "危险", "风险", "威胁", "恐吓", "勒索软件",
        "通过", "进行", "发现", "利用", "可以",
        "时候", "地方", "东西", "办法", "样子", "道理",
        "关系", "问题", "意思", "感觉", "需要", "知道",
        "认为", "觉得", "希望", "准备", "开始", "继续",
        "完成", "实现", "达到", "获得", "得到", "保持",
        "支持", "帮助", "解决", "处理", "管理", "控制",
        "掌握", "了解", "认识", "理解", "思考", "讨论",
        "交流", "合作", "竞争", "变化", "发展", "进步",
        "提高", "增加", "扩大", "加强", "改善", "优化",
        "调整", "改革", "创新", "突破", "超越", "领先",
        "优势", "特色", "差异", "相同", "类似", "相关",
        "重要", "关键", "主要", "基本", "核心", "重点",
        "特点", "缺点", "优点", "弱点", "角度", "层面",
        "深度", "广度", "高度", "速度", "力度", "程度",
        "范围", "规模", "水平", "质量", "效率", "效果",
        "成果", "成本", "机遇", "挑战", "困难", "障碍",
        "危害", "损失", "伤害", "破坏", "影响", "后果",
        "责任", "利益", "价值", "意义", "作用", "目的",
        "动机", "背景", "基础", "前提", "因素", "现象",
        "本质", "规律", "趋势", "方向", "前景", "未来",
        "历史", "现状", "状况", "形势", "局面", "格局",
        "态势", "动态", "演变", "转变", "转化", "更新",
        "升级", "迭代", "替代", "取代", "淘汰", "兴起",
        "崛起", "繁荣", "衰落", "复苏", "恢复", "重建",
        "整合", "融合", "协同", "联动", "互动", "互通",
        "互联", "共享", "共建", "共赢", "互利", "互补",
        "协作", "配合", "保护", "维护", "保障", "保证",
        "确保", "防范", "预防", "预警", "监控", "监测",
        "检测", "识别", "确认", "验证", "认证", "授权",
        "许可", "批准", "同意", "允许", "接受", "认可",
        "承认", "肯定", "否定", "拒绝", "反对", "抵抗",
        "应对", "解决", "面对", "重视", "关注", "关心",
        "担忧", "担心", "害怕", "恐惧", "紧张", "紧急",
        "严重", "恶劣", "失败", "挫折", "打击", "冲击",
        "震惊", "惊讶", "意外", "突然", "瞬间", "短暂",
        "暂时", "临时", "时间", "日期", "年份", "月份",
        "周期", "阶段", "时期", "时代", "今天", "明天",
        "昨天", "天气", "气候", "温度", "空气", "污染",
        "治理", "增强", "巩固", "稳定", "平稳", "安定",
        "和平", "和谐", "恰当", "适当", "合适", "正确",
        "准确", "精确", "真实", "客观", "公正", "公平",
        "公开", "透明", "清晰", "明确", "具体", "详细",
        "完整", "全面", "彻底", "深入", "细致", "仔细",
        "认真", "严谨", "严格", "严厉", "严肃", "慎重",
        "谨慎", "小心", "耐心", "决心", "信心", "信念",
        "理想", "追求", "梦想", "道路", "途径", "方式",
        "手段", "步骤", "程序", "流程", "环节", "操作",
        "执行", "实施", "落实", "推进", "推动", "促进",
        "带动", "引领", "引导", "指导", "培训", "教育",
        "学习", "探索", "探讨", "沟通", "对话", "协商",
        "谈判", "商量", "争论", "辩论", "争议", "分歧",
        "区别", "差距", "距离", "空间", "地区", "区域",
        "地带", "界限", "边界", "边缘", "中心", "要点",
        "要素", "源头", "起源", "来源", "出处", "渠道",
        "路径", "入口", "出口", "门户", "窗口", "载体",
        "媒体", "工具", "设备", "形式", "形态", "走向",
        "动向", "展望", "预期", "预测", "估计", "推测",
        "猜测", "评估", "鉴定", "鉴别", "辨别", "区分",
        "分类", "归类", "整理", "归纳", "总结", "概括",
        "提炼", "提取", "获取", "收集", "采集", "编辑",
        "编写", "编制", "撰写", "起草", "拟定", "制定",
        "出台", "发布", "公布", "宣布", "通告", "通知",
        "通报", "公告", "声明", "决策", "裁决", "判决",
        "裁定", "认定", "核实", "查证", "调查", "调研",
        "考察", "视察", "检查", "检验", "测试", "试验",
        "实验", "实践", "实行", "贯彻", "加快", "加速",
        "深化", "拓展", "延伸", "拓宽", "开拓", "开发",
        "开放", "解放", "释放", "激发", "激活", "启动",
        "开始", "开启", "发起", "发动", "组织", "安排",
        "部署", "布置", "分配", "调配", "调度", "协调",
        "统筹", "规划", "计划", "设计", "策划", "谋划",
        "筹备", "准备", "防备", "防护", "保卫", "守护",
        "监督", "监管", "整治", "整顿", "改造", "改良",
        "改进", "完善", "提升", "强化", "细化", "量化",
        "散步", "出去", "适合",
    })

    _CHINESE_CRIMINAL_CONTEXT_KEYWORDS = frozenset({
        "暗网", "黑产", "灰产", "诈骗", "恶意", "木马", "勒索", "后门",
        "漏洞利用", "0day", "零日", "黑客", "攻击", "变种", "传播",
        "出售", "贩卖", "交易", "黑市", "地下", "非法", "违规",
        "盗取", "窃取", "入侵", "植入", "感染", "僵尸", "远控",
        "提权", "绕过", "突破", "免杀", "混淆", "挖矿", "劫持",
        "钓鱼", "间谍", "蠕虫", "病毒", "篡改", "伪造", "冒充",
        "欺骗", "诱骗", "操控", "拦截", "爆破", "暴力破解",
        "供应链攻击", "勒索软件", "双重勒索", "数据泄露",
        "跑分", "洗钱", "套现", "杀猪盘", "套路贷", "四件套",
        "水房", "车手", "接码", "养号", "薅羊毛", "色流",
        "撞库", "脱库", "社工", "肉鸡", "抓鸡", "挂马",
        "DDoS", "CC攻击", "黑SEO", "菠菜", "盘口",
        "招募", "求购", "佣金", "价格", "通道", "码商",
        "电诈", "引流", "话术", "操盘手", "资金盘",
        "出货", "收网", "分赃", "上线", "下线",
    })

    def __init__(self, vector_store: VectorStore, blacktalk_engine: BlackTalkEngine, llm_service=None):
        self.vector_store = vector_store
        self.blacktalk_engine = blacktalk_engine
        self._llm_service = llm_service
        self._llm_analyzer = LLMTermAnalyzer(llm_service)
        self._propagation_analyzer = TermPropagationAnalyzer(vector_store)
        self._word2idx: Dict[str, int] = {}
        self._idx2word: Dict[int, str] = {}
        self._word_freq: Counter = Counter()
        self._model: Optional[SkipGramModel] = None
        self._reference_dist: Optional[np.ndarray] = None
        self._term_vectors: Dict[str, np.ndarray] = {}
        self._trained = False
        self._max_vocab = 20000
        self._persist_dir = "./model_data/zero_day"
        self._segmentation_dict: Optional[Dict[str, int]] = None
        os.makedirs(self._persist_dir, exist_ok=True)

    def _build_segmentation_dict(self) -> Dict[str, int]:
        if self._segmentation_dict is not None:
            return self._segmentation_dict
        known_terms = set(self.blacktalk_engine._term_index.keys())
        all_words = self._CHINESE_COMMON_WORDS | self._CHINESE_CRIMINAL_CONTEXT_KEYWORDS | known_terms
        self._segmentation_dict = {}
        for word in all_words:
            if len(word) >= 2:
                self._segmentation_dict[word] = len(word)
        return self._segmentation_dict

    def _forward_max_match(self, text: str, dictionary: Dict[str, int]) -> List[Tuple[str, bool]]:
        result = []
        i = 0
        n = len(text)
        while i < n:
            matched = False
            max_len = min(6, n - i)
            for length in range(max_len, 1, -1):
                candidate = text[i:i + length]
                if candidate in dictionary:
                    result.append((candidate, True))
                    i += length
                    matched = True
                    break
            if not matched:
                result.append((text[i], False))
                i += 1
        return result

    def _tokenize(self, text: str) -> List[str]:
        result = []
        i = 0
        lower = text.lower()
        n = len(lower)
        while i < n:
            ch = lower[i]
            if '\u4e00' <= ch <= '\u9fff':
                chinese_segment = []
                while i < n and '\u4e00' <= lower[i] <= '\u9fff':
                    chinese_segment.append(lower[i])
                    i += 1
                for j in range(len(chinese_segment) - 1):
                    result.append(chinese_segment[j] + chinese_segment[j + 1])
            elif ch.isascii() and ch.isalpha():
                start = i
                while i < n and lower[i].isascii() and lower[i].isalpha():
                    i += 1
                word = lower[start:i]
                if len(word) >= 2:
                    if len(word) < 6:
                        result.append(word)
                    else:
                        sub = self._try_split_compound(word)
                        if sub and len(sub) > 1:
                            result.extend(sub)
                        else:
                            result.append(word)
            elif ch.isdigit():
                while i < n and lower[i].isdigit():
                    i += 1
            else:
                i += 1
        return result

    def _try_split_compound(self, token: str) -> Optional[List[str]]:
        if len(token) < 6:
            return None
        n = len(token)
        best_split = None
        best_score = 0
        for i in range(2, n - 1):
            left = token[:i]
            right = token[i:]
            if len(left) < 2 or len(right) < 2:
                continue
            left_known = left in self._COMMON_ENGLISH_WORDS
            right_known = right in self._COMMON_ENGLISH_WORDS
            if left_known and right_known:
                score = len(left) + len(right)
                if score > best_score:
                    best_score = score
                    best_split = [left, right]
            elif left_known and len(right) >= 3:
                sub_right = self._try_split_compound(right)
                if sub_right and len(sub_right) > 1:
                    score = len(left) + sum(len(w) for w in sub_right)
                    if score > best_score:
                        best_score = score
                        best_split = [left] + sub_right
        return best_split

    def _build_vocab(self, corpus: List[str]):
        self._word_freq = Counter()
        for text in corpus:
            tokens = self._tokenize(text)
            self._word_freq.update(tokens)

        self._word2idx = {}
        self._idx2word = {}
        idx = 0
        for word, freq in self._word_freq.items():
            if freq >= self.MIN_COUNT:
                self._word2idx[word] = idx
                self._idx2word[idx] = word
                idx += 1
                if len(self._word2idx) > self._max_vocab:
                    oldest_word = next(iter(self._word2idx))
                    oldest_idx = self._word2idx[oldest_word]
                    self._idx2word.pop(oldest_idx, None)
                    self._term_vectors.pop(oldest_word, None)
                    del self._word2idx[oldest_word]

        logger.info(f"Vocabulary built: {len(self._word2idx)} words from {len(corpus)} documents")

    def _generate_training_pairs(self, corpus: List[str]) -> List[Tuple[int, int]]:
        pairs = []
        for text in corpus:
            tokens = self._tokenize(text)
            indices = [self._word2idx[t] for t in tokens if t in self._word2idx]
            for i, center in enumerate(indices):
                for j in range(max(0, i - self.WINDOW_SIZE), min(len(indices), i + self.WINDOW_SIZE + 1)):
                    if i != j:
                        pairs.append((center, indices[j]))
        return pairs

    def _negative_sampling(self, num_neg: int) -> np.ndarray:
        freq = np.array([self._word_freq.get(self._idx2word.get(i, ""), 1) for i in range(len(self._idx2word))])
        freq = np.power(freq, 0.75)
        freq = freq / freq.sum()
        return np.random.choice(len(freq), size=num_neg, p=freq)

    def train(self, corpus: List[str], epochs: int = 3):
        if not corpus:
            logger.warning("Empty corpus, skipping training")
            return

        self._build_vocab(corpus)
        if len(self._word2idx) < 2:
            logger.warning("Vocabulary too small for training")
            return

        self._model = SkipGramModel(len(self._word2idx), self.EMBED_DIM)
        pairs = self._generate_training_pairs(corpus)
        if not pairs:
            logger.warning("No training pairs generated")
            return

        logger.info(f"Training Skip-gram: {len(pairs)} pairs, {epochs} epochs")

        for epoch in range(epochs):
            np.random.shuffle(pairs)
            total_loss = 0.0
            lr = self.LEARNING_RATE * (1.0 - epoch / epochs)
            lr = max(lr, 0.001)

            for center, context in pairs:
                v_c = self._model.W_in[center]
                v_o = self._model.W_out[context]
                score = np.dot(v_c, v_o)
                score = np.clip(score, -10, 10)
                sig = 1.0 / (1.0 + np.exp(-score))
                grad_out = (sig - 1.0) * v_c
                grad_in = (sig - 1.0) * v_o
                self._model.W_out[context] -= lr * grad_out
                self._model.W_in[center] -= lr * grad_in
                total_loss += -np.log(sig + 1e-10)

                neg_indices = self._negative_sampling(self.NEGATIVE_SAMPLES)
                for neg in neg_indices:
                    v_n = self._model.W_out[neg]
                    score_neg = np.dot(v_c, v_n)
                    score_neg = np.clip(score_neg, -10, 10)
                    sig_neg = 1.0 / (1.0 + np.exp(score_neg))
                    grad_neg_out = (sig_neg - 0.0) * v_c
                    grad_neg_in = (sig_neg - 0.0) * v_n
                    self._model.W_out[neg] -= lr * grad_neg_out
                    self._model.W_in[center] -= lr * grad_neg_in

            if (epoch + 1) % 5 == 0 or epoch == 0:
                logger.info(f"Epoch {epoch + 1}/{epochs}, loss: {total_loss / len(pairs):.4f}")

        self._compute_reference_distribution(corpus)
        self._extract_term_vectors()
        self._trained = True
        self._save_model()
        logger.info("Skip-gram training complete")

    def _compute_reference_distribution(self, corpus: List[str]):
        all_embeddings = []
        for text in corpus:
            tokens = self._tokenize(text)
            for t in tokens:
                if t in self._word2idx:
                    all_embeddings.append(self._model.get_embedding(self._word2idx[t]))

        if not all_embeddings:
            return

        all_emb = np.array(all_embeddings)
        centroid = all_emb.mean(axis=0)
        dists = np.linalg.norm(all_emb - centroid, axis=1)
        n_bins = 20
        hist, _ = np.histogram(dists, bins=n_bins, density=True)
        self._reference_dist = hist / hist.sum()

    def _extract_term_vectors(self):
        for term in self.blacktalk_engine._term_index:
            tokens = self._tokenize(term)
            vectors = []
            for t in tokens:
                if t in self._word2idx:
                    vectors.append(self._model.get_embedding(self._word2idx[t]))
            if vectors:
                self._term_vectors[term] = np.mean(vectors, axis=0)

    def _compute_kl_drift(self, text: str) -> float:
        if not self._trained or self._reference_dist is None:
            return 0.0

        tokens = self._tokenize(text)
        vectors = []
        for t in tokens:
            if t in self._word2idx:
                try:
                    vec = self._model.get_embedding(self._word2idx[t])
                    if vec is not None and np.all(np.isfinite(vec)):
                        vectors.append(vec)
                except (IndexError, ValueError):
                    continue

        if len(vectors) < 2:
            return 0.0

        emb = np.array(vectors)
        centroid = emb.mean(axis=0)
        dists = np.linalg.norm(emb - centroid, axis=1)
        n_bins = len(self._reference_dist)
        if n_bins == 0:
            return 0.0
        hist, _ = np.histogram(dists, bins=n_bins, density=True)
        hist_sum = hist.sum()
        if hist_sum == 0:
            return 0.0
        current_dist = hist / hist_sum

        kl_div = _safe_kl(current_dist, self._reference_dist)
        return min(kl_div, 2.0)

    def _compute_context_anomaly(self, term: str, context: str) -> float:
        if not self._trained or term not in self._term_vectors:
            return 0.5

        term_vec = self._term_vectors[term]
        context_tokens = self._tokenize(context)
        context_vecs = []
        for t in context_tokens:
            if t in self._word2idx:
                context_vecs.append(self._model.get_embedding(self._word2idx[t]))

        if not context_vecs:
            return 0.5

        context_mean = np.mean(context_vecs, axis=0)
        norm_term = np.linalg.norm(term_vec)
        norm_context = np.linalg.norm(context_mean)

        if norm_term < 1e-8 or norm_context < 1e-8:
            return 0.5

        similarity = float(np.dot(term_vec, context_mean) / (norm_term * norm_context))
        anomaly = 1.0 - max(0.0, min(1.0, (similarity + 1) / 2))
        return anomaly

    def _detect_unknown_terms(self, text: str) -> List[Dict]:
        tokens = self._tokenize(text)
        known_terms = set(self.blacktalk_engine._term_index.keys())
        candidates = []

        english_tokens = []
        for t in tokens:
            if not any('\u4e00' <= ch <= '\u9fff' for ch in t):
                english_tokens.append(t)

        seen_ngrams = set()
        for i in range(len(english_tokens)):
            for length in range(1, min(4, len(english_tokens) - i + 1)):
                token_slice = english_tokens[i:i + length]
                if length == 1:
                    ngram = token_slice[0]
                    if ngram in self._COMMON_ENGLISH_WORDS:
                        continue
                    if ngram in known_terms:
                        continue
                    if len(ngram) < 3:
                        continue
                else:
                    ngram = " ".join(token_slice)
                    if ngram in known_terms:
                        continue
                    if all(t in self._COMMON_ENGLISH_WORDS for t in token_slice):
                        continue
                    if ngram in seen_ngrams:
                        continue

                seen_ngrams.add(ngram)

                context_anomaly = self._compute_context_anomaly(ngram, text)
                kl_drift = self._compute_kl_drift(text)

                confidence = 0.0
                if context_anomaly > 0.4:
                    confidence += 0.3
                if kl_drift > self.DRIFT_THRESHOLD:
                    confidence += 0.3
                if any(kw in text for kw in ["出售", "价格", "佣金", "套现", "跑分", "通道", "接码", "养号", "求购", "招募", "暗网", "黑产", "诈骗", "恶意", "木马", "勒索", "后门", "攻击", "变种", "传播"]):
                    confidence += 0.2
                if context_anomaly > 0.6:
                    confidence += 0.2

                confidence = min(confidence, 1.0)

                if confidence >= self.CONFIDENCE_THRESHOLD:
                    candidates.append({
                        "term": ngram,
                        "confidence": confidence,
                        "context_anomaly": context_anomaly,
                        "kl_drift": kl_drift,
                        "context": text[max(0, text.find(ngram) - 20):text.find(ngram) + len(ngram) + 20],
                    })

        seen = set()
        unique = []
        for c in sorted(candidates, key=lambda x: x["confidence"], reverse=True):
            if c["term"] not in seen:
                seen.add(c["term"])
                unique.append(c)

        return unique

    def _is_common_word_combination(self, tokens: List[str]) -> bool:
        if not tokens or len(tokens) < 2:
            return False
        all_common = all(t in self._COMMON_ENGLISH_WORDS for t in tokens)
        if all_common:
            return True
        if len(tokens) == 2:
            combined = tokens[0] + tokens[1]
            if combined in self._COMMON_ENGLISH_WORDS:
                return True
        return False

    _CHINESE_FUNCTION_CHARS = frozenset("的了在是我有和就不人都一个上也很好说到要去你会着看他这那他她它们把被让给对向从到为与以至于而且或但如若则虽因故什怎多么")

    def _detect_chinese_zero_day_terms(self, text: str) -> List[Dict]:
        chinese_segments = re.findall(r'[\u4e00-\u9fff]+', text)
        if not chinese_segments:
            return []

        known_terms = set(self.blacktalk_engine._term_index.keys())
        all_known = self._CHINESE_COMMON_WORDS | self._CHINESE_CRIMINAL_CONTEXT_KEYWORDS | known_terms

        has_criminal_context = any(kw in text for kw in self._CHINESE_CRIMINAL_CONTEXT_KEYWORDS)
        if not has_criminal_context:
            return []

        seg_dict = self._build_segmentation_dict()
        candidates = []

        for segment in chinese_segments:
            segmented = self._forward_max_match(segment, seg_dict)
            oov_spans = []
            current_oov_start = None
            current_oov_chars = []

            for idx, (token, is_known) in enumerate(segmented):
                if not is_known:
                    if current_oov_start is None:
                        current_oov_start = idx
                    current_oov_chars.append(token)
                else:
                    if current_oov_chars:
                        oov_spans.append((current_oov_start, "".join(current_oov_chars)))
                        current_oov_start = None
                        current_oov_chars = []
            if current_oov_chars:
                oov_spans.append((current_oov_start, "".join(current_oov_chars)))

            for span_start, oov_text in oov_spans:
                if len(oov_text) < 2:
                    continue
                for glen in range(min(4, len(oov_text)), 1, -1):
                    for k in range(len(oov_text) - glen + 1):
                        chunk = oov_text[k:k + glen]
                        if chunk in all_known:
                            continue
                        if chunk[0] in self._CHINESE_FUNCTION_CHARS or chunk[-1] in self._CHINESE_FUNCTION_CHARS:
                            continue
                        if self._can_decompose_into_known(chunk, all_known):
                            continue

                        confidence = 0.3
                        if has_criminal_context:
                            confidence += 0.3
                        if len(chunk) >= 2:
                            confidence += 0.2
                        kl_drift = self._compute_kl_drift(text) if self._trained else 0.0
                        if kl_drift > self.DRIFT_THRESHOLD:
                            confidence += 0.2

                        context_anomaly = 0.0
                        if self._trained:
                            context_anomaly = self._compute_context_anomaly(chunk, text)
                            if context_anomaly > 0.5:
                                confidence = min(confidence + 0.15, 1.0)

                        confidence = min(confidence, 1.0)

                        if confidence >= self.CONFIDENCE_THRESHOLD:
                            idx = text.find(chunk)
                            ctx = text[max(0, idx - 20):idx + len(chunk) + 20]
                            candidates.append({
                                "term": chunk,
                                "confidence": confidence,
                                "context_anomaly": context_anomaly,
                                "kl_drift": kl_drift,
                                "context": ctx,
                                "_start": idx,
                                "_length": len(chunk),
                            })

            covered = [False] * len(segment)
            for word in all_known:
                if len(word) < 2:
                    continue
                start = 0
                while True:
                    idx = segment.find(word, start)
                    if idx == -1:
                        break
                    for j in range(idx, min(idx + len(word), len(covered))):
                        covered[j] = True
                    start = idx + 1

            i = 0
            while i < len(segment):
                if covered[i]:
                    i += 1
                    continue
                j = i
                while j < len(segment) and not covered[j]:
                    j += 1
                gap = segment[i:j]
                if len(gap) >= 2:
                    for glen in range(min(4, len(gap)), 1, -1):
                        for k in range(len(gap) - glen + 1):
                            chunk = gap[k:k + glen]
                            if chunk in all_known:
                                continue
                            if chunk[0] in self._CHINESE_FUNCTION_CHARS or chunk[-1] in self._CHINESE_FUNCTION_CHARS:
                                continue
                            if self._can_decompose_into_known(chunk, all_known):
                                continue

                            confidence = 0.3
                            if has_criminal_context:
                                confidence += 0.3
                            if len(chunk) >= 2:
                                confidence += 0.2
                            kl_drift = self._compute_kl_drift(text) if self._trained else 0.0
                            if kl_drift > self.DRIFT_THRESHOLD:
                                confidence += 0.2

                            confidence = min(confidence, 1.0)

                            if confidence >= self.CONFIDENCE_THRESHOLD:
                                idx = text.find(chunk)
                                ctx = text[max(0, idx - 20):idx + len(chunk) + 20]
                                candidates.append({
                                    "term": chunk,
                                    "confidence": confidence,
                                    "context_anomaly": 0.0,
                                    "kl_drift": kl_drift,
                                    "context": ctx,
                                    "_start": idx,
                                    "_length": len(chunk),
                                })
                i = j

        accepted = []
        accepted_spans = []
        for c in sorted(candidates, key=lambda x: (-x["_length"], -x["confidence"])):
            subsumed = False
            for span_start, span_end in accepted_spans:
                if c["_start"] >= span_start and c["_start"] + c["_length"] <= span_end:
                    subsumed = True
                    break
            if not subsumed and c["term"] not in [a["term"] for a in accepted]:
                accepted_spans.append((c["_start"], c["_start"] + c["_length"]))
                accepted.append(c)

        results = []
        for c in accepted:
            results.append({
                "term": c["term"],
                "confidence": c["confidence"],
                "context_anomaly": c["context_anomaly"],
                "kl_drift": c["kl_drift"],
                "context": c["context"],
            })

        return results

    def _can_decompose_into_known(self, chunk: str, dictionary: set) -> bool:
        n = len(chunk)
        if n <= 2:
            return False
        dp = [False] * (n + 1)
        dp[0] = True
        for i in range(1, n + 1):
            for length in range(2, min(5, i + 1)):
                if dp[i - length] and chunk[i - length:i] in dictionary:
                    dp[i] = True
                    break
        return dp[n]

    async def detect_zero_day_terms(self, text: str) -> List:
        if not self._trained:
            self._try_load_model()

        known_terms = set(self.blacktalk_engine._term_index.keys())
        candidates = self._detect_unknown_terms(text)
        chinese_candidates = self._detect_chinese_zero_day_terms(text)

        seen = set()
        unique_candidates = []
        for c in sorted(candidates + chinese_candidates, key=lambda x: x["confidence"], reverse=True):
            if c["term"] not in seen:
                seen.add(c["term"])
                unique_candidates.append(c)

        results = []
        for c in unique_candidates:
            term = c["term"]
            if term in known_terms:
                continue
            if self._is_in_dictionary(term):
                continue

            category = await self._infer_category_enhanced(c["context"], term)
            normal_meaning, criminal_meaning = await self._infer_meanings_enhanced(term, c["context"])

            novelty_score = 0.0
            if self._llm_service is not None:
                try:
                    novelty = await self._llm_analyzer.assess_term_novelty(term, c["context"])
                    novelty_score = novelty.get("novelty_score", 0.0)
                except Exception:
                    pass

            is_truly_new = novelty_score >= 0.6 if self._llm_service else True

            results.append(ZeroDayTerm(
                term=term,
                normal_meaning=normal_meaning,
                criminal_meaning=criminal_meaning,
                confidence=c["confidence"],
                context=c["context"],
                category=category,
                is_truly_new=is_truly_new,
            ))

        results.sort(key=lambda t: t.confidence, reverse=True)
        logger.info(f"Zero-day detection: {len(results)} new terms found (KL drift + context anomaly)")
        return results

    def _is_in_dictionary(self, term: str) -> bool:
        return term in self.blacktalk_engine._term_index

    async def _infer_category_enhanced(self, context: str, term: str = "") -> str:
        fallback = self._infer_category_from_context(context)
        if self._llm_service is None or not term:
            return fallback
        try:
            llm_category = await self._llm_analyzer.classify_term_category(term, context)
            if llm_category:
                return llm_category
        except Exception as exc:
            logger.warning(f"LLM category classification failed, falling back: {exc}")
        return fallback

    async def _infer_meanings_enhanced(self, term: str, context: str) -> Tuple[str, str]:
        if self._llm_service is not None:
            try:
                meanings = await self._llm_analyzer.infer_term_meaning(term, context)
                normal = meanings.get("normal_meaning", "")
                criminal = meanings.get("criminal_meaning", "")
                if normal or criminal:
                    return (
                        normal or self._guess_normal_meaning(term),
                        criminal or self._guess_criminal_meaning(context, term),
                    )
            except Exception as exc:
                logger.warning(f"LLM meaning inference failed, falling back: {exc}")
        return self._guess_normal_meaning(term), self._guess_criminal_meaning(context, term)

    def _infer_category_from_context(self, context: str) -> str:
        category_keywords = {
            "money_laundering": ["跑分", "水房", "套现", "通道", "四件套", "走账", "洗白", "码商"],
            "fraud": ["诈骗", "杀猪", "套路", "话术", "引流", "薅羊毛", "接码", "养号"],
            "gambling": ["菠菜", "盘口", "菜农", "代理", "返水"],
            "hacking": ["木马", "挂马", "漏洞", "入侵", "脱库", "撞库", "肉鸡", "DDoS"],
            "drug": ["毒品", "大麻", "冰毒"],
        }
        for cat, kws in category_keywords.items():
            for kw in kws:
                if kw in context:
                    return cat
        return "other"

    def _guess_normal_meaning(self, term: str) -> str:
        if term.isascii():
            return f"英文术语"
        if len(term) <= 2:
            return f"常见缩写"
        return f"常规含义待确认"

    def _guess_criminal_meaning(self, context: str, term: str) -> str:
        meaning_hints = {
            "出售": "可能与非法交易相关",
            "价格": "可能与黑产定价相关",
            "佣金": "可能与黑产分赃相关",
            "通道": "可能与资金通道相关",
            "跑分": "可能与洗钱相关",
            "接码": "可能与验证码服务相关",
            "养号": "可能与账号培育相关",
        }
        for hint, meaning in meaning_hints.items():
            if hint in context:
                return meaning
        return "黑灰产含义待确认"

    async def track_semantic_drift(self, term: str) -> "SemanticDriftResult":
        if not self._trained:
            self._try_load_model()

        historical_uses = await self._find_historical_uses(term)

        if not historical_uses:
            return SemanticDriftResult(
                term=term, original_meaning="", current_meaning="",
                drift_timeline=[], drift_velocity=0.0,
            )

        dict_meaning = ""
        if term in self.blacktalk_engine._term_index:
            term_id = self.blacktalk_engine._term_index[term]
            bt = self.blacktalk_engine._dictionary.get(term_id)
            if bt:
                dict_meaning = bt.meaning

        timeline = []
        drift_scores = []
        for u in historical_uses:
            content = u.get("content", "")
            kl = self._compute_kl_drift(content)
            anomaly = self._compute_context_anomaly(term, content)
            drift_score = (kl + anomaly) / 2.0
            drift_scores.append(drift_score)
            timeline.append({
                "date": u.get("timestamp", "未知"),
                "meaning": f"上下文异常度: {anomaly:.2f}, KL散度: {kl:.2f}",
                "source": u.get("source", "未知"),
                "drift_score": drift_score,
            })

        drift_velocity = float(np.mean(drift_scores)) if drift_scores else 0.0

        current_meaning = dict_meaning
        if drift_velocity > self.DRIFT_THRESHOLD and len(historical_uses) > 1:
            latest = historical_uses[-1].get("content", "")
            current_meaning = f"[语义漂移检测] 原始: {dict_meaning}, 当前上下文暗示含义可能已变化 (漂移速度: {drift_velocity:.2f})"

        if self._llm_service is not None and len(historical_uses) >= 2:
            try:
                llm_analysis = await self._llm_analyzer.analyze_semantic_drift(term, historical_uses)
                if llm_analysis.get("drift_analysis"):
                    current_meaning = f"{current_meaning}\n[LLM深度分析] {llm_analysis['drift_analysis']}"
                if llm_analysis.get("predicted_direction"):
                    current_meaning = f"{current_meaning}\n[预测方向] {llm_analysis['predicted_direction']}"
                if llm_analysis.get("timeline_detail"):
                    for detail in llm_analysis["timeline_detail"]:
                        enriched = {
                            "date": detail.get("date", ""),
                            "meaning": detail.get("meaning_shift", ""),
                            "significance": detail.get("significance", 0.0),
                            "source": "llm_analysis",
                        }
                        timeline.append(enriched)
                    timeline.sort(key=lambda t: t.get("date", "") or "")
            except Exception as exc:
                logger.warning(f"LLM semantic drift analysis failed: {exc}")

        return SemanticDriftResult(
            term=term,
            original_meaning=dict_meaning or "未知",
            current_meaning=current_meaning,
            drift_timeline=timeline,
            drift_velocity=drift_velocity,
        )

    async def _find_historical_uses(self, term: str) -> List[Dict]:
        results = await self.vector_store.search_intelligence(term, n_results=20)
        uses = []
        for result in results:
            doc = result.get("document", "")
            metadata = result.get("metadata", {})
            if not doc:
                continue
            uses.append({
                "content": doc[:500],
                "timestamp": metadata.get("collected_at", metadata.get("timestamp", "")),
                "source": metadata.get("source", "unknown"),
                "id": result.get("id", ""),
            })
        uses.sort(key=lambda u: u.get("timestamp", "") or "")
        return uses

    async def track_cross_platform_migration(self, term: str) -> "MigrationResult":
        platform_uses = await self._find_platform_uses(term)

        if not platform_uses:
            return MigrationResult(
                term=term, origin_platform="unknown",
                migration_path=[], current_platforms=[], spread_speed=0.0,
            )

        earliest_platform = None
        earliest_time = None
        migration_path = []
        current_platforms = []

        for platform, uses in platform_uses.items():
            if uses:
                first_seen = uses[0].get("timestamp", "")
                count = len(uses)
                migration_path.append({
                    "platform": platform,
                    "first_seen": first_seen,
                    "count": count,
                })
                current_platforms.append(platform)
                if earliest_time is None or (first_seen and first_seen < earliest_time):
                    earliest_time = first_seen
                    earliest_platform = platform

        migration_path.sort(key=lambda p: p.get("first_seen", "") or "")

        num_platforms = len(platform_uses)
        total_uses = sum(len(uses) for uses in platform_uses.values())
        spread_speed = min(num_platforms / 5.0, 1.0) * min(total_uses / 10.0, 1.0)

        return MigrationResult(
            term=term,
            origin_platform=earliest_platform or "unknown",
            migration_path=migration_path,
            current_platforms=current_platforms,
            spread_speed=spread_speed,
        )

    async def analyze_term_propagation(self, term: str) -> Dict:
        return await self._propagation_analyzer.analyze_propagation(term)

    async def _find_platform_uses(self, term: str) -> Dict[str, List[Dict]]:
        results = await self.vector_store.search_intelligence(term, n_results=30)
        platform_uses: Dict[str, List[Dict]] = {}
        for result in results:
            metadata = result.get("metadata", {})
            source = metadata.get("source", "unknown")
            if source not in platform_uses:
                platform_uses[source] = []
            platform_uses[source].append({
                "content": result.get("document", "")[:300],
                "timestamp": metadata.get("collected_at", metadata.get("timestamp", "")),
                "id": result.get("id", ""),
            })
        for platform in platform_uses:
            platform_uses[platform].sort(key=lambda u: u.get("timestamp", "") or "")
        return platform_uses

    def _save_model(self):
        if self._model is None:
            return
        model_path = os.path.join(self._persist_dir, "skipgram.npz")
        self._model.save(model_path)
        meta = {
            "word2idx": self._word2idx,
            "trained": self._trained,
        }
        meta_path = os.path.join(self._persist_dir, "metadata.pkl")
        with open(meta_path, "wb") as f:
            pickle.dump(meta, f)
        if self._reference_dist is not None:
            ref_path = os.path.join(self._persist_dir, "reference_dist.npy")
            np.save(ref_path, self._reference_dist)
        logger.info(f"Zero-day model saved to {self._persist_dir}")

    def _try_load_model(self) -> bool:
        model_path = os.path.join(self._persist_dir, "skipgram.npz")
        meta_path = os.path.join(self._persist_dir, "metadata.pkl")
        ref_path = os.path.join(self._persist_dir, "reference_dist.npy")

        if not os.path.exists(model_path) or not os.path.exists(meta_path):
            return False

        try:
            self._model = SkipGramModel.load(model_path)
            with open(meta_path, "rb") as f:
                meta = pickle.load(f)
            self._word2idx = meta.get("word2idx", {})
            self._idx2word = {v: k for k, v in self._word2idx.items()}
            self._trained = meta.get("trained", False)
            if os.path.exists(ref_path):
                self._reference_dist = np.load(ref_path)
            self._extract_term_vectors()
            logger.info(f"Zero-day model loaded: vocab={len(self._word2idx)}")
            return True
        except Exception as exc:
            logger.warning(f"Failed to load zero-day model: {exc}")
            return False
