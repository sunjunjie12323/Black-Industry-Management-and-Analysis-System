import asyncio
import hashlib
import json
import os
import re
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional, Tuple

from loguru import logger


@dataclass
class TranslationResult:
    source_text: str
    translated_text: str
    source_lang: str
    target_lang: str
    method: str
    confidence: float
    from_cache: bool = False
    terminology_applied: List[str] = field(default_factory=list)
    latency_ms: float = 0.0
    quality_score: Optional[float] = None
    needs_review: bool = False

    def to_dict(self) -> Dict:
        return {
            "source_text": self.source_text[:200],
            "translated_text": self.translated_text[:200],
            "source_lang": self.source_lang,
            "target_lang": self.target_lang,
            "method": self.method,
            "confidence": round(self.confidence, 4),
            "from_cache": self.from_cache,
            "terminology_applied": self.terminology_applied,
            "latency_ms": round(self.latency_ms, 2),
            "quality_score": self.quality_score,
            "needs_review": self.needs_review,
        }


@dataclass
class TMMatch:
    source_text: str
    target_text: str
    similarity: float
    source_lang: str
    target_lang: str
    tm_id: str

    def to_dict(self) -> Dict:
        return {
            "source_text": self.source_text[:200],
            "target_text": self.target_text[:200],
            "similarity": round(self.similarity, 4),
            "source_lang": self.source_lang,
            "target_lang": self.target_lang,
            "tm_id": self.tm_id,
        }


@dataclass
class TermEntry:
    term: str
    translation: str
    priority: str = "suggest_translate"

    def to_dict(self) -> Dict:
        return {
            "term": self.term,
            "translation": self.translation,
            "priority": self.priority,
        }


class LLMTranslator:
    def __init__(self, llm_service=None):
        self._llm = llm_service
        self._translation_cache: Dict[str, TranslationResult] = {}
        self._max_cache_size = 5000

    async def translate(
        self,
        text: str,
        source_lang: str = "zh",
        target_lang: str = "en",
        domain: Optional[str] = None,
        terminology: Optional[Dict[str, str]] = None,
        terminology_with_priority: Optional[Dict[str, TermEntry]] = None,
        timeout: float = 30.0,
    ) -> TranslationResult:
        import time
        start = time.time()

        cache_key = hashlib.md5(f"{text}:{source_lang}:{target_lang}:{domain}".encode()).hexdigest()
        if cache_key in self._translation_cache:
            cached = self._translation_cache[cache_key]
            cached.from_cache = True
            cached.latency_ms = (time.time() - start) * 1000
            return cached

        if not self._llm:
            return TranslationResult(
                source_text=text,
                translated_text=text,
                source_lang=source_lang,
                target_lang=target_lang,
                method="no_llm",
                confidence=0.0,
                latency_ms=(time.time() - start) * 1000,
            )

        lang_names = {
            "zh": "中文", "en": "英语", "ja": "日语", "ko": "韩语",
            "ru": "俄语", "de": "德语", "fr": "法语", "es": "西班牙语", "ar": "阿拉伯语",
        }
        src_name = lang_names.get(source_lang, source_lang)
        tgt_name = lang_names.get(target_lang, target_lang)

        prompt = f"请将以下{src_name}文本翻译为{tgt_name}"
        if domain:
            prompt += f"，领域为{domain}"
        prompt += "。保持专业术语的准确性，直接输出翻译结果，不要添加解释。\n\n"

        if terminology_with_priority:
            must_keep = [(k, v) for k, v in terminology_with_priority.items() if v.priority == "must_keep"]
            must_translate = [(k, v) for k, v in terminology_with_priority.items() if v.priority == "must_translate"]
            suggest = [(k, v) for k, v in terminology_with_priority.items() if v.priority == "suggest_translate"]

            if must_keep:
                prompt += "【必须保留原文的术语】(翻译时请保留原文，不要翻译):\n"
                for src_term, entry in must_keep:
                    prompt += f"- {src_term}\n"
                prompt += "\n"

            if must_translate:
                prompt += "【必须翻译的术语】(翻译时必须使用指定译法):\n"
                for src_term, entry in must_translate:
                    prompt += f"- {src_term} → {entry.translation}\n"
                prompt += "\n"

            if suggest:
                prompt += "【建议翻译的术语】(建议使用指定译法，但可根据语境调整):\n"
                for src_term, entry in suggest:
                    prompt += f"- {src_term} → {entry.translation}\n"
                prompt += "\n"

        elif terminology:
            terms_str = "\n".join([f"- {k} → {v}" for k, v in terminology.items()])
            prompt += f"术语表:\n{terms_str}\n\n"

        prompt += f"原文:\n{text}"

        try:
            response = await asyncio.wait_for(self._llm.chat(prompt), timeout=timeout)

            if isinstance(response, dict):
                translated = response.get("content", "")
            elif isinstance(response, str):
                translated = response
            else:
                translated = str(response)

            applied_terms = []
            violations = []

            if terminology_with_priority:
                for src_term, entry in terminology_with_priority.items():
                    if entry.priority == "must_keep":
                        if src_term not in translated:
                            violations.append(f"must_keep_violation:{src_term}")
                        else:
                            applied_terms.append(f"{src_term}(保留)")
                    elif entry.priority == "must_translate":
                        if entry.translation in translated:
                            applied_terms.append(f"{src_term}→{entry.translation}")
                        else:
                            violations.append(f"must_translate_violation:{src_term}→{entry.translation}")
                    elif entry.priority == "suggest_translate":
                        if entry.translation in translated:
                            applied_terms.append(f"{src_term}→{entry.translation}")
            elif terminology:
                for src_term, tgt_term in terminology.items():
                    if tgt_term in translated:
                        applied_terms.append(f"{src_term}→{tgt_term}")

            confidence = 0.85 if applied_terms else 0.75
            needs_review = len(violations) > 0
            if violations:
                confidence *= 0.8
                logger.warning(f"术语验证违规: {violations}")

            result = TranslationResult(
                source_text=text,
                translated_text=translated.strip(),
                source_lang=source_lang,
                target_lang=target_lang,
                method="llm",
                confidence=confidence,
                terminology_applied=applied_terms,
                latency_ms=(time.time() - start) * 1000,
                needs_review=needs_review,
            )

            self._translation_cache[cache_key] = result
            if len(self._translation_cache) > self._max_cache_size:
                oldest_key = next(iter(self._translation_cache))
                del self._translation_cache[oldest_key]
            return result

        except asyncio.TimeoutError:
            logger.warning(f"LLM翻译超时: {source_lang}->{target_lang}")
            return TranslationResult(
                source_text=text,
                translated_text="",
                source_lang=source_lang,
                target_lang=target_lang,
                method="llm_timeout",
                confidence=0.0,
                latency_ms=(time.time() - start) * 1000,
            )
        except Exception as exc:
            logger.error(f"LLM翻译失败: {exc}")
            return TranslationResult(
                source_text=text,
                translated_text="",
                source_lang=source_lang,
                target_lang=target_lang,
                method="llm_error",
                confidence=0.0,
                latency_ms=(time.time() - start) * 1000,
            )

    async def batch_translate(
        self,
        texts: List[str],
        source_lang: str = "zh",
        target_lang: str = "en",
        domain: Optional[str] = None,
        terminology: Optional[Dict[str, str]] = None,
        terminology_with_priority: Optional[Dict[str, TermEntry]] = None,
        concurrency: int = 5,
    ) -> List[TranslationResult]:
        semaphore = asyncio.Semaphore(concurrency)

        async def _translate_one(text: str) -> TranslationResult:
            async with semaphore:
                return await self.translate(
                    text, source_lang, target_lang, domain,
                    terminology, terminology_with_priority
                )

        tasks = [_translate_one(text) for text in texts]
        return await asyncio.gather(*tasks)


class TranslationMemory:
    def __init__(self, similarity_threshold: float = 0.7, storage_path: Optional[str] = None):
        self._threshold = similarity_threshold
        self._storage_path = storage_path
        self._memories: Dict[str, List[Dict]] = defaultdict(list)
        self._max_memories_per_lang = 500

    def add_memory(
        self,
        source_text: str,
        target_text: str,
        source_lang: str,
        target_lang: str,
        domain: Optional[str] = None,
        tm_id: Optional[str] = None,
    ):
        key = f"{source_lang}:{target_lang}"
        entry = {
            "id": tm_id or uuid.uuid4().hex[:16],
            "source_text": source_text,
            "target_text": target_text,
            "source_lang": source_lang,
            "target_lang": target_lang,
            "domain": domain,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        self._memories[key].append(entry)
        if len(self._memories[key]) > self._max_memories_per_lang:
            self._memories[key] = self._memories[key][-self._max_memories_per_lang:]

    def load_memories(self, memories: List[Dict]):
        for mem in memories:
            key = f"{mem.get('source_lang', 'zh')}:{mem.get('target_lang', 'en')}"
            self._memories[key].append(mem)

    def find_match(
        self,
        source_text: str,
        source_lang: str = "zh",
        target_lang: str = "en",
    ) -> Optional[TMMatch]:
        key = f"{source_lang}:{target_lang}"
        candidates = self._memories.get(key, [])

        best_match = None
        best_similarity = 0.0

        for mem in candidates:
            similarity = self._compute_similarity(source_text, mem["source_text"])
            if similarity > best_similarity:
                best_similarity = similarity
                best_match = mem

        if best_match and best_similarity >= self._threshold:
            return TMMatch(
                source_text=best_match["source_text"],
                target_text=best_match["target_text"],
                similarity=best_similarity,
                source_lang=source_lang,
                target_lang=target_lang,
                tm_id=best_match.get("id", ""),
            )

        return None

    def find_matches(
        self,
        source_text: str,
        source_lang: str = "zh",
        target_lang: str = "en",
        top_k: int = 3,
    ) -> List[TMMatch]:
        key = f"{source_lang}:{target_lang}"
        candidates = self._memories.get(key, [])

        scored = []
        for mem in candidates:
            similarity = self._compute_similarity(source_text, mem["source_text"])
            if similarity >= self._threshold * 0.8:
                scored.append((similarity, mem))

        scored.sort(key=lambda x: x[0], reverse=True)

        return [
            TMMatch(
                source_text=mem["source_text"],
                target_text=mem["target_text"],
                similarity=sim,
                source_lang=source_lang,
                target_lang=target_lang,
                tm_id=mem.get("id", ""),
            )
            for sim, mem in scored[:top_k]
        ]

    def save_to_file(self, path: Optional[str] = None) -> bool:
        file_path = path or self._storage_path
        if not file_path:
            logger.warning("未指定翻译记忆存储路径")
            return False

        try:
            dir_path = os.path.dirname(file_path)
            if dir_path:
                os.makedirs(dir_path, exist_ok=True)
            data = {}
            for key, entries in self._memories.items():
                data[key] = entries
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            logger.info(f"翻译记忆已保存至 {file_path}, 共 {sum(len(v) for v in self._memories.values())} 条")
            return True
        except Exception as exc:
            logger.error(f"翻译记忆保存失败: {exc}")
            return False

    def load_from_file(self, path: Optional[str] = None) -> bool:
        file_path = path or self._storage_path
        if not file_path:
            logger.warning("未指定翻译记忆存储路径")
            return False

        try:
            if not os.path.exists(file_path):
                logger.warning(f"翻译记忆文件不存在: {file_path}")
                return False

            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            count = 0
            for key, entries in data.items():
                for entry in entries:
                    self._memories[key].append(entry)
                    count += 1

            logger.info(f"从 {file_path} 加载了 {count} 条翻译记忆")
            return True
        except Exception as exc:
            logger.error(f"翻译记忆加载失败: {exc}")
            return False

    def get_stats(self) -> Dict:
        total = sum(len(v) for v in self._memories.values())
        lang_pairs = list(self._memories.keys())
        return {
            "total_memories": total,
            "language_pairs": lang_pairs,
            "pair_counts": {k: len(v) for k, v in self._memories.items()},
        }

    @staticmethod
    def _compute_similarity(text_a: str, text_b: str) -> float:
        if not text_a or not text_b:
            return 0.0
        seq_ratio = SequenceMatcher(None, text_a.lower(), text_b.lower()).ratio()
        edit_sim = TranslationMemory._edit_distance_similarity(text_a, text_b)
        return seq_ratio * 0.6 + edit_sim * 0.4

    @staticmethod
    def _edit_distance_similarity(text_a: str, text_b: str) -> float:
        if not text_a or not text_b:
            return 0.0
        len_a, len_b = len(text_a), len(text_b)
        if len_a == 0 and len_b == 0:
            return 1.0

        dp = list(range(len_b + 1))
        for i in range(1, len_a + 1):
            prev = dp[0]
            dp[0] = i
            for j in range(1, len_b + 1):
                temp = dp[j]
                if text_a[i - 1] == text_b[j - 1]:
                    dp[j] = prev
                else:
                    dp[j] = 1 + min(prev, dp[j], dp[j - 1])
                prev = temp

        max_len = max(len_a, len_b)
        return 1.0 - dp[len_b] / max_len if max_len > 0 else 0.0


class TMMatcher:
    def __init__(self, similarity_threshold: float = 0.7):
        self._threshold = similarity_threshold
        self._memories: Dict[str, List[Dict]] = defaultdict(list)
        self._max_memories_per_lang = 500

    def add_memory(
        self,
        source_text: str,
        target_text: str,
        source_lang: str,
        target_lang: str,
        domain: Optional[str] = None,
        tm_id: Optional[str] = None,
    ):
        key = f"{source_lang}:{target_lang}"
        self._memories[key].append({
            "id": tm_id or uuid.uuid4().hex[:16],
            "source_text": source_text,
            "target_text": target_text,
            "source_lang": source_lang,
            "target_lang": target_lang,
            "domain": domain,
        })
        if len(self._memories[key]) > self._max_memories_per_lang:
            self._memories[key] = self._memories[key][-self._max_memories_per_lang:]

    def load_memories(self, memories: List[Dict]):
        for mem in memories:
            key = f"{mem.get('source_lang', 'zh')}:{mem.get('target_lang', 'en')}"
            self._memories[key].append(mem)

    def find_match(
        self,
        source_text: str,
        source_lang: str = "zh",
        target_lang: str = "en",
    ) -> Optional[TMMatch]:
        key = f"{source_lang}:{target_lang}"
        candidates = self._memories.get(key, [])

        best_match = None
        best_similarity = 0.0

        for mem in candidates:
            similarity = self._compute_similarity(source_text, mem["source_text"])
            if similarity > best_similarity:
                best_similarity = similarity
                best_match = mem

        if best_match and best_similarity >= self._threshold:
            return TMMatch(
                source_text=best_match["source_text"],
                target_text=best_match["target_text"],
                similarity=best_similarity,
                source_lang=source_lang,
                target_lang=target_lang,
                tm_id=best_match.get("id", ""),
            )

        return None

    def find_matches(
        self,
        source_text: str,
        source_lang: str = "zh",
        target_lang: str = "en",
        top_k: int = 3,
    ) -> List[TMMatch]:
        key = f"{source_lang}:{target_lang}"
        candidates = self._memories.get(key, [])

        scored = []
        for mem in candidates:
            similarity = self._compute_similarity(source_text, mem["source_text"])
            if similarity >= self._threshold * 0.8:
                scored.append((similarity, mem))

        scored.sort(key=lambda x: x[0], reverse=True)

        return [
            TMMatch(
                source_text=mem["source_text"],
                target_text=mem["target_text"],
                similarity=sim,
                source_lang=source_lang,
                target_lang=target_lang,
                tm_id=mem.get("id", ""),
            )
            for sim, mem in scored[:top_k]
        ]

    @staticmethod
    def _compute_similarity(text_a: str, text_b: str) -> float:
        if not text_a or not text_b:
            return 0.0
        return SequenceMatcher(None, text_a.lower(), text_b.lower()).ratio()


class TerminologyInjector:
    THREAT_INTEL_GLOSSARY_ZH_EN = {
        "跑分": "money laundering relay",
        "洗钱": "money laundering",
        "四件套": "four-piece identity kit",
        "猫池": "SMS pool device",
        "杀猪盘": "pig butchering scam",
        "接码": "verification code receiving service",
        "养号": "account farming",
        "料子": "stolen personal data",
        "黑料": "illicit data",
        "卡商": "bank card dealer",
        "料商": "data dealer",
        "水房": "money laundering operation",
        "车手": "cash withdrawal mule",
        "马仔": "low-level operative",
        "博彩": "online gambling",
        "菠菜": "online gambling (euphemism)",
        "色流": "adult traffic",
        "引流": "traffic diversion",
        "木马": "Trojan horse",
        "钓鱼": "phishing",
        "勒索": "ransomware",
        "肉鸡": "zombie host",
        "僵尸网络": "botnet",
        "暗网": "dark web",
        "挖矿": "cryptocurrency mining",
        "套现": "cash out",
        "黑卡": "black market card",
        "话术": "social engineering script",
        "资金盘": "Ponzi scheme",
        "套路贷": "predatory lending",
        "裸贷": "naked-photo loan",
        "拦截卡": "SMS intercept SIM card",
        "实名": "real-name authentication",
        "代付": "proxy payment",
        "提现": "cash withdrawal",
    }

    DEFAULT_PRIORITY_MAP = {
        "跑分": "must_translate",
        "杀猪盘": "must_translate",
        "四件套": "must_translate",
        "猫池": "must_translate",
        "肉鸡": "must_translate",
        "水房": "must_translate",
        "料子": "must_translate",
        "话术": "must_translate",
        "暗网": "must_translate",
        "钓鱼": "suggest_translate",
        "挖矿": "suggest_translate",
        "博彩": "suggest_translate",
        "菠菜": "suggest_translate",
        "引流": "suggest_translate",
    }

    def __init__(self):
        self._custom_terminology: Dict[str, Dict[str, str]] = defaultdict(dict)
        self._priority_map: Dict[str, Dict[str, str]] = defaultdict(dict)
        self._max_industries = 50

    def add_term(self, term: str, translation: str, source_lang: str = "zh", target_lang: str = "en"):
        key = f"{source_lang}:{target_lang}"
        self._custom_terminology[key][term] = translation
        if len(self._custom_terminology) > self._max_industries:
            oldest_key = next(iter(self._custom_terminology))
            del self._custom_terminology[oldest_key]
            self._priority_map.pop(oldest_key, None)

    def add_term_with_priority(
        self,
        term: str,
        translation: str,
        priority: str = "suggest_translate",
        source_lang: str = "zh",
        target_lang: str = "en",
    ):
        key = f"{source_lang}:{target_lang}"
        self._custom_terminology[key][term] = translation
        self._priority_map[key][term] = priority
        if len(self._custom_terminology) > self._max_industries:
            oldest_key = next(iter(self._custom_terminology))
            del self._custom_terminology[oldest_key]
            self._priority_map.pop(oldest_key, None)

    def load_terms(self, terms: List[Dict]):
        for t in terms:
            src_lang = t.get("source_lang", "zh")
            tgt_lang = t.get("target_lang", "en")
            key = f"{src_lang}:{tgt_lang}"
            self._custom_terminology[key][t["term"]] = t["translation"]
            if "priority" in t:
                self._priority_map[key][t["term"]] = t["priority"]
        if len(self._custom_terminology) > self._max_industries:
            oldest_key = next(iter(self._custom_terminology))
            del self._custom_terminology[oldest_key]
            self._priority_map.pop(oldest_key, None)

    def get_terminology(
        self, source_lang: str = "zh", target_lang: str = "en"
    ) -> Dict[str, str]:
        terms = {}
        if source_lang == "zh" and target_lang == "en":
            terms.update(self.THREAT_INTEL_GLOSSARY_ZH_EN)

        key = f"{source_lang}:{target_lang}"
        terms.update(self._custom_terminology.get(key, {}))
        return terms

    def get_terminology_with_priority(
        self, source_lang: str = "zh", target_lang: str = "en"
    ) -> Dict[str, TermEntry]:
        result = {}
        key = f"{source_lang}:{target_lang}"

        if source_lang == "zh" and target_lang == "en":
            for term, translation in self.THREAT_INTEL_GLOSSARY_ZH_EN.items():
                priority = self.DEFAULT_PRIORITY_MAP.get(term, "suggest_translate")
                if key in self._priority_map and term in self._priority_map[key]:
                    priority = self._priority_map[key][term]
                result[term] = TermEntry(term=term, translation=translation, priority=priority)

        for term, translation in self._custom_terminology.get(key, {}).items():
            priority = self._priority_map.get(key, {}).get(term, "suggest_translate")
            result[term] = TermEntry(term=term, translation=translation, priority=priority)

        return result

    def apply_terminology(
        self,
        text: str,
        source_lang: str = "zh",
        target_lang: str = "en",
        custom_terms: Optional[Dict[str, str]] = None,
    ) -> Tuple[str, List[str]]:
        terms = self.get_terminology(source_lang, target_lang)
        if custom_terms:
            terms.update(custom_terms)

        applied = []
        result = text

        sorted_terms = sorted(terms.items(), key=lambda x: len(x[0]), reverse=True)
        for src_term, tgt_term in sorted_terms:
            if src_term in result:
                result = result.replace(src_term, tgt_term)
                applied.append(f"{src_term}→{tgt_term}")

        return result, applied

    def verify_terminology(
        self,
        source_text: str,
        translated_text: str,
        source_lang: str = "zh",
        target_lang: str = "en",
    ) -> Dict:
        terms_with_priority = self.get_terminology_with_priority(source_lang, target_lang)
        violations = []
        verified = []

        for src_term, entry in terms_with_priority.items():
            if src_term not in source_text:
                continue

            if entry.priority == "must_keep":
                if src_term in translated_text:
                    verified.append({"term": src_term, "status": "kept", "priority": "must_keep"})
                else:
                    violations.append({
                        "term": src_term,
                        "expected": f"保留原文'{src_term}'",
                        "priority": "must_keep",
                    })
            elif entry.priority == "must_translate":
                if entry.translation in translated_text:
                    verified.append({
                        "term": src_term,
                        "translation": entry.translation,
                        "status": "translated",
                        "priority": "must_translate",
                    })
                else:
                    violations.append({
                        "term": src_term,
                        "expected": entry.translation,
                        "priority": "must_translate",
                    })
            elif entry.priority == "suggest_translate":
                if entry.translation in translated_text:
                    verified.append({
                        "term": src_term,
                        "translation": entry.translation,
                        "status": "translated",
                        "priority": "suggest_translate",
                    })
                else:
                    verified.append({
                        "term": src_term,
                        "status": "not_translated",
                        "priority": "suggest_translate",
                    })

        return {
            "verified": verified,
            "violations": violations,
            "violation_count": len(violations),
            "pass": len(violations) == 0,
        }


class TranslationQualityAssessor:
    def __init__(self, llm_service=None, review_threshold: float = 0.5):
        self._llm = llm_service
        self._review_threshold = review_threshold

    async def assess(
        self,
        source: str,
        translation: str,
        source_lang: str,
        target_lang: str,
        terminology: Optional[Dict[str, str]] = None,
    ) -> Dict:
        default_result = {
            "overall_score": 0.0,
            "accuracy": 0.0,
            "fluency": 0.0,
            "terminology_consistency": 0.0,
            "suggestions": [],
            "needs_review": True,
        }

        if not source or not translation:
            return default_result

        term_score = self._compute_terminology_score(translation, terminology)
        heuristic_scores = self._compute_heuristic_scores(source, translation)

        if self._llm:
            llm_scores = await self._assess_with_llm(
                source, translation, source_lang, target_lang
            )
            if llm_scores:
                overall = round(
                    llm_scores["accuracy"] * 0.4
                    + llm_scores["fluency"] * 0.3
                    + term_score * 0.3,
                    4,
                )
                needs_review = overall < self._review_threshold
                return {
                    "overall_score": overall,
                    "accuracy": round(llm_scores["accuracy"], 4),
                    "fluency": round(llm_scores["fluency"], 4),
                    "terminology_consistency": round(term_score, 4),
                    "suggestions": llm_scores.get("suggestions", []),
                    "needs_review": needs_review,
                }

        overall = round(
            heuristic_scores["accuracy"] * 0.4
            + heuristic_scores["fluency"] * 0.3
            + term_score * 0.3,
            4,
        )
        needs_review = overall < self._review_threshold

        suggestions = self._generate_suggestions(
            heuristic_scores, term_score, source, translation
        )

        return {
            "overall_score": overall,
            "accuracy": round(heuristic_scores["accuracy"], 4),
            "fluency": round(heuristic_scores["fluency"], 4),
            "terminology_consistency": round(term_score, 4),
            "suggestions": suggestions,
            "needs_review": needs_review,
        }

    async def batch_assess(
        self,
        pairs: List[Dict],
        source_lang: str,
        target_lang: str,
        terminology: Optional[Dict[str, str]] = None,
        concurrency: int = 3,
    ) -> List[Dict]:
        semaphore = asyncio.Semaphore(concurrency)

        async def _assess_one(pair: Dict) -> Dict:
            async with semaphore:
                return await self.assess(
                    pair.get("source", ""),
                    pair.get("translation", ""),
                    source_lang,
                    target_lang,
                    terminology,
                )

        tasks = [_assess_one(pair) for pair in pairs]
        return list(await asyncio.gather(*tasks))

    async def _assess_with_llm(
        self,
        source: str,
        translation: str,
        source_lang: str,
        target_lang: str,
    ) -> Optional[Dict]:
        lang_names = {
            "zh": "中文", "en": "英语", "ja": "日语", "ko": "韩语",
            "ru": "俄语", "de": "德语", "fr": "法语", "es": "西班牙语", "ar": "阿拉伯语",
        }
        src_name = lang_names.get(source_lang, source_lang)
        tgt_name = lang_names.get(target_lang, target_lang)

        eval_prompt = (
            f"请评估以下{src_name}到{tgt_name}翻译的质量。\n\n"
            f"原文: {source}\n"
            f"译文: {translation}\n\n"
            f"请按以下维度打分(0-10分)，并以JSON格式输出:\n"
            f'{{"accuracy": <0-10>, "fluency": <0-10>, "suggestions": ["<建议1>", "<建议2>"]}}\n'
            f"accuracy: 译文是否准确传达了原文的含义\n"
            f"fluency: 译文是否流畅自然、符合目标语言表达习惯\n"
            f"suggestions: 改进建议列表(如有)\n"
            f"仅输出JSON，不要添加其他内容。"
        )

        try:
            response = await asyncio.wait_for(self._llm.chat(eval_prompt), timeout=15.0)
            content = response if isinstance(response, str) else (
                response.get("content", "") if isinstance(response, dict) else str(response)
            )

            json_match = re.search(r'\{[^}]+\}', content, re.DOTALL)
            if json_match:
                eval_data = json.loads(json_match.group())
                accuracy = min(max(eval_data.get("accuracy", 5) / 10.0, 0.0), 1.0)
                fluency = min(max(eval_data.get("fluency", 5) / 10.0, 0.0), 1.0)
                suggestions = eval_data.get("suggestions", [])
                return {
                    "accuracy": accuracy,
                    "fluency": fluency,
                    "suggestions": suggestions,
                }
        except (asyncio.TimeoutError, json.JSONDecodeError, Exception) as exc:
            logger.warning(f"LLM质量评估失败: {exc}")

        return None

    @staticmethod
    def _compute_terminology_score(translation: str, terminology: Optional[Dict[str, str]]) -> float:
        if not terminology:
            return 0.5
        term_total = len(terminology)
        term_covered = 0
        for tgt_term in terminology.values():
            if tgt_term in translation:
                term_covered += 1
        return round(term_covered / term_total, 4) if term_total > 0 else 0.5

    @staticmethod
    def _compute_heuristic_scores(source: str, translation: str) -> Dict[str, float]:
        src_len = len(source)
        tgt_len = len(translation)
        length_ratio = min(src_len, tgt_len) / max(src_len, tgt_len) if max(src_len, tgt_len) > 0 else 0.0

        accuracy = length_ratio if length_ratio > 0.3 else length_ratio * 0.5
        fluency = min(length_ratio * 1.2, 1.0) if length_ratio > 0.4 else length_ratio * 0.6

        return {"accuracy": accuracy, "fluency": fluency}

    @staticmethod
    def _generate_suggestions(
        heuristic_scores: Dict[str, float],
        term_score: float,
        source: str,
        translation: str,
    ) -> List[str]:
        suggestions = []
        if term_score < 0.5:
            suggestions.append("部分术语未按术语表翻译，建议检查术语一致性")
        src_len = len(source)
        tgt_len = len(translation)
        length_ratio = min(src_len, tgt_len) / max(src_len, tgt_len) if max(src_len, tgt_len) > 0 else 0.0
        if length_ratio < 0.3:
            suggestions.append("译文长度与原文差异较大，可能存在漏译或过度翻译")
        if heuristic_scores["fluency"] < 0.5:
            suggestions.append("译文流畅度较低，建议人工审校")
        return suggestions


class TranslationEngine:
    def __init__(self, llm_service=None, tm_storage_path: Optional[str] = None):
        self._llm_translator = LLMTranslator(llm_service)
        self._tm_matcher = TMMatcher()
        self._translation_memory = TranslationMemory(storage_path=tm_storage_path)
        self._term_injector = TerminologyInjector()
        self._quality_assessor = TranslationQualityAssessor(llm_service)
        self._industry_terms: Dict[str, str] = {}

    def set_industry_terms(self, terms: Dict[str, str]):
        self._industry_terms = terms
        for source_term, target_translation in terms.items():
            self._term_injector.add_term(
                term=source_term,
                translation=target_translation,
                source_lang="zh",
                target_lang="en",
            )
        return True

    async def translate(
        self,
        text: str,
        source_lang: str = "zh",
        target_lang: str = "en",
        domain: Optional[str] = None,
        use_tm: bool = True,
        use_llm: bool = True,
    ) -> TranslationResult:
        import time
        start = time.time()

        if use_tm:
            tm_match = self._tm_matcher.find_match(text, source_lang, target_lang)
            if tm_match and tm_match.similarity >= 0.95:
                return TranslationResult(
                    source_text=text,
                    translated_text=tm_match.target_text,
                    source_lang=source_lang,
                    target_lang=target_lang,
                    method="tm_exact",
                    confidence=0.95,
                    from_cache=True,
                    latency_ms=(time.time() - start) * 1000,
                )

            tm_match_adv = self._translation_memory.find_match(text, source_lang, target_lang)
            if tm_match_adv and tm_match_adv.similarity >= 0.95:
                return TranslationResult(
                    source_text=text,
                    translated_text=tm_match_adv.target_text,
                    source_lang=source_lang,
                    target_lang=target_lang,
                    method="tm_exact",
                    confidence=0.95,
                    from_cache=True,
                    latency_ms=(time.time() - start) * 1000,
                )

        terminology = self._term_injector.get_terminology(source_lang, target_lang)
        terminology_with_priority = self._term_injector.get_terminology_with_priority(source_lang, target_lang)

        if use_llm:
            result = await self._llm_translator.translate(
                text, source_lang, target_lang, domain, terminology, terminology_with_priority
            )

            if result.confidence > 0.5:
                self._tm_matcher.add_memory(
                    text, result.translated_text, source_lang, target_lang, domain
                )
                self._translation_memory.add_memory(
                    text, result.translated_text, source_lang, target_lang, domain
                )

            verification = self._term_injector.verify_terminology(
                text, result.translated_text, source_lang, target_lang
            )
            if not verification["pass"]:
                result.needs_review = True
                result.confidence *= 0.9

            return result

        pre_translated, applied = self._term_injector.apply_terminology(
            text, source_lang, target_lang
        )

        return TranslationResult(
            source_text=text,
            translated_text=pre_translated,
            source_lang=source_lang,
            target_lang=target_lang,
            method="terminology_only",
            confidence=0.3 if applied else 0.0,
            terminology_applied=applied,
            latency_ms=(time.time() - start) * 1000,
        )

    async def batch_translate(
        self,
        texts: List[str],
        source_lang: str = "zh",
        target_lang: str = "en",
        domain: Optional[str] = None,
        concurrency: int = 5,
    ) -> List[Dict]:
        semaphore = asyncio.Semaphore(concurrency)

        async def _translate_one(text: str) -> Dict:
            async with semaphore:
                tm_match = self._tm_matcher.find_match(text, source_lang, target_lang)
                if tm_match and tm_match.similarity >= 0.95:
                    return {
                        "translated_text": tm_match.target_text,
                        "source_lang": source_lang,
                        "target_lang": target_lang,
                        "terminology_applied": [],
                        "model": "tm_exact",
                        "tm_match": tm_match.to_dict(),
                    }
                result = await self.translate_with_llm(text, source_lang, target_lang, domain)
                return result

        tasks = [_translate_one(text) for text in texts]
        return list(await asyncio.gather(*tasks))

    async def translate_with_llm(
        self,
        text: str,
        source_lang: str = "zh",
        target_lang: str = "en",
        domain: Optional[str] = None,
    ) -> Dict:
        import time
        start = time.time()

        terminology = self._term_injector.get_terminology(source_lang, target_lang)
        terminology_with_priority = self._term_injector.get_terminology_with_priority(source_lang, target_lang)

        lang_names = {
            "zh": "中文", "en": "英语", "ja": "日语", "ko": "韩语",
            "ru": "俄语", "de": "德语", "fr": "法语", "es": "西班牙语", "ar": "阿拉伯语",
        }
        src_name = lang_names.get(source_lang, source_lang)
        tgt_name = lang_names.get(target_lang, target_lang)

        system_prompt = f"你是一个专业的{src_name}到{tgt_name}翻译引擎。"
        if domain:
            system_prompt += f"你的专长领域是{domain}。"
        system_prompt += "请严格遵循术语表进行翻译，保持术语的一致性和准确性。直接输出翻译结果，不要添加解释。"

        if terminology:
            terms_str = "\n".join([f"- {k} → {v}" for k, v in terminology.items()])
            system_prompt += f"\n\n术语表:\n{terms_str}"

        try:
            result = await self._llm_translator.translate(
                text, source_lang, target_lang, domain, terminology, terminology_with_priority
            )

            translated_text = result.translated_text
            if translated_text:
                translated_text, term_applied = self._term_injector.apply_terminology(
                    translated_text, source_lang, target_lang
                )
            else:
                term_applied = result.terminology_applied

            model = "llm"
            if result.from_cache:
                model = "llm_cache"
            elif result.method == "llm_timeout":
                model = "llm_timeout"
            elif result.method == "llm_error":
                model = "llm_error"
            elif result.method == "no_llm":
                model = "none"

            logger.debug(
                f"translate_with_llm: {source_lang}->{target_lang}, "
                f"latency={round((time.time() - start) * 1000, 2)}ms, "
                f"terms={len(term_applied)}, model={model}"
            )

            return {
                "translated_text": translated_text,
                "source_lang": source_lang,
                "target_lang": target_lang,
                "terminology_applied": term_applied,
                "model": model,
            }
        except Exception as exc:
            logger.error(f"translate_with_llm失败: {exc}")
            return {
                "translated_text": "",
                "source_lang": source_lang,
                "target_lang": target_lang,
                "terminology_applied": [],
                "model": "error",
            }

    async def detect_language(self, text: str) -> Dict:
        if not text or not text.strip():
            return {
                "detected_lang": "unknown",
                "confidence": 0.0,
                "alternatives": [],
            }

        scores: Dict[str, float] = defaultdict(float)
        total_chars = 0

        for ch in text:
            if not ch.strip():
                continue
            total_chars += 1
            cp = ord(ch)

            if 0x4E00 <= cp <= 0x9FFF or 0x3400 <= cp <= 0x4DBF or 0x20000 <= cp <= 0x2A6DF:
                scores["zh"] += 1.0
            elif 0x3040 <= cp <= 0x309F or 0x30A0 <= cp <= 0x30FF:
                scores["ja"] += 1.0
            elif 0xAC00 <= cp <= 0xD7AF or 0x1100 <= cp <= 0x11FF or 0x3130 <= cp <= 0x318F:
                scores["ko"] += 1.0
            elif 0x0400 <= cp <= 0x04FF or 0x0500 <= cp <= 0x052F:
                scores["ru"] += 1.0
            elif 0x0600 <= cp <= 0x06FF or 0x0750 <= cp <= 0x077F or 0xFB50 <= cp <= 0xFDFF or 0xFE70 <= cp <= 0xFEFF:
                scores["ar"] += 1.0
            elif 0x0041 <= cp <= 0x007A:
                scores["en"] += 0.3
            elif 0x00C0 <= cp <= 0x024F:
                scores["en"] += 0.1

        if "zh" in scores and "ja" not in scores:
            for ch in text:
                if 0x4E00 <= ord(ch) <= 0x9FFF:
                    scores["zh"] += 0.5
                    break

        if total_chars == 0:
            return {
                "detected_lang": "unknown",
                "confidence": 0.0,
                "alternatives": [],
            }

        sorted_langs = sorted(scores.items(), key=lambda x: x[1], reverse=True)

        if not sorted_langs:
            return {
                "detected_lang": "unknown",
                "confidence": 0.0,
                "alternatives": [],
            }

        detected_lang = sorted_langs[0][0]
        top_score = sorted_langs[0][1]
        confidence = min(round(top_score / total_chars, 4), 1.0)

        alternatives = [
            {"lang": lang, "score": round(score / total_chars, 4)}
            for lang, score in sorted_langs[1:4]
            if score / total_chars > 0.05
        ]

        return {
            "detected_lang": detected_lang,
            "confidence": confidence,
            "alternatives": alternatives,
        }

    async def get_translation_quality_score(
        self,
        source: str,
        translation: str,
        source_lang: str,
        target_lang: str,
    ) -> Dict:
        default_result = {
            "overall_score": 0.0,
            "accuracy": 0.0,
            "fluency": 0.0,
            "terminology_score": 0.0,
            "suggestions": [],
        }

        if not source or not translation:
            return default_result

        terminology = self._term_injector.get_terminology(source_lang, target_lang)
        assessment = await self._quality_assessor.assess(
            source, translation, source_lang, target_lang, terminology
        )

        return {
            "overall_score": assessment["overall_score"],
            "accuracy": assessment["accuracy"],
            "fluency": assessment["fluency"],
            "terminology_score": assessment["terminology_consistency"],
            "suggestions": assessment["suggestions"],
        }

    def add_terminology(self, term: str, translation: str, source_lang: str = "zh", target_lang: str = "en"):
        self._term_injector.add_term(term, translation, source_lang, target_lang)

    def add_terminology_with_priority(
        self,
        term: str,
        translation: str,
        priority: str = "suggest_translate",
        source_lang: str = "zh",
        target_lang: str = "en",
    ):
        self._term_injector.add_term_with_priority(term, translation, priority, source_lang, target_lang)

    def load_translation_memories(self, memories: List[Dict]):
        self._tm_matcher.load_memories(memories)
        self._translation_memory.load_memories(memories)

    def load_terminology_list(self, terms: List[Dict]):
        self._term_injector.load_terms(terms)

    def get_quality_score(self, source: str, translation: str) -> float:
        if not source or not translation:
            return 0.0

        terminology = self._term_injector.get_terminology()
        term_total = len(terminology)
        term_covered = 0
        if term_total > 0:
            for tgt_term in terminology.values():
                if tgt_term in translation:
                    term_covered += 1
        term_score = term_covered / term_total if term_total > 0 else 0.5

        src_len = len(source)
        tgt_len = len(translation)
        length_ratio = min(src_len, tgt_len) / max(src_len, tgt_len) if max(src_len, tgt_len) > 0 else 0.0
        length_score = length_ratio if length_ratio > 0.3 else length_ratio * 0.5

        struct_score = SequenceMatcher(None, source.split(), translation.split()).ratio() * 0.5

        score = term_score * 0.4 + length_score * 0.3 + struct_score * 0.3
        return round(min(max(score, 0.0), 1.0), 4)

    def find_tm_matches(
        self, text: str, source_lang: str = "zh", target_lang: str = "en", top_k: int = 3
    ) -> List[Dict]:
        matches = self._tm_matcher.find_matches(text, source_lang, target_lang, top_k)
        return [m.to_dict() for m in matches]

    def save_translation_memory(self, path: Optional[str] = None) -> bool:
        return self._translation_memory.save_to_file(path)

    def load_translation_memory_from_file(self, path: Optional[str] = None) -> bool:
        return self._translation_memory.load_from_file(path)

    def verify_terminology(
        self,
        source_text: str,
        translated_text: str,
        source_lang: str = "zh",
        target_lang: str = "en",
    ) -> Dict:
        return self._term_injector.verify_terminology(
            source_text, translated_text, source_lang, target_lang
        )

    async def assess_translation_quality(
        self,
        source: str,
        translation: str,
        source_lang: str,
        target_lang: str,
    ) -> Dict:
        terminology = self._term_injector.get_terminology(source_lang, target_lang)
        return await self._quality_assessor.assess(
            source, translation, source_lang, target_lang, terminology
        )
