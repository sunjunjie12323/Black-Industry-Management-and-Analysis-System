from datetime import datetime
from typing import Dict, List, Optional
from uuid import uuid4

from loguru import logger

from app.config import settings
from app.agents.base import BaseAgent
from app.core.blacktalk_engine import BlackTalkEngine
from app.core.llm import LLMService
from app.core.rule_based_extractor import rule_extractor
from app.core.vector_store import VectorStore
from app.models.intelligence import (
    CleanedIntelligence,
    ThreatLevel,
)


def _sanitize_input(text: str, max_length: int = 10000) -> str:
    if not text:
        return ""
    sanitized = text[:max_length]
    sanitized = sanitized.replace("```", " ")
    sanitized = sanitized.replace("<|im_end|>", " ")
    sanitized = sanitized.replace("<|im_start|>", " ")
    return sanitized.strip()


class CleanerAgent(BaseAgent):
    def __init__(
        self,
        llm: LLMService,
        vector_store: VectorStore,
        blacktalk_engine: BlackTalkEngine,
    ):
        super().__init__("cleaner", llm, vector_store)
        self.blacktalk_engine = blacktalk_engine

    async def execute(self, task: Dict) -> Dict:
        task_type = task.get("type", "clean")
        try:
            if task_type == "clean":
                raw_intel = task.get("raw_intelligence")
                if not raw_intel:
                    return self._create_task_result(
                        status="failed",
                        data={},
                        errors=["raw_intelligence is required for clean task"],
                    )
                decode_blacktalk = task.get("decode_blacktalk", True)
                extract_entities = task.get("extract_entities", True)
                cleaned = await self.clean(
                    raw_intel,
                    decode_blacktalk=decode_blacktalk,
                    extract_entities=extract_entities,
                )
                result = self._create_task_result(
                    status="success",
                    data={"cleaned_intelligence": cleaned},
                )

            elif task_type == "batch_clean":
                raw_intels = task.get("raw_intelligence", [])
                if not raw_intels:
                    return self._create_task_result(
                        status="failed",
                        data={},
                        errors=["raw_intelligence list is required for batch_clean"],
                    )
                decode_blacktalk = task.get("decode_blacktalk", True)
                extract_entities = task.get("extract_entities", True)
                cleaned_list = await self.batch_clean(
                    raw_intels,
                    decode_blacktalk=decode_blacktalk,
                    extract_entities=extract_entities,
                )
                result = self._create_task_result(
                    status="success",
                    data={
                        "total_input": len(raw_intels),
                        "total_cleaned": len(cleaned_list),
                        "cleaned_intelligences": cleaned_list,
                    },
                )

            else:
                result = self._create_task_result(
                    status="failed",
                    data={},
                    errors=[f"Unknown task type: {task_type}"],
                )

        except Exception as exc:
            self.logger.error(f"Cleaner task failed: {exc}")
            result = self._create_task_result(
                status="failed",
                data={},
                errors=[str(exc)],
            )

        await self._log_execution(task, result)
        return result

    async def clean(
        self,
        raw_intel: Dict,
        decode_blacktalk: bool = True,
        extract_entities: bool = True,
    ) -> Dict:
        content = raw_intel.get("content", "")
        raw_id = raw_intel.get("id", uuid4().hex)

        if not content:
            cleaned = CleanedIntelligence(
                raw_id=raw_id,
                content="",
                threat_level=ThreatLevel.INFO,
            )
            return cleaned.model_dump()

        cleaned_content = await self.remove_noise(content)

        decoded_content = cleaned_content
        blacktalk_terms: Dict[str, str] = {}
        if decode_blacktalk:
            decoded_content, blacktalk_terms = await self.blacktalk_engine.decode(
                cleaned_content
            )
            if blacktalk_terms:
                try:
                    await self.blacktalk_engine.auto_learn(
                        text=content,
                        decoded_terms=blacktalk_terms,
                    )
                except Exception as exc:
                    self.logger.warning(
                        f"Auto-learn blacktalk failed: {exc}"
                    )

        entities: List[str] = []
        entity_details: List[Dict] = []
        if extract_entities:
            entity_details = await self.extract_entities(decoded_content)
            entities = [e["value"] for e in entity_details]

        threat_level = await self.assess_threat_level(
            decoded_content, blacktalk_terms
        )

        cleaned = CleanedIntelligence(
            raw_id=raw_id,
            content=cleaned_content,
            decoded_content=decoded_content if blacktalk_terms else None,
            blacktalk_terms=blacktalk_terms,
            entities=entities,
            threat_level=threat_level,
        )

        try:
            await self.vector_store.add_intelligence(
                intel_id=cleaned.id,
                content=decoded_content,
                metadata={
                    "raw_id": raw_id,
                    "status": "cleaned",
                    "threat_level": threat_level,
                    "blacktalk_count": len(blacktalk_terms),
                    "entity_count": len(entities),
                    "cleaned_at": cleaned.cleaned_at.isoformat(),
                },
            )
        except Exception as exc:
            self.logger.warning(
                f"Failed to store cleaned intelligence: {exc}"
            )

        result = cleaned.model_dump()
        result["entity_details"] = entity_details
        return result

    async def batch_clean(
        self,
        raw_intels: List[Dict],
        decode_blacktalk: bool = True,
        extract_entities: bool = True,
    ) -> List[Dict]:
        seen_contents: set = set()
        unique_intels: List[Dict] = []

        for intel in raw_intels:
            content = intel.get("content", "")
            if not content:
                continue
            content_key = content.strip().lower()[:200]
            if content_key in seen_contents:
                continue
            seen_contents.add(content_key)
            unique_intels.append(intel)

        semantic_deduped = await self._semantic_dedup(unique_intels)
        if len(semantic_deduped) < len(unique_intels):
            self.logger.info(
                f"Semantic dedup: {len(unique_intels)} -> {len(semantic_deduped)} items"
            )
            unique_intels = semantic_deduped

        self.logger.info(
            f"Batch dedup: {len(raw_intels)} -> {len(unique_intels)} items"
        )

        cleaned_list: List[Dict] = []
        for intel in unique_intels:
            try:
                cleaned = await self.clean(
                    raw_intel=intel,
                    decode_blacktalk=decode_blacktalk,
                    extract_entities=extract_entities,
                )
                cleaned_list.append(cleaned)
            except Exception as exc:
                self.logger.error(
                    f"Failed to clean item {intel.get('id', 'unknown')}: {exc}"
                )
                continue

        self.logger.info(
            f"Batch clean completed: {len(cleaned_list)}/{len(unique_intels)} items cleaned"
        )
        return cleaned_list

    async def _semantic_dedup(
        self, intels: List[Dict], threshold: float = 0.92
    ) -> List[Dict]:
        if len(intels) <= 1:
            return intels

        try:
            temp_collection_name = f"_dedup_{uuid4().hex[:12]}"
            contents = [intel.get("content", "") for intel in intels]
            temp_ids = [f"dedup_{i}" for i in range(len(intels))]

            for i, content in enumerate(contents):
                if not content:
                    continue
                await self.vector_store.add_intelligence(
                    intel_id=temp_ids[i],
                    content=content,
                    metadata={"temp_dedup": True, "original_index": i},
                )

            keep_indices = []
            seen_as_dup = set()
            for i, content in enumerate(contents):
                if not content or i in seen_as_dup:
                    continue
                results = await self.vector_store.search_intelligence(content, n_results=2)
                is_dup = False
                for r in results:
                    rid = r.get("id", "")
                    dist = r.get("distance", 1.0)
                    if rid.startswith("dedup_"):
                        j = int(rid.split("_")[1])
                        if j != i and j in keep_indices and dist < (1.0 - threshold):
                            is_dup = True
                            seen_as_dup.add(i)
                            break
                if not is_dup:
                    keep_indices.append(i)

            try:
                await self.vector_store.delete("intelligence", temp_ids)
            except Exception:
                pass

            return [intels[i] for i in keep_indices]
        except Exception as exc:
            self.logger.warning(f"Vector dedup failed, falling back to simhash: {exc}")
            return self._simhash_dedup(intels)

    @staticmethod
    def _cosine_similarity(a, b) -> float:
        if a is None or b is None:
            return 0.0
        try:
            import numpy as np
            a_arr = np.array(a)
            b_arr = np.array(b)
            norm_a = np.linalg.norm(a_arr)
            norm_b = np.linalg.norm(b_arr)
            if norm_a == 0 or norm_b == 0:
                return 0.0
            return float(np.dot(a_arr, b_arr) / (norm_a * norm_b))
        except Exception:
            return 0.0

    @staticmethod
    def _simhash(text: str, hash_bits: int = 64) -> int:
        v = [0] * hash_bits
        tokens = text.lower().split()
        if not tokens:
            return 0
        for token in tokens:
            h = hash(token) & ((1 << hash_bits) - 1)
            for i in range(hash_bits):
                if h & (1 << i):
                    v[i] += 1
                else:
                    v[i] -= 1
        fingerprint = 0
        for i in range(hash_bits):
            if v[i] >= 0:
                fingerprint |= (1 << i)
        return fingerprint

    @staticmethod
    def _hamming_distance(a: int, b: int) -> int:
        x = a ^ b
        count = 0
        while x:
            count += 1
            x &= x - 1
        return count

    def _simhash_dedup(self, intels: List[Dict], max_hamming: int = 3) -> List[Dict]:
        if not intels:
            return intels
        fingerprints = []
        for intel in intels:
            content = intel.get("content", "")
            fingerprints.append(self._simhash(content))
        keep_indices = []
        seen_as_dup = set()
        for i in range(len(intels)):
            if i in seen_as_dup:
                continue
            is_dup = False
            for j in keep_indices:
                if self._hamming_distance(fingerprints[i], fingerprints[j]) < max_hamming:
                    is_dup = True
                    seen_as_dup.add(i)
                    break
            if not is_dup:
                keep_indices.append(i)
        return [intels[i] for i in keep_indices]

    async def remove_noise(self, content: str) -> str:
        if not content or len(content.strip()) < 10:
            return content

        system_prompt = (
            "你是一个黑灰产情报清洗专家。请对以下原始情报内容进行去噪处理，"
            "去除以下内容：\n"
            "1. 广告信息（如推广链接、微信号推广等与核心情报无关的内容）\n"
            "2. 多余的表情符号和格式化残留\n"
            "3. 与核心主题无关的闲聊内容\n"
            "4. 重复啰嗦的表述\n\n"
            "要求：\n"
            "- 保留所有与黑灰产相关的核心信息\n"
            "- 保留黑话/暗语原样，不要翻译或替换\n"
            "- 保留IP、域名、URL、手机号等关键实体\n"
            "- 保持原文语义不变\n"
            "- 只返回清洗后的文本，不要添加任何解释"
        )
        prompt = f"请清洗以下原始情报内容：\n\n{content}"

        try:
            cleaned = await self.llm.generate(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=settings.LLM_TEMPERATURE_ANALYSIS,
                max_tokens=settings.LLM_MAX_TOKENS_LONG,
            )
            cleaned = cleaned.strip()
            if len(cleaned) < len(content) * 0.3:
                self.logger.warning(
                    "Cleaned content too short, using rule-based fallback"
                )
                return rule_extractor.remove_noise_rule_based(content)
            return cleaned
        except Exception as exc:
            self.logger.warning(f"LLM noise removal failed, using rule-based fallback: {exc}")
            return rule_extractor.remove_noise_rule_based(content)

    async def extract_entities(self, content: str) -> List[Dict]:
        if not content:
            return []

        rule_entities = rule_extractor.extract_entities(content)
        rule_values = {e["value"] for e in rule_entities}

        system_prompt = (
            "你是一个黑灰产情报实体提取专家。从以下文本中提取所有有价值的实体信息。\n\n"
            "需要提取的实体类型：\n"
            "- ip: IP地址\n"
            "- domain: 域名\n"
            "- url: URL链接\n"
            "- phone: 手机号码\n"
            "- email: 邮箱地址\n"
            "- crypto_wallet: 加密货币钱包地址\n"
            "- account: 账号名称（QQ号、微信号、Telegram用户名等）\n"
            "- tool: 工具名称（木马、软件、平台名称等）\n"
            "- organization: 组织/团伙名称\n"
            "- person: 人名或代号\n"
            "- payment_method: 支付方式（银行卡号、支付宝、微信支付等）\n\n"
            "返回JSON数组，每个元素包含：\n"
            "- type: 实体类型（上述之一）\n"
            "- value: 实体值\n"
            "- context: 实体出现的上下文（原文中包含该实体的短句）\n\n"
            "只返回JSON数组，不要其他内容。如果没有实体，返回空数组[]。"
        )
        prompt = f"请从以下文本中提取实体：\n\n{_sanitize_input(content)}"

        llm_entities: List[Dict] = []
        try:
            result = await self.llm.generate_json(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=settings.LLM_TEMPERATURE_ANALYSIS,
            )
            if isinstance(result, list):
                for item in result:
                    if isinstance(item, dict) and "type" in item and "value" in item:
                        llm_entities.append({
                            "type": item["type"],
                            "value": item["value"],
                            "context": item.get("context", ""),
                        })
            if isinstance(result, dict):
                if "entities" in result and isinstance(result["entities"], list):
                    llm_entities = [
                        {
                            "type": e.get("type", "unknown"),
                            "value": e.get("value", ""),
                            "context": e.get("context", ""),
                        }
                        for e in result["entities"]
                        if isinstance(e, dict) and e.get("value")
                    ]
        except Exception as exc:
            self.logger.warning(f"LLM entity extraction failed, using rule-based only: {exc}")

        merged = list(rule_entities)
        seen_values = rule_values.copy()
        for entity in llm_entities:
            val = entity.get("value", "")
            if val and val not in seen_values:
                seen_values.add(val)
                merged.append(entity)

        return merged

    async def assess_threat_level(
        self, content: str, decoded_terms: Dict[str, str]
    ) -> str:
        blacktalk_density = 0.0
        if content and decoded_terms:
            total_terms = sum(
                content.count(term) for term in decoded_terms.keys()
            )
            content_len = max(len(content), 1)
            blacktalk_density = min(total_terms / (content_len / 50.0), 1.0)

        system_prompt = (
            "你是一个黑灰产威胁等级评估专家。根据以下情报内容和黑话解码信息，"
            "评估该情报的威胁等级。\n\n"
            "威胁等级定义：\n"
            "- critical: 涉及正在进行的重大犯罪活动、大规模数据泄露、关键基础设施攻击\n"
            "- high: 涉及具体的犯罪工具/方法、明确的攻击计划、大量个人信息交易\n"
            "- medium: 涉及可疑活动但缺乏具体细节、一般性的黑产讨论\n"
            "- low: 间接提及黑产活动、信息较为模糊\n"
            "- info: 仅为信息性内容，无直接威胁\n\n"
            "只返回威胁等级（critical/high/medium/low/info），不要其他内容。"
        )
        decoded_str = ""
        if decoded_terms:
            decoded_str = "黑话解码：" + "、".join(
                f"{k}({v})" for k, v in decoded_terms.items()
            )
        prompt = (
            f"情报内容：{_sanitize_input(content)}\n\n"
            f"{decoded_str}\n\n"
            f"黑话密度：{blacktalk_density:.2f}\n\n"
            f"请评估威胁等级。"
        )

        try:
            response = await self.llm.generate(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=settings.LLM_TEMPERATURE_ANALYSIS,
                max_tokens=settings.LLM_MAX_TOKENS_MINIMAL,
            )
            level_str = response.strip().lower()
            valid_levels = {"critical", "high", "medium", "low", "info"}
            if level_str in valid_levels:
                return level_str
        except Exception as exc:
            self.logger.warning(f"LLM threat level assessment failed, using rule-based fallback: {exc}")

        rule_level, rule_conf = rule_extractor.assess_threat_level(
            content, decoded_terms
        )
        if rule_level != "info" and rule_conf > 0.2:
            return rule_level

        if blacktalk_density > 0.5:
            return "high"
        if blacktalk_density > 0.2:
            return "medium"
        if decoded_terms:
            return "low"
        return "info"
