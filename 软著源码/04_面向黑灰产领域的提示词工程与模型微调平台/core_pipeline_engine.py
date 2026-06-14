import asyncio
import hashlib
import json
import re
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from loguru import logger


class StepStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class PipelineStepResult:
    step_type: str
    step_order: int
    status: StepStatus
    input_count: int = 0
    output_count: int = 0
    duration_ms: float = 0
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "step_type": self.step_type,
            "step_order": self.step_order,
            "status": self.status.value,
            "input_count": self.input_count,
            "output_count": self.output_count,
            "duration_ms": round(self.duration_ms, 2),
            "error_message": self.error_message,
            "metadata": self.metadata,
        }


@dataclass
class PipelineExecution:
    pipeline_id: str
    task_id: str
    status: StepStatus = StepStatus.PENDING
    progress: float = 0.0
    step_results: List[PipelineStepResult] = field(default_factory=list)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            "pipeline_id": self.pipeline_id,
            "task_id": self.task_id,
            "status": self.status.value,
            "progress": round(self.progress, 4),
            "step_results": [r.to_dict() for r in self.step_results],
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "error_message": self.error_message,
        }


@dataclass
class DAGNode:
    node_id: str
    step_type: str
    config: Dict[str, Any] = field(default_factory=dict)
    depends_on: List[str] = field(default_factory=list)
    condition: Optional[Dict[str, Any]] = None
    max_retries: int = 3
    retry_delay_base: float = 2.0
    timeout_seconds: float = 300.0


@dataclass
class DAGExecutionResult:
    node_id: str
    status: StepStatus
    output_data: List[Dict[str, Any]] = field(default_factory=list)
    duration_ms: float = 0.0
    retry_count: int = 0
    error_message: Optional[str] = None
    skipped_reason: Optional[str] = None


class DataCleaner:
    def __init__(self):
        self._minhash_signatures: Dict[str, List[int]] = {}
        self._num_perm: int = 128
        self._similarity_threshold: float = 0.8
        self._num_bands: int = 16
        self._rows_per_band: int = self._num_perm // self._num_bands
        self._lsh_buckets: List[Dict[str, Set[str]]] = [
            {} for _ in range(self._num_bands)
        ]
        self._max_signatures = 10000
        self._noise_patterns = [
            re.compile(r'^[\s\d\.\,\;\:\!\?\-]+$'),
            re.compile(r'^(.)\1{10,}$'),
            re.compile(r'^[\W_]+$'),
        ]
        self._meaningless_words = {
            "test", "null", "none", "undefined", "n/a", "na",
            "todo", "fixme", "placeholder", "sample", "example",
            "测试", "无", "空", "待定", "示例",
        }

    def clean_text(self, text: str) -> Tuple[str, Dict[str, Any]]:
        if not text:
            return "", {"original_length": 0, "cleaned_length": 0, "operations": []}

        operations = []
        original_len = len(text)

        cleaned = text.strip()
        if len(cleaned) != len(text):
            operations.append("strip_whitespace")

        cleaned = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', cleaned)
        operations.append("remove_control_chars")

        cleaned = re.sub(r'(.)\1{4,}', r'\1\1\1', cleaned)
        operations.append("collapse_repeated_chars")

        cleaned = re.sub(r'https?://\S+', '[URL_REDACTED]', cleaned)
        operations.append("redact_urls")

        cleaned = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '[IP_REDACTED]', cleaned)
        operations.append("redact_ips")

        cleaned = re.sub(r'\s+', ' ', cleaned).strip()
        operations.append("normalize_whitespace")

        cleaned = re.sub(r'[\ufeff\u200b\u200c\u200d\ufeff]', '', cleaned)
        operations.append("remove_zero_width_chars")

        return cleaned, {
            "original_length": original_len,
            "cleaned_length": len(cleaned),
            "operations": operations,
        }

    def fix_encoding(self, text: str) -> Tuple[str, Dict[str, Any]]:
        meta: Dict[str, Any] = {"fixed": False, "original_encoding": None, "operations": []}
        if not text:
            return text, meta

        mojibake_patterns = [
            (r'è', '的'),
            (r'ä', '的'),
            (r'ç', '的'),
            (r'å', '的'),
            (r'æ', '的'),
            (r'Ã©', 'é'),
            (r'Ã¨', 'è'),
            (r'Ãª', 'ê'),
            (r'Ã«', 'ë'),
            (r'Ã¡', 'á'),
            (r'Ã ', 'à'),
            (r'Ã³', 'ó'),
            (r'Ã¶', 'ö'),
            (r'Ã¼', 'ü'),
            (r'ÃŸ', 'ß'),
            (r'Ã±', 'ñ'),
            (r'â€œ', '"'),
            (r'â€\x9d', '"'),
            (r'â€˜', '''),
            (r'â€™', '''),
            (r'â€"', '—'),
            (r'â€"', '–'),
            (r'â€¦', '…'),
        ]

        fixed = text
        for pattern, replacement in mojibake_patterns:
            new_fixed = re.sub(pattern, replacement, fixed)
            if new_fixed != fixed:
                meta["fixed"] = True
                meta["operations"].append(f"fix_mojibake:{pattern[:10]}")
                fixed = new_fixed

        try:
            fixed.encode('ascii')
            return fixed, meta
        except UnicodeEncodeError:
            pass

        try:
            import chardet
            raw = text.encode('raw_unicode_escape')
            detected = chardet.detect(raw)
            if detected and detected.get("encoding") and detected["confidence"] > 0.7:
                meta["original_encoding"] = detected["encoding"]
                try:
                    fixed = raw.decode(detected["encoding"])
                    if fixed != text:
                        meta["fixed"] = True
                        meta["operations"].append(f"reencode:{detected['encoding']}")
                except (UnicodeDecodeError, LookupError):
                    pass
        except ImportError:
            pass

        return fixed, meta

    def is_noise(self, text: str, min_length: int = 10, max_length: int = 50000) -> Tuple[bool, str]:
        if not text or not text.strip():
            return True, "empty"
        if len(text) < min_length:
            return True, "too_short"
        if len(text) > max_length:
            return True, "too_long"
        for pattern in self._noise_patterns:
            if pattern.match(text.strip()):
                return True, "noise_pattern"
        stripped = text.strip().lower()
        if stripped in self._meaningless_words:
            return True, "meaningless"
        alpha_count = sum(1 for c in text if c.isalpha())
        if alpha_count / max(len(text), 1) < 0.1:
            return True, "low_alpha_ratio"
        return False, ""

    def standardize_format(self, item: Dict[str, Any]) -> Dict[str, Any]:
        standardized = dict(item)

        date_fields = ["date", "created_at", "updated_at", "published_at", "timestamp"]
        for df in date_fields:
            if df in standardized and isinstance(standardized[df], str):
                val = standardized[df]
                for fmt in [
                    "%Y-%m-%dT%H:%M:%S",
                    "%Y-%m-%d %H:%M:%S",
                    "%Y/%m/%d %H:%M:%S",
                    "%Y-%m-%d",
                    "%d/%m/%Y",
                    "%m/%d/%Y",
                ]:
                    try:
                        dt = datetime.strptime(val.strip(), fmt)
                        standardized[df] = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                        break
                    except ValueError:
                        continue

        for key, value in standardized.items():
            if isinstance(value, str):
                if value.lower() in ("null", "none", "n/a", "na", "undefined", "-"):
                    standardized[key] = None

        if "threat_level" in standardized and isinstance(standardized["threat_level"], str):
            level_map = {
                "crit": "critical", "critical": "critical",
                "high": "high", "important": "high", "h": "high",
                "medium": "medium", "med": "medium", "moderate": "medium", "m": "medium",
                "low": "low", "minor": "low", "l": "low",
                "info": "info", "informational": "info", "i": "info",
            }
            standardized["threat_level"] = level_map.get(
                standardized["threat_level"].lower().strip(),
                standardized["threat_level"],
            )

        return standardized

    def compute_minhash(self, text: str) -> List[int]:
        tokens = re.findall(r'\w+', text.lower())
        shingles = set()
        for i in range(len(tokens) - 2):
            shingles.add(' '.join(tokens[i:i + 3]))

        if not shingles:
            return [0] * self._num_perm

        signature = []
        for i in range(self._num_perm):
            min_hash = float('inf')
            for shingle in shingles:
                hash_val = int(hashlib.md5(f"{shingle}_{i}".encode()).hexdigest(), 16)
                if hash_val < min_hash:
                    min_hash = hash_val
            signature.append(min_hash)
        return signature

    def estimate_similarity(self, sig_a: List[int], sig_b: List[int]) -> float:
        if not sig_a or not sig_b or len(sig_a) != len(sig_b):
            return 0.0
        matches = sum(1 for a, b in zip(sig_a, sig_b) if a == b)
        return matches / len(sig_a)

    def _compute_lsh_bands(self, signature: List[int]) -> List[str]:
        bands = []
        for i in range(self._num_bands):
            start = i * self._rows_per_band
            end = start + self._rows_per_band
            band = tuple(signature[start:end])
            bands.append(hashlib.md5(str(band).encode()).hexdigest())
        return bands

    def is_duplicate(self, text: str, doc_id: str = "") -> Tuple[bool, Optional[str]]:
        sig = self.compute_minhash(text)
        doc_id = doc_id or hashlib.md5(text.encode()).hexdigest()[:16]

        bands = self._compute_lsh_bands(sig)
        for band_idx, band_hash in enumerate(bands):
            bucket = self._lsh_buckets[band_idx]
            if band_hash in bucket:
                for candidate_id in bucket[band_hash]:
                    if candidate_id in self._minhash_signatures:
                        sim = self.estimate_similarity(sig, self._minhash_signatures[candidate_id])
                        if sim >= self._similarity_threshold:
                            return True, candidate_id

        self._minhash_signatures[doc_id] = sig
        if len(self._minhash_signatures) > self._max_signatures:
            self._minhash_signatures.clear()
            for bucket in self._lsh_buckets:
                bucket.clear()
        for band_idx, band_hash in enumerate(bands):
            bucket = self._lsh_buckets[band_idx]
            if band_hash not in bucket:
                bucket[band_hash] = set()
            bucket[band_hash].add(doc_id)

        return False, None

    def batch_deduplicate(self, documents: List[Dict[str, str]]) -> Tuple[List[Dict], List[Dict]]:
        unique = []
        duplicates = []
        for doc in documents:
            text = doc.get("content", "")
            doc_id = doc.get("id", hashlib.md5(text.encode()).hexdigest()[:16])
            is_dup, dup_of = self.is_duplicate(text, doc_id)
            if is_dup:
                doc["duplicate_of"] = dup_of
                duplicates.append(doc)
            else:
                unique.append(doc)
        return unique, duplicates

    def full_clean(
        self,
        item: Dict[str, Any],
        min_length: int = 10,
        max_length: int = 50000,
        fix_encoding: bool = True,
        standardize: bool = True,
    ) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
        meta: Dict[str, Any] = {"operations": [], "filtered": False, "filter_reason": ""}

        if standardize:
            item = self.standardize_format(item)
            meta["operations"].append("standardize_format")

        content = item.get("content", "")
        if not content:
            meta["filtered"] = True
            meta["filter_reason"] = "no_content"
            return None, meta

        if fix_encoding:
            content, enc_meta = self.fix_encoding(content)
            if enc_meta["fixed"]:
                item["content"] = content
                meta["operations"].extend(enc_meta["operations"])

        is_noise, reason = self.is_noise(content, min_length, max_length)
        if is_noise:
            meta["filtered"] = True
            meta["filter_reason"] = reason
            return None, meta

        cleaned_content, clean_meta = self.clean_text(content)
        item["content"] = cleaned_content
        meta["operations"].extend(clean_meta["operations"])
        meta["original_length"] = clean_meta["original_length"]
        meta["cleaned_length"] = clean_meta["cleaned_length"]

        return item, meta


class DataAnnotator:
    def __init__(self, llm_service=None):
        self._llm = llm_service
        self._annotation_cache: Dict[str, Dict] = {}
        self._max_cache_size = 1000

    async def auto_annotate(
        self,
        text: str,
        annotation_type: str = "threat_classification",
        categories: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        cache_key = hashlib.md5(f"{text[:200]}:{annotation_type}".encode()).hexdigest()
        if cache_key in self._annotation_cache:
            return self._annotation_cache[cache_key]

        if not self._llm:
            result = self._rule_based_annotate(text, annotation_type, categories)
        else:
            result = await self._llm_annotate(text, annotation_type, categories)

        self._annotation_cache[cache_key] = result
        if len(self._annotation_cache) > self._max_cache_size:
            oldest_key = next(iter(self._annotation_cache))
            del self._annotation_cache[oldest_key]
        return result

    def _rule_based_annotate(
        self, text: str, annotation_type: str, categories: Optional[List[str]]
    ) -> Dict[str, Any]:
        if annotation_type == "threat_classification":
            threat_keywords = {
                "critical": ["0day", "零日", "在野利用", "紧急漏洞"],
                "high": ["勒索", "ransomware", "APT", "高级持续性威胁", "供应链攻击"],
                "medium": ["钓鱼", "phishing", "木马", "trojan", "DDoS"],
                "low": ["扫描", "scan", "探测", "probe"],
                "info": ["公告", "advisory", "更新", "update"],
            }
            text_lower = text.lower()
            detected_level = "info"
            for level, keywords in threat_keywords.items():
                if any(kw in text_lower for kw in keywords):
                    detected_level = level
                    break

            return {
                "annotation_type": annotation_type,
                "label": detected_level,
                "confidence": 0.7 if detected_level != "info" else 0.5,
                "method": "rule_based",
                "keywords_matched": [kw for kw in ["勒索", "钓鱼", "木马", "DDoS", "0day", "扫描"] if kw in text_lower],
            }

        return {"annotation_type": annotation_type, "label": "unknown", "confidence": 0.0, "method": "rule_based"}

    async def _llm_annotate(
        self, text: str, annotation_type: str, categories: Optional[List[str]]
    ) -> Dict[str, Any]:
        cat_str = ", ".join(categories) if categories else "critical, high, medium, low, info"
        prompt = (
            f"请对以下威胁情报文本进行分类标注：\n\n"
            f"分类类型: {annotation_type}\n"
            f"可选类别: {cat_str}\n\n"
            f"文本内容:\n{text[:1000]}\n\n"
            f"请以JSON格式返回: {{\"label\": \"类别\", \"confidence\": 0.0-1.0, \"reason\": \"分类理由\"}}"
        )
        try:
            response = await self._llm.chat(prompt)
            if isinstance(response, dict):
                llm_text = response.get("content", "")
            elif isinstance(response, str):
                llm_text = response
            else:
                llm_text = str(response)

            json_match = re.search(r'\{[^}]+\}', llm_text)
            if json_match:
                parsed = json.loads(json_match.group())
                return {
                    "annotation_type": annotation_type,
                    "label": parsed.get("label", "unknown"),
                    "confidence": min(1.0, max(0.0, float(parsed.get("confidence", 0.5)))),
                    "method": "llm_assisted",
                    "reason": parsed.get("reason", ""),
                }
        except Exception as exc:
            logger.warning(f"LLM标注失败: {exc}")

        return self._rule_based_annotate(text, annotation_type, categories)


class LLMDataAnnotator:
    def __init__(self, llm_service=None):
        self._llm = llm_service
        self._annotation_cache: Dict[str, Dict] = {}
        self._consistency_threshold: float = 0.7
        self._max_cache_size = 1000

    async def annotate(
        self,
        text: str,
        annotation_type: str = "threat_classification",
        categories: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        cache_key = hashlib.md5(f"{text[:200]}:{annotation_type}".encode()).hexdigest()
        if cache_key in self._annotation_cache:
            return self._annotation_cache[cache_key]

        if not self._llm:
            result = self._rule_based_annotate(text, annotation_type, categories)
        else:
            result = await self._llm_annotate(text, annotation_type, categories)

        self._annotation_cache[cache_key] = result
        if len(self._annotation_cache) > self._max_cache_size:
            oldest_key = next(iter(self._annotation_cache))
            del self._annotation_cache[oldest_key]
        return result

    async def annotate_threat(
        self, text: str, categories: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        result = await self.annotate(text, "threat_classification", categories)
        entity_result = await self.annotate(text, "entity_extraction")
        result["entities"] = entity_result.get("entities", [])
        return result

    async def batch_annotate(
        self,
        items: List[Dict[str, Any]],
        annotation_type: str = "threat_classification",
        categories: Optional[List[str]] = None,
        batch_size: int = 10,
    ) -> List[Dict[str, Any]]:
        results = []
        for i in range(0, len(items), batch_size):
            batch = items[i:i + batch_size]
            tasks = []
            for item in batch:
                content = item.get("content", "")
                if content:
                    tasks.append(self.annotate(content, annotation_type, categories))
                else:
                    async def _empty_annotation():
                        return {
                            "annotation_type": annotation_type,
                            "label": "unknown",
                            "confidence": 0.0,
                            "method": "skipped",
                        }
                    tasks.append(_empty_annotation())
            annotations = await asyncio.gather(*tasks, return_exceptions=True)
            for item, annotation in zip(batch, annotations):
                if isinstance(annotation, Exception):
                    annotation = {
                        "annotation_type": annotation_type,
                        "label": "unknown",
                        "confidence": 0.0,
                        "method": "error",
                        "error": str(annotation),
                    }
                item["_annotation"] = annotation
                if annotation.get("label"):
                    item["threat_level"] = annotation["label"]
                results.append(item)
        return results

    async def check_consistency(
        self, items: List[Dict[str, Any]], sample_size: int = 20
    ) -> Dict[str, Any]:
        import random
        sample = random.sample(items, min(sample_size, len(items))) if items else []
        if not sample:
            return {"consistency_score": 0.0, "re_annotated": 0, "mismatches": 0}

        mismatches = 0
        checked = 0
        for item in sample:
            original = item.get("_annotation", {})
            original_label = original.get("label")
            if not original_label:
                continue

            content = item.get("content", "")
            if not content:
                continue

            re_result = await self.annotate(content, original.get("annotation_type", "threat_classification"))
            re_label = re_result.get("label")
            checked += 1

            if re_label != original_label:
                mismatches += 1

        consistency_score = 1.0 - (mismatches / max(checked, 1))
        return {
            "consistency_score": round(consistency_score, 4),
            "re_annotated": checked,
            "mismatches": mismatches,
            "is_consistent": consistency_score >= self._consistency_threshold,
        }

    def _rule_based_annotate(
        self, text: str, annotation_type: str, categories: Optional[List[str]]
    ) -> Dict[str, Any]:
        if annotation_type == "threat_classification":
            threat_keywords = {
                "critical": ["0day", "零日", "在野利用", "紧急漏洞", "rce", "远程代码执行"],
                "high": ["勒索", "ransomware", "APT", "高级持续性威胁", "供应链攻击", "后门", "backdoor"],
                "medium": ["钓鱼", "phishing", "木马", "trojan", "DDoS", "挖矿", "mining", "botnet"],
                "low": ["扫描", "scan", "探测", "probe", "端口扫描"],
                "info": ["公告", "advisory", "更新", "update", "补丁", "patch"],
            }
            text_lower = text.lower()
            detected_level = "info"
            matched_keywords = []
            for level, keywords in threat_keywords.items():
                for kw in keywords:
                    if kw in text_lower:
                        detected_level = level
                        matched_keywords.append(kw)
                        break
                if detected_level != "info":
                    break

            return {
                "annotation_type": annotation_type,
                "label": detected_level,
                "confidence": 0.7 if detected_level != "info" else 0.5,
                "method": "rule_based",
                "keywords_matched": matched_keywords,
            }

        elif annotation_type == "entity_extraction":
            entities = []
            ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
            url_pattern = r'https?://\S+'
            email_pattern = r'\b[\w.-]+@[\w.-]+\.\w+\b'
            cve_pattern = r'CVE-\d{4}-\d{4,}'
            md5_pattern = r'\b[a-fA-F0-9]{32}\b'
            sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
            domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'

            for match in re.finditer(ip_pattern, text):
                entities.append({"type": "ip", "value": match.group()})
            for match in re.finditer(url_pattern, text):
                entities.append({"type": "url", "value": match.group()})
            for match in re.finditer(email_pattern, text):
                entities.append({"type": "email", "value": match.group()})
            for match in re.finditer(cve_pattern, text):
                entities.append({"type": "cve", "value": match.group()})
            for match in re.finditer(md5_pattern, text):
                entities.append({"type": "md5", "value": match.group()})
            for match in re.finditer(sha256_pattern, text):
                entities.append({"type": "sha256", "value": match.group()})
            for match in re.finditer(domain_pattern, text):
                val = match.group()
                if not re.match(ip_pattern, val):
                    entities.append({"type": "domain", "value": val})

            return {
                "annotation_type": annotation_type,
                "entities": entities,
                "method": "rule_based",
                "confidence": 0.8,
            }

        return {"annotation_type": annotation_type, "label": "unknown", "confidence": 0.0, "method": "rule_based"}

    async def _llm_annotate(
        self, text: str, annotation_type: str, categories: Optional[List[str]]
    ) -> Dict[str, Any]:
        if annotation_type == "entity_extraction":
            return await self._llm_entity_extract(text)

        cat_str = ", ".join(categories) if categories else "critical, high, medium, low, info"
        prompt = (
            f"请对以下威胁情报文本进行分类标注：\n\n"
            f"分类类型: {annotation_type}\n"
            f"可选类别: {cat_str}\n\n"
            f"文本内容:\n{text[:1000]}\n\n"
            f"请以JSON格式返回: {{\"label\": \"类别\", \"confidence\": 0.0-1.0, \"reason\": \"分类理由\"}}"
        )
        try:
            response = await self._llm.chat(prompt)
            if isinstance(response, dict):
                llm_text = response.get("content", "")
            elif isinstance(response, str):
                llm_text = response
            else:
                llm_text = str(response)

            json_match = re.search(r'\{[^}]+\}', llm_text)
            if json_match:
                parsed = json.loads(json_match.group())
                return {
                    "annotation_type": annotation_type,
                    "label": parsed.get("label", "unknown"),
                    "confidence": min(1.0, max(0.0, float(parsed.get("confidence", 0.5)))),
                    "method": "llm_assisted",
                    "reason": parsed.get("reason", ""),
                }
        except Exception as exc:
            logger.warning(f"LLM标注失败: {exc}")

        return self._rule_based_annotate(text, annotation_type, categories)

    async def _llm_entity_extract(self, text: str) -> Dict[str, Any]:
        prompt = (
            f"请从以下威胁情报文本中提取关键实体：\n\n"
            f"文本内容:\n{text[:1000]}\n\n"
            f"请以JSON格式返回实体列表: {{\"entities\": [{{\"type\": \"实体类型(ip/domain/url/cve/hash/email/organization/malware)\", \"value\": \"实体值\"}}]}}"
        )
        try:
            response = await self._llm.chat(prompt)
            if isinstance(response, dict):
                llm_text = response.get("content", "")
            elif isinstance(response, str):
                llm_text = response
            else:
                llm_text = str(response)

            json_match = re.search(r'\{[\s\S]*?\}', llm_text)
            if json_match:
                parsed = json.loads(json_match.group())
                entities = parsed.get("entities", [])
                return {
                    "annotation_type": "entity_extraction",
                    "entities": entities,
                    "method": "llm_assisted",
                    "confidence": 0.85,
                }
        except Exception as exc:
            logger.warning(f"LLM实体提取失败: {exc}")

        return self._rule_based_annotate(text, "entity_extraction", None)


class DataAugmentor:
    def __init__(self, llm_service=None):
        self._llm = llm_service

    async def augment(
        self,
        text: str,
        method: str = "paraphrase",
        count: int = 3,
    ) -> List[Dict[str, Any]]:
        if method == "paraphrase":
            return await self._paraphrase_augment(text, count)
        elif method == "back_translation":
            return await self._back_translation_augment(text, count)
        elif method == "entity_replace":
            return self._entity_replace_augment(text, count)
        else:
            return [{"text": text, "method": method, "augmented": False}]

    async def _paraphrase_augment(self, text: str, count: int) -> List[Dict[str, Any]]:
        if not self._llm:
            return [{"text": text, "method": "paraphrase", "augmented": False, "reason": "LLM未配置"}]

        prompt = (
            f"请对以下威胁情报文本进行{count}种不同表述的改写，保持核心信息不变：\n\n"
            f"{text[:800]}\n\n"
            f"请以JSON数组格式返回: [{{\"text\": \"改写文本\"}}]"
        )
        try:
            response = await self._llm.chat(prompt)
            if isinstance(response, dict):
                llm_text = response.get("content", "")
            elif isinstance(response, str):
                llm_text = response
            else:
                llm_text = str(response)

            json_match = re.search(r'\[[\s\S]*?\]', llm_text)
            if json_match:
                parsed = json.loads(json_match.group())
                results = []
                for item in parsed[:count]:
                    results.append({
                        "text": item.get("text", text),
                        "method": "paraphrase",
                        "augmented": True,
                    })
                return results
        except Exception as exc:
            logger.warning(f"改写增强失败: {exc}")

        return [{"text": text, "method": "paraphrase", "augmented": False}]

    async def _back_translation_augment(self, text: str, count: int) -> List[Dict[str, Any]]:
        if not self._llm:
            return [{"text": text, "method": "back_translation", "augmented": False, "reason": "LLM未配置"}]

        results = []
        try:
            translate_prompt = f"将以下中文文本翻译为英文，保持威胁情报的专业性：\n\n{text[:800]}"
            response = await self._llm.chat(translate_prompt)
            if isinstance(response, dict):
                en_text = response.get("content", "")
            elif isinstance(response, str):
                en_text = response
            else:
                en_text = str(response)

            if en_text:
                back_prompt = f"将以下英文威胁情报翻译回中文：\n\n{en_text[:800]}"
                response = await self._llm.chat(back_prompt)
                if isinstance(response, dict):
                    zh_text = response.get("content", "")
                elif isinstance(response, str):
                    zh_text = response
                else:
                    zh_text = str(response)

                if zh_text and zh_text != text:
                    results.append({
                        "text": zh_text,
                        "method": "back_translation",
                        "augmented": True,
                        "intermediate": en_text[:200],
                    })
        except Exception as exc:
            logger.warning(f"回译增强失败: {exc}")

        if not results:
            results.append({"text": text, "method": "back_translation", "augmented": False})

        return results

    def _entity_replace_augment(self, text: str, count: int) -> List[Dict[str, Any]]:
        entity_patterns = {
            "IP": r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            "URL": r'https?://\S+',
            "EMAIL": r'\b[\w.-]+@[\w.-]+\.\w+\b',
            "CVE": r'CVE-\d{4}-\d{4,}',
            "HASH": r'\b[a-fA-F0-9]{32,64}\b',
            "DOMAIN": r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
        }

        results = []
        for i in range(count):
            augmented = text
            replaced = []
            for etype, pattern in entity_patterns.items():
                matches = re.findall(pattern, augmented)
                for match in matches:
                    placeholder = f"[{etype}_{hashlib.md5(match.encode()).hexdigest()[:6]}]"
                    augmented = augmented.replace(match, placeholder, 1)
                    replaced.append({"original": match, "replacement": placeholder, "type": etype})

            if replaced:
                results.append({
                    "text": augmented,
                    "method": "entity_replace",
                    "augmented": True,
                    "replacements": replaced,
                })
            else:
                results.append({"text": text, "method": "entity_replace", "augmented": False})

        return results


class FormatConverter:
    SUPPORTED_FORMATS = ["jsonl", "csv", "alpaca", "parquet", "json", "sharegpt", "chatml"]

    def detect_format(self, content: str) -> str:
        stripped = content.strip()
        if not stripped:
            return "json"

        if stripped.startswith("[") or stripped.startswith("{"):
            try:
                parsed = json.loads(stripped)
                if isinstance(parsed, list):
                    if parsed and isinstance(parsed[0], dict):
                        first = parsed[0]
                        if "instruction" in first and "output" in first:
                            return "alpaca"
                        if "conversations" in first:
                            return "sharegpt"
                        if "messages" in first:
                            return "chatml"
                    return "json"
                return "json"
            except json.JSONDecodeError:
                pass

        lines = stripped.split("\n")
        jsonl_valid = 0
        for line in lines[:5]:
            line = line.strip()
            if line:
                try:
                    json.loads(line)
                    jsonl_valid += 1
                except json.JSONDecodeError:
                    break
        if jsonl_valid >= 2:
            return "jsonl"

        if "," in stripped and "\n" in stripped:
            first_line = stripped.split("\n")[0]
            if re.match(r'^[\w\s,]+$', first_line) and "," in first_line:
                return "csv"

        return "json"

    def convert(
        self,
        data: List[Dict[str, Any]],
        source_format: str,
        target_format: str,
        field_mapping: Optional[Dict[str, str]] = None,
    ) -> Tuple[str, Dict[str, Any]]:
        if source_format not in self.SUPPORTED_FORMATS or target_format not in self.SUPPORTED_FORMATS:
            return "", {"error": f"不支持的格式转换: {source_format}→{target_format}"}

        mapped_data = self._apply_field_mapping(data, field_mapping)

        if target_format == "jsonl":
            output = "\n".join(json.dumps(item, ensure_ascii=False) for item in mapped_data)
        elif target_format == "csv":
            if not mapped_data:
                return "", {"error": "数据为空"}
            headers = list(mapped_data[0].keys())
            lines = [",".join(headers)]
            for item in mapped_data:
                row = []
                for h in headers:
                    val = str(item.get(h, "")).replace('"', '""')
                    row.append(f'"{val}"')
                lines.append(",".join(row))
            output = "\n".join(lines)
        elif target_format == "alpaca":
            alpaca_items = []
            for item in mapped_data:
                alpaca_items.append({
                    "instruction": item.get("instruction", item.get("content", "")),
                    "input": item.get("input", ""),
                    "output": item.get("output", item.get("label", "")),
                })
            output = json.dumps(alpaca_items, ensure_ascii=False, indent=2)
        elif target_format == "sharegpt":
            sharegpt_items = []
            for item in mapped_data:
                conversations = item.get("conversations", [])
                if not conversations:
                    conversations = [
                        {"from": "human", "value": item.get("instruction", item.get("content", ""))},
                        {"from": "gpt", "value": item.get("output", item.get("label", ""))},
                    ]
                sharegpt_items.append({
                    "id": item.get("id", hashlib.md5(str(item).encode()).hexdigest()[:16]),
                    "conversations": conversations,
                })
            output = json.dumps(sharegpt_items, ensure_ascii=False, indent=2)
        elif target_format == "chatml":
            chatml_items = []
            for item in mapped_data:
                messages = []
                instruction = item.get("instruction", item.get("content", ""))
                output_text = item.get("output", item.get("label", ""))
                if instruction:
                    messages.append({"role": "user", "content": instruction})
                if output_text:
                    messages.append({"role": "assistant", "content": output_text})
                chatml_items.append({"messages": messages})
            output = json.dumps(chatml_items, ensure_ascii=False, indent=2)
        elif target_format == "parquet":
            try:
                import pyarrow as pa
                import pyarrow.parquet as pq

                if not mapped_data:
                    return "", {"error": "数据为空"}

                all_keys = set()
                for item in mapped_data:
                    all_keys.update(item.keys())

                columns = {}
                for key in sorted(all_keys):
                    columns[key] = [str(item.get(key, "")) for item in mapped_data]

                table = pa.table(columns)
                import io
                buf = io.BytesIO()
                pq.write_table(table, buf)
                output = buf.getvalue().hex()
                meta_extra = {"note": "parquet格式以hex编码返回，需解码后写入文件"}
            except ImportError:
                output = json.dumps(mapped_data, ensure_ascii=False, indent=2)
                meta_extra = {"warning": "pyarrow未安装，回退为JSON格式"}
        elif target_format == "json":
            output = json.dumps(mapped_data, ensure_ascii=False, indent=2)
        else:
            output = json.dumps(mapped_data, ensure_ascii=False)

        meta = {
            "source_format": source_format,
            "target_format": target_format,
            "input_count": len(data),
            "output_count": len(mapped_data),
            "output_size_bytes": len(output.encode()),
        }
        if "meta_extra" in dir():
            meta.update(meta_extra)

        return output, meta

    def convert_auto(
        self,
        content: str,
        target_format: str,
        field_mapping: Optional[Dict[str, str]] = None,
    ) -> Tuple[str, Dict[str, Any]]:
        source_format = self.detect_format(content)
        data = self.parse_content(content, source_format)
        return self.convert(data, source_format, target_format, field_mapping)

    def parse_content(self, content: str, source_format: str) -> List[Dict[str, Any]]:
        if source_format == "jsonl":
            return [json.loads(line) for line in content.strip().split("\n") if line.strip()]
        elif source_format == "csv":
            import csv
            from io import StringIO
            reader = csv.DictReader(StringIO(content))
            return [row for row in reader]
        elif source_format in ("json", "alpaca", "sharegpt", "chatml"):
            parsed = json.loads(content)
            if isinstance(parsed, list):
                return parsed
            return [parsed]
        elif source_format == "parquet":
            try:
                import pyarrow.parquet as pq
                import io
                buf = io.BytesIO(bytes.fromhex(content))
                table = pq.read_table(buf)
                return table.to_pydict()
            except Exception:
                return json.loads(content) if content else []
        return json.loads(content) if content else []

    def incremental_convert(
        self,
        new_items: List[Dict[str, Any]],
        existing_content: str,
        target_format: str,
        field_mapping: Optional[Dict[str, str]] = None,
    ) -> Tuple[str, Dict[str, Any]]:
        existing_data = []
        if existing_content.strip():
            source_format = self.detect_format(existing_content)
            existing_data = self.parse_content(existing_content, source_format)

        combined = existing_data + new_items
        mapped = self._apply_field_mapping(combined, field_mapping)

        if target_format == "jsonl":
            new_lines = [json.dumps(item, ensure_ascii=False) for item in self._apply_field_mapping(new_items, field_mapping)]
            if existing_content.strip():
                output = existing_content.rstrip() + "\n" + "\n".join(new_lines)
            else:
                output = "\n".join(new_lines)
        else:
            output, _ = self.convert(combined, "json", target_format, field_mapping)

        meta = {
            "target_format": target_format,
            "existing_count": len(existing_data),
            "new_count": len(new_items),
            "total_count": len(combined),
            "incremental": True,
        }
        return output, meta

    def _apply_field_mapping(
        self, data: List[Dict], mapping: Optional[Dict[str, str]]
    ) -> List[Dict]:
        if not mapping:
            return data
        mapped = []
        for item in data:
            new_item = {}
            for src_field, tgt_field in mapping.items():
                if src_field in item:
                    new_item[tgt_field] = item[src_field]
            for key, value in item.items():
                if key not in mapping and key not in new_item:
                    new_item[key] = value
            mapped.append(new_item)
        return mapped


class DAGExecutor:
    def __init__(self, llm_service=None, max_concurrent: int = 5):
        self._llm = llm_service
        self._max_concurrent = max_concurrent
        self._cleaner = DataCleaner()
        self._annotator = LLMDataAnnotator(llm_service)
        self._augmentor = DataAugmentor(llm_service)
        self._converter = FormatConverter()
        self._execution_results: Dict[str, Dict[str, DAGExecutionResult]] = {}
        self._max_execution_results = 50

    def topological_sort(self, nodes: List[DAGNode]) -> List[List[str]]:
        graph: Dict[str, List[str]] = defaultdict(list)
        in_degree: Dict[str, int] = {}
        node_ids = {n.node_id for n in nodes}

        for node in nodes:
            in_degree.setdefault(node.node_id, 0)
            for dep in node.depends_on:
                if dep in node_ids:
                    graph[dep].append(node.node_id)
                    in_degree[node.node_id] = in_degree.get(node.node_id, 0) + 1

        layers = []
        remaining = dict(in_degree)

        while remaining:
            ready = [nid for nid, deg in remaining.items() if deg == 0]
            if not ready:
                cyclic = list(remaining.keys())
                logger.warning(f"DAG检测到循环依赖: {cyclic}")
                for nid in cyclic:
                    remaining[nid] = 0
                ready = cyclic
                break

            layers.append(ready)

            for nid in ready:
                for next_nid in graph[nid]:
                    if next_nid in remaining:
                        remaining[next_nid] -= 1
                del remaining[nid]

        return layers

    async def execute(
        self,
        nodes: List[DAGNode],
        input_data: List[Dict[str, Any]],
        pipeline_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        pipeline_id = pipeline_id or uuid.uuid4().hex
        self._execution_results[pipeline_id] = {}
        results_map: Dict[str, DAGExecutionResult] = {}
        node_map = {n.node_id: n for n in nodes}
        data_map: Dict[str, List[Dict[str, Any]]] = {"__input__": input_data}

        layers = self.topological_sort(nodes)
        total_nodes = len(nodes)
        completed = 0
        failed = False

        for layer in layers:
            if failed:
                for nid in layer:
                    results_map[nid] = DAGExecutionResult(
                        node_id=nid,
                        status=StepStatus.SKIPPED,
                        skipped_reason="upstream_failure",
                    )
                continue

            if len(layer) == 1:
                nid = layer[0]
                node = node_map[nid]
                result = await self._execute_node_with_retry(
                    node, data_map, results_map, pipeline_id
                )
                results_map[nid] = result
                if result.status == StepStatus.COMPLETED:
                    data_map[nid] = result.output_data
                    completed += 1
                elif result.status == StepStatus.SKIPPED:
                    data_map[nid] = data_map.get(self._get_dependency_data_key(node, data_map), input_data)
                    completed += 1
                else:
                    failed = True
            else:
                semaphore = asyncio.Semaphore(self._max_concurrent)
                tasks = []
                for nid in layer:
                    node = node_map[nid]
                    tasks.append(self._execute_node_with_semaphore(
                        semaphore, node, data_map, results_map, pipeline_id
                    ))
                layer_results = await asyncio.gather(*tasks, return_exceptions=True)

                for nid, result in zip(layer, layer_results):
                    if isinstance(result, Exception):
                        result = DAGExecutionResult(
                            node_id=nid,
                            status=StepStatus.FAILED,
                            error_message=str(result),
                        )
                    results_map[nid] = result
                    if result.status == StepStatus.COMPLETED:
                        data_map[nid] = result.output_data
                        completed += 1
                    elif result.status == StepStatus.SKIPPED:
                        data_map[nid] = data_map.get(
                            self._get_dependency_data_key(node_map[nid], data_map), input_data
                        )
                        completed += 1
                    else:
                        failed = True

        self._execution_results[pipeline_id] = results_map
        if len(self._execution_results) > self._max_execution_results:
            oldest_keys = list(self._execution_results.keys())[:len(self._execution_results) - self._max_execution_results]
            for k in oldest_keys:
                del self._execution_results[k]

        final_data = input_data
        for nid in reversed([n.node_id for n in nodes]):
            if nid in data_map and results_map.get(nid, DAGExecutionResult(node_id="", status=StepStatus.FAILED)).status in (
                StepStatus.COMPLETED, StepStatus.SKIPPED,
            ):
                final_data = data_map[nid]
                break

        return {
            "pipeline_id": pipeline_id,
            "status": "failed" if failed else "completed",
            "progress": round(completed / max(total_nodes, 1), 4),
            "total_nodes": total_nodes,
            "completed_nodes": completed,
            "results": {nid: self._dag_result_to_dict(r) for nid, r in results_map.items()},
            "output_data": final_data,
        }

    def _get_dependency_data_key(
        self, node: DAGNode, data_map: Dict[str, List[Dict[str, Any]]]
    ) -> str:
        for dep in node.depends_on:
            if dep in data_map:
                return dep
        return "__input__"

    async def _execute_node_with_semaphore(
        self,
        semaphore: asyncio.Semaphore,
        node: DAGNode,
        data_map: Dict[str, List[Dict[str, Any]]],
        results_map: Dict[str, DAGExecutionResult],
        pipeline_id: str,
    ) -> DAGExecutionResult:
        async with semaphore:
            return await self._execute_node_with_retry(node, data_map, results_map, pipeline_id)

    async def _execute_node_with_retry(
        self,
        node: DAGNode,
        data_map: Dict[str, List[Dict[str, Any]]],
        results_map: Dict[str, DAGExecutionResult],
        pipeline_id: str,
    ) -> DAGExecutionResult:
        if node.condition:
            should_run = self._evaluate_condition(node.condition, data_map, results_map)
            if not should_run:
                return DAGExecutionResult(
                    node_id=node.node_id,
                    status=StepStatus.SKIPPED,
                    skipped_reason="condition_not_met",
                )

        input_data = data_map.get("__input__", [])
        for dep in node.depends_on:
            if dep in data_map:
                input_data = data_map[dep]
                break

        last_error = None
        for attempt in range(node.max_retries + 1):
            start = datetime.now(timezone.utc)
            try:
                output_data = await asyncio.wait_for(
                    self._execute_step(node.step_type, node.config, input_data),
                    timeout=node.timeout_seconds,
                )
                duration = (datetime.now(timezone.utc) - start).total_seconds() * 1000
                return DAGExecutionResult(
                    node_id=node.node_id,
                    status=StepStatus.COMPLETED,
                    output_data=output_data,
                    duration_ms=duration,
                    retry_count=attempt,
                )
            except asyncio.TimeoutError:
                duration = (datetime.now(timezone.utc) - start).total_seconds() * 1000
                last_error = f"步骤超时({node.timeout_seconds}s)"
                logger.warning(f"DAG节点 {node.node_id} 超时 (尝试 {attempt + 1}/{node.max_retries + 1})")
            except Exception as exc:
                duration = (datetime.now(timezone.utc) - start).total_seconds() * 1000
                last_error = str(exc)
                logger.warning(f"DAG节点 {node.node_id} 失败 (尝试 {attempt + 1}/{node.max_retries + 1}): {exc}")

            if attempt < node.max_retries:
                delay = min(node.retry_delay_base ** (attempt + 1), 60.0)
                await asyncio.sleep(delay)

        return DAGExecutionResult(
            node_id=node.node_id,
            status=StepStatus.FAILED,
            error_message=last_error,
            retry_count=node.max_retries,
        )

    def _evaluate_condition(
        self,
        condition: Dict[str, Any],
        data_map: Dict[str, List[Dict[str, Any]]],
        results_map: Dict[str, DAGExecutionResult],
    ) -> bool:
        cond_type = condition.get("type", "result_check")

        if cond_type == "result_check":
            check_node = condition.get("node_id", "")
            expected_status = condition.get("status", "completed")
            if check_node in results_map:
                return results_map[check_node].status.value == expected_status
            return False

        elif cond_type == "data_field":
            field = condition.get("field", "")
            operator = condition.get("operator", "exists")
            value = condition.get("value")
            source_node = condition.get("node_id", "__input__")
            data = data_map.get(source_node, [])
            if not data:
                return False
            item = data[0]
            item_val = item.get(field)
            if operator == "exists":
                return item_val is not None
            elif operator == "equals":
                return item_val == value
            elif operator == "not_equals":
                return item_val != value
            elif operator == "contains" and isinstance(item_val, str):
                return value in item_val
            elif operator == "gte":
                return item_val is not None and item_val >= value
            elif operator == "lte":
                return item_val is not None and item_val <= value
            return False

        elif cond_type == "count_check":
            source_node = condition.get("node_id", "__input__")
            operator = condition.get("operator", "gte")
            value = condition.get("value", 0)
            data = data_map.get(source_node, [])
            count = len(data)
            if operator == "gte":
                return count >= value
            elif operator == "lte":
                return count <= value
            elif operator == "equals":
                return count == value
            elif operator == "gt":
                return count > value
            elif operator == "lt":
                return count < value
            return False

        return True

    async def _execute_step(
        self, step_type: str, config: Dict[str, Any], input_data: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        if step_type == "import":
            return self._execute_import(config, input_data)
        elif step_type == "clean":
            return await self._execute_clean(config, input_data)
        elif step_type == "label":
            return await self._execute_label(config, input_data)
        elif step_type == "augment":
            return await self._execute_augment(config, input_data)
        elif step_type == "format_convert":
            return await self._execute_convert(config, input_data)
        elif step_type == "filter":
            return self._execute_filter(config, input_data)
        elif step_type == "merge":
            return self._execute_merge(config, input_data)
        elif step_type == "sample":
            return self._execute_sample(config, input_data)
        else:
            logger.warning(f"未知步骤类型: {step_type}")
            return input_data

    def _execute_import(self, config: Dict, current_data: List[Dict]) -> List[Dict]:
        source = config.get("source", "inline")
        if source == "inline":
            return current_data
        elif source == "csv":
            import csv
            from io import StringIO
            csv_content = config.get("content", "")
            reader = csv.DictReader(StringIO(csv_content))
            return [row for row in reader]
        elif source == "json":
            json_content = config.get("content", "[]")
            return json.loads(json_content)
        elif source == "jsonl":
            jsonl_content = config.get("content", "")
            return [json.loads(line) for line in jsonl_content.strip().split("\n") if line.strip()]
        return current_data

    async def _execute_clean(self, config: Dict, current_data: List[Dict]) -> List[Dict]:
        dedup = config.get("deduplicate", True)
        clean_text = config.get("clean_text", True)
        min_length = config.get("min_length", 10)
        max_length = config.get("max_length", 50000)
        fix_encoding = config.get("fix_encoding", True)
        standardize = config.get("standardize", True)

        cleaned = []
        for item in current_data:
            result_item, meta = self._cleaner.full_clean(
                item,
                min_length=min_length,
                max_length=max_length,
                fix_encoding=fix_encoding,
                standardize=standardize,
            )
            if result_item is not None:
                result_item["_clean_meta"] = meta
                cleaned.append(result_item)

        if dedup:
            unique, duplicates = self._cleaner.batch_deduplicate(cleaned)
            for item in unique:
                item["_dedup_checked"] = True
            for item in duplicates:
                item["_is_duplicate"] = True
                item["_duplicate_of"] = item.get("duplicate_of", "")
            cleaned = unique

        return cleaned

    async def _execute_label(self, config: Dict, current_data: List[Dict]) -> List[Dict]:
        annotation_type = config.get("annotation_type", "threat_classification")
        categories = config.get("categories")
        auto_annotate = config.get("auto_annotate", True)
        batch_size = config.get("batch_size", 10)

        if not auto_annotate:
            return current_data

        return await self._annotator.batch_annotate(
            current_data, annotation_type, categories, batch_size
        )

    async def _execute_augment(self, config: Dict, current_data: List[Dict]) -> List[Dict]:
        method = config.get("method", "paraphrase")
        count = config.get("count", 2)
        max_items = config.get("max_items", 50)

        if not self._llm and method in ("paraphrase", "back_translation"):
            logger.info(f"LLM未配置，跳过{method}增强")
            return current_data

        items_to_augment = current_data[:max_items]
        augmented = []

        for item in items_to_augment:
            content = item.get("content", "")
            if not content:
                continue
            results = await self._augmentor.augment(content, method, count)
            for aug_result in results:
                if aug_result.get("augmented"):
                    aug_item = dict(item)
                    aug_item["content"] = aug_result["text"]
                    aug_item["_augmented"] = True
                    aug_item["_augment_method"] = method
                    augmented.append(aug_item)

        return current_data + augmented

    async def _execute_convert(self, config: Dict, current_data: List[Dict]) -> List[Dict]:
        target_format = config.get("target_format", "jsonl")
        field_mapping = config.get("field_mapping")

        output, meta = self._converter.convert(
            current_data, "json", target_format, field_mapping
        )

        if output:
            return [{"content": output, "_format": target_format, "_conversion_meta": meta}]

        return current_data

    def _execute_filter(self, config: Dict, current_data: List[Dict]) -> List[Dict]:
        field = config.get("field", "threat_level")
        operator = config.get("operator", "in")
        value = config.get("value", [])

        filtered = []
        for item in current_data:
            item_val = item.get(field)
            if operator == "in" and item_val in value:
                filtered.append(item)
            elif operator == "not_in" and item_val not in value:
                filtered.append(item)
            elif operator == "equals" and item_val == value:
                filtered.append(item)
            elif operator == "not_equals" and item_val != value:
                filtered.append(item)
            elif operator == "contains" and isinstance(item_val, str) and value in item_val:
                filtered.append(item)
            elif operator == "gte" and item_val is not None and item_val >= value:
                filtered.append(item)
            elif operator == "lte" and item_val is not None and item_val <= value:
                filtered.append(item)
            elif operator == "exists" and item_val is not None:
                filtered.append(item)
            elif operator == "not_exists" and item_val is None:
                filtered.append(item)

        return filtered

    def _execute_merge(self, config: Dict, current_data: List[Dict]) -> List[Dict]:
        merge_field = config.get("merge_field", "id")
        strategy = config.get("strategy", "deduplicate")

        if strategy == "deduplicate":
            seen = set()
            result = []
            for item in current_data:
                key = item.get(merge_field, "")
                if key not in seen:
                    seen.add(key)
                    result.append(item)
            return result
        elif strategy == "concat":
            return current_data
        elif strategy == "latest":
            grouped = defaultdict(list)
            for item in current_data:
                key = item.get(merge_field, "")
                grouped[key].append(item)
            result = []
            for key, items in grouped.items():
                items.sort(key=lambda x: x.get("updated_at", x.get("created_at", "")), reverse=True)
                result.append(items[0])
            return result

        return current_data

    def _execute_sample(self, config: Dict, current_data: List[Dict]) -> List[Dict]:
        sample_size = config.get("size", 100)
        method = config.get("method", "random")
        seed = config.get("seed", 42)

        if method == "random":
            import random
            rng = random.Random(seed)
            return rng.sample(current_data, min(sample_size, len(current_data)))
        elif method == "stratified":
            stratify_field = config.get("stratify_field", "threat_level")
            groups = defaultdict(list)
            for item in current_data:
                key = item.get(stratify_field, "unknown")
                groups[key].append(item)

            per_group = max(1, sample_size // max(len(groups), 1))
            result = []
            import random
            rng = random.Random(seed)
            for key, items in groups.items():
                result.extend(rng.sample(items, min(per_group, len(items))))
            return result[:sample_size]
        elif method == "first":
            return current_data[:sample_size]
        elif method == "last":
            return current_data[-sample_size:]

        return current_data

    def _dag_result_to_dict(self, result: DAGExecutionResult) -> Dict[str, Any]:
        return {
            "node_id": result.node_id,
            "status": result.status.value,
            "output_count": len(result.output_data),
            "duration_ms": round(result.duration_ms, 2),
            "retry_count": result.retry_count,
            "error_message": result.error_message,
            "skipped_reason": result.skipped_reason,
        }

    def get_execution_results(self, pipeline_id: str) -> Optional[Dict[str, DAGExecutionResult]]:
        return self._execution_results.get(pipeline_id)


class PipelineExecutor:
    def __init__(self, llm_service=None):
        self._cleaner = DataCleaner()
        self._annotator = DataAnnotator(llm_service)
        self._llm_annotator = LLMDataAnnotator(llm_service)
        self._augmentor = DataAugmentor(llm_service)
        self._converter = FormatConverter()
        self._dag_executor = DAGExecutor(llm_service)
        self._active_executions: Dict[str, PipelineExecution] = {}
        self._max_active_executions = 100
        self._llm = llm_service

    async def execute_pipeline(
        self,
        task_id: str,
        steps: List[Dict[str, Any]],
        input_data: Optional[List[Dict[str, Any]]] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> PipelineExecution:
        pipeline_id = uuid.uuid4().hex
        execution = PipelineExecution(
            pipeline_id=pipeline_id,
            task_id=task_id,
            status=StepStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
        )
        self._active_executions[pipeline_id] = execution
        completed_ids = [pid for pid, ex in self._active_executions.items() if ex.status != StepStatus.RUNNING]
        for pid in completed_ids:
            if len(self._active_executions) > self._max_active_executions:
                del self._active_executions[pid]

        sorted_steps = sorted(steps, key=lambda s: s.get("order", 0))
        current_data = input_data or []

        try:
            for i, step in enumerate(sorted_steps):
                step_type = step.get("step_type", "")
                step_config = step.get("config", {})
                step_result = PipelineStepResult(
                    step_type=step_type,
                    step_order=step.get("order", i),
                    status=StepStatus.RUNNING,
                    input_count=len(current_data),
                )

                step_start = datetime.now(timezone.utc)

                try:
                    if step_type == "import":
                        current_data = await self._execute_import(step_config, current_data)
                    elif step_type == "clean":
                        current_data = await self._execute_clean(step_config, current_data)
                    elif step_type == "label":
                        current_data = await self._execute_label(step_config, current_data)
                    elif step_type == "augment":
                        current_data = await self._execute_augment(step_config, current_data)
                    elif step_type == "format_convert":
                        current_data = await self._execute_convert(step_config, current_data)
                    elif step_type == "filter":
                        current_data = self._execute_filter(step_config, current_data)
                    elif step_type == "conditional":
                        current_data = await self._execute_conditional(step_config, current_data, sorted_steps, i)
                    elif step_type == "merge":
                        current_data = self._execute_merge(step_config, current_data)
                    elif step_type == "sample":
                        current_data = self._execute_sample(step_config, current_data)
                    else:
                        step_result.status = StepStatus.SKIPPED
                        step_result.error_message = f"未知步骤类型: {step_type}"

                    if step_result.status == StepStatus.RUNNING:
                        step_result.status = StepStatus.COMPLETED
                    step_result.output_count = len(current_data)

                except Exception as exc:
                    step_result.status = StepStatus.FAILED
                    step_result.error_message = "步骤执行失败"
                    execution.status = StepStatus.FAILED
                    execution.error_message = f"步骤{step_type}执行失败"
                    logger.error(f"Pipeline step {step_type} failed: {exc}")

                step_end = datetime.now(timezone.utc)
                step_result.duration_ms = (step_end - step_start).total_seconds() * 1000
                execution.step_results.append(step_result)

                execution.progress = (i + 1) / len(sorted_steps)

                if step_result.status == StepStatus.FAILED:
                    break

            if execution.status == StepStatus.RUNNING:
                execution.status = StepStatus.COMPLETED

        except Exception as exc:
            execution.status = StepStatus.FAILED
            execution.error_message = "管线执行失败"

        execution.completed_at = datetime.now(timezone.utc)
        execution.progress = 1.0 if execution.status == StepStatus.COMPLETED else execution.progress

        return execution

    async def execute_dag_pipeline(
        self,
        task_id: str,
        nodes: List[DAGNode],
        input_data: Optional[List[Dict[str, Any]]] = None,
    ) -> PipelineExecution:
        pipeline_id = uuid.uuid4().hex
        execution = PipelineExecution(
            pipeline_id=pipeline_id,
            task_id=task_id,
            status=StepStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
        )
        self._active_executions[pipeline_id] = execution
        completed_ids = [pid for pid, ex in self._active_executions.items() if ex.status != StepStatus.RUNNING]
        for pid in completed_ids:
            if len(self._active_executions) > self._max_active_executions:
                del self._active_executions[pid]

        try:
            dag_result = await self._dag_executor.execute(nodes, input_data or [], pipeline_id)

            for nid, result_dict in dag_result.get("results", {}).items():
                step_result = PipelineStepResult(
                    step_type=nid,
                    step_order=0,
                    status=StepStatus(result_dict.get("status", "completed")),
                    duration_ms=result_dict.get("duration_ms", 0),
                    error_message=result_dict.get("error_message"),
                    metadata={
                        "retry_count": result_dict.get("retry_count", 0),
                        "skipped_reason": result_dict.get("skipped_reason"),
                        "output_count": result_dict.get("output_count", 0),
                    },
                )
                execution.step_results.append(step_result)

            if dag_result.get("status") == "completed":
                execution.status = StepStatus.COMPLETED
            else:
                execution.status = StepStatus.FAILED
                execution.error_message = "DAG执行中存在失败节点"

            execution.progress = dag_result.get("progress", 1.0)

        except Exception as exc:
            execution.status = StepStatus.FAILED
            execution.error_message = "管线执行失败"

        execution.completed_at = datetime.now(timezone.utc)
        execution.progress = 1.0 if execution.status == StepStatus.COMPLETED else execution.progress

        return execution

    def _resolve_dependencies(self, steps: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
        step_map = {}
        for step in steps:
            step_id = step.get("id", step.get("step_type", "") + "_" + str(step.get("order", 0)))
            step["_id"] = step_id
            step_map[step_id] = step

        in_degree = {sid: 0 for sid in step_map}
        graph = {sid: [] for sid in step_map}

        for sid, step in step_map.items():
            deps = step.get("depends_on", [])
            if isinstance(deps, str):
                deps = [deps]
            for dep in deps:
                if dep in step_map:
                    graph[dep].append(sid)
                    in_degree[sid] += 1

        layers = []
        remaining = dict(in_degree)

        while remaining:
            ready = [sid for sid, deg in remaining.items() if deg == 0]
            if not ready:
                cyclic = list(remaining.keys())
                logger.warning(f"检测到循环依赖: {cyclic}")
                for sid in cyclic:
                    remaining[sid] = 0
                ready = cyclic
                break

            layer = [step_map[sid] for sid in ready]
            layers.append(layer)

            for sid in ready:
                for next_sid in graph[sid]:
                    if next_sid in remaining:
                        remaining[next_sid] -= 1
                del remaining[sid]

        return layers

    async def execute_pipeline_parallel(self, task_id: str, steps: List[Dict[str, Any]], input_data: Optional[List[Dict]] = None, config: Optional[Dict] = None, max_concurrent: int = 3) -> PipelineExecution:
        pipeline_id = uuid.uuid4().hex
        execution = PipelineExecution(
            pipeline_id=pipeline_id,
            task_id=task_id,
            status=StepStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
        )
        self._active_executions[pipeline_id] = execution
        completed_ids = [pid for pid, ex in self._active_executions.items() if ex.status != StepStatus.RUNNING]
        for pid in completed_ids:
            if len(self._active_executions) > self._max_active_executions:
                del self._active_executions[pid]

        layers = self._resolve_dependencies(steps)
        current_data = input_data or []
        total_layers = len(layers)
        completed_steps = 0
        total_steps = sum(len(layer) for layer in layers)

        try:
            for layer_idx, layer in enumerate(layers):
                if len(layer) == 1:
                    step = layer[0]
                    step_result = await self._execute_single_step(step, current_data, config)
                    execution.step_results.append(step_result)
                    if step_result.status == StepStatus.COMPLETED:
                        current_data = step_result.metadata.get("output_data", current_data)
                    elif step_result.status == StepStatus.FAILED:
                        retry_count = step.get("retry_count", 0)
                        max_retries = step.get("max_retries", 2)
                        while retry_count < max_retries and step_result.status == StepStatus.FAILED:
                            retry_count += 1
                            logger.info(f"重试步骤 {step.get('step_type')} ({retry_count}/{max_retries})")
                            await asyncio.sleep(min(2 ** retry_count, 10))
                            step_result = await self._execute_single_step(step, current_data, config)
                            step_result.metadata["retry_count"] = retry_count
                        if step_result.status == StepStatus.FAILED:
                            execution.status = StepStatus.FAILED
                            execution.error_message = f"步骤 {step.get('step_type')} 重试{max_retries}次后仍失败"
                            execution.step_results.append(step_result)
                            break
                    completed_steps += 1
                else:
                    semaphore = asyncio.Semaphore(max_concurrent)
                    tasks = []
                    for step in layer:
                        tasks.append(self._execute_step_with_semaphore(semaphore, step, current_data, config))
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    for i, result in enumerate(results):
                        if isinstance(result, Exception):
                            step_result = PipelineStepResult(
                                step_type=layer[i].get("step_type", ""),
                                step_order=layer[i].get("order", 0),
                                status=StepStatus.FAILED,
                                error_message="步骤执行异常",
                            )
                        else:
                            step_result = result
                        execution.step_results.append(step_result)
                        if step_result.status == StepStatus.COMPLETED:
                            output = step_result.metadata.get("output_data", [])
                            current_data = current_data + output if isinstance(output, list) else current_data
                        completed_steps += 1

                execution.progress = completed_steps / max(1, total_steps)

            if execution.status == StepStatus.RUNNING:
                execution.status = StepStatus.COMPLETED

        except Exception as exc:
            execution.status = StepStatus.FAILED
            execution.error_message = "管线执行失败"

        execution.completed_at = datetime.now(timezone.utc)
        execution.progress = 1.0 if execution.status == StepStatus.COMPLETED else execution.progress
        return execution

    async def _execute_single_step(self, step: Dict, current_data: List[Dict], config: Optional[Dict] = None) -> PipelineStepResult:
        step_type = step.get("step_type", "")
        step_config = step.get("config", {})
        step_result = PipelineStepResult(
            step_type=step_type,
            step_order=step.get("order", 0),
            status=StepStatus.RUNNING,
            input_count=len(current_data),
        )
        step_start = datetime.now(timezone.utc)

        try:
            if step_type == "import":
                current_data = await self._execute_import(step_config, current_data)
            elif step_type == "clean":
                current_data = await self._execute_clean(step_config, current_data)
            elif step_type == "label":
                current_data = await self._execute_label(step_config, current_data)
            elif step_type == "augment":
                current_data = await self._execute_augment(step_config, current_data)
            elif step_type == "format_convert":
                current_data = await self._execute_convert(step_config, current_data)
            else:
                step_result.status = StepStatus.SKIPPED
                step_result.error_message = f"未知步骤类型: {step_type}"

            if step_result.status == StepStatus.RUNNING:
                step_result.status = StepStatus.COMPLETED
            step_result.output_count = len(current_data)
            step_result.metadata["output_data"] = current_data
        except Exception as exc:
            step_result.status = StepStatus.FAILED
            step_result.error_message = "步骤执行失败"

        step_end = datetime.now(timezone.utc)
        step_result.duration_ms = (step_end - step_start).total_seconds() * 1000
        return step_result

    async def _execute_step_with_semaphore(self, semaphore: asyncio.Semaphore, step: Dict, current_data: List[Dict], config: Optional[Dict] = None) -> PipelineStepResult:
        async with semaphore:
            return await self._execute_single_step(step, current_data, config)

    async def _execute_import(
        self, config: Dict, current_data: List[Dict]
    ) -> List[Dict]:
        return self.execute_import(config, current_data)

    def execute_import(
        self, config: Dict, current_data: List[Dict]
    ) -> List[Dict]:
        source = config.get("source", "inline")
        if source == "inline":
            return current_data
        elif source == "csv":
            import csv
            from io import StringIO
            csv_content = config.get("content", "")
            reader = csv.DictReader(StringIO(csv_content))
            return [row for row in reader]
        elif source == "json":
            json_content = config.get("content", "[]")
            return json.loads(json_content)
        elif source == "jsonl":
            jsonl_content = config.get("content", "")
            return [json.loads(line) for line in jsonl_content.strip().split("\n") if line.strip()]
        return current_data

    async def _execute_clean(
        self, config: Dict, current_data: List[Dict]
    ) -> List[Dict]:
        dedup = config.get("deduplicate", True)
        clean_text = config.get("clean_text", True)
        min_length = config.get("min_length", 10)
        max_length = config.get("max_length", 50000)
        fix_encoding = config.get("fix_encoding", True)
        standardize = config.get("standardize", True)

        cleaned = []
        for item in current_data:
            result_item, meta = self._cleaner.full_clean(
                item,
                min_length=min_length,
                max_length=max_length,
                fix_encoding=fix_encoding,
                standardize=standardize,
            )
            if result_item is not None:
                result_item["_clean_meta"] = meta
                cleaned.append(result_item)

        if dedup:
            unique, duplicates = self._cleaner.batch_deduplicate(cleaned)
            for item in unique:
                item["_dedup_checked"] = True
            for item in duplicates:
                item["_is_duplicate"] = True
                item["_duplicate_of"] = item.get("duplicate_of", "")
            cleaned = unique

        return cleaned

    async def _execute_label(
        self, config: Dict, current_data: List[Dict]
    ) -> List[Dict]:
        annotation_type = config.get("annotation_type", "threat_classification")
        categories = config.get("categories")
        auto_annotate = config.get("auto_annotate", True)
        use_llm_annotator = config.get("use_llm_annotator", False)
        batch_size = config.get("batch_size", 10)

        if not auto_annotate:
            return current_data

        if use_llm_annotator:
            return await self._llm_annotator.batch_annotate(
                current_data, annotation_type, categories, batch_size
            )

        for item in current_data:
            content = item.get("content", "")
            if content:
                annotation = await self._annotator.auto_annotate(
                    content, annotation_type, categories
                )
                item["_annotation"] = annotation
                if annotation.get("label"):
                    item["threat_level"] = annotation["label"]

        return current_data

    async def _execute_augment(
        self, config: Dict, current_data: List[Dict]
    ) -> List[Dict]:
        method = config.get("method", "paraphrase")
        count = config.get("count", 2)
        max_items = config.get("max_items", 50)

        if not self._llm and method in ("paraphrase", "back_translation"):
            logger.info(f"LLM未配置，跳过{method}增强")
            return current_data

        items_to_augment = current_data[:max_items]
        augmented = []

        for item in items_to_augment:
            content = item.get("content", "")
            if not content:
                continue
            results = await self._augmentor.augment(content, method, count)
            for aug_result in results:
                if aug_result.get("augmented"):
                    aug_item = dict(item)
                    aug_item["content"] = aug_result["text"]
                    aug_item["_augmented"] = True
                    aug_item["_augment_method"] = method
                    augmented.append(aug_item)

        return current_data + augmented

    async def _execute_convert(
        self, config: Dict, current_data: List[Dict]
    ) -> List[Dict]:
        target_format = config.get("target_format", "jsonl")
        field_mapping = config.get("field_mapping")
        auto_detect = config.get("auto_detect", False)
        incremental = config.get("incremental", False)
        existing_content = config.get("existing_content", "")

        if incremental and existing_content:
            output, meta = self._converter.incremental_convert(
                current_data, existing_content, target_format, field_mapping
            )
        elif auto_detect:
            if current_data and isinstance(current_data[0].get("content"), str):
                content = current_data[0]["content"]
                output, meta = self._converter.convert_auto(content, target_format, field_mapping)
            else:
                output, meta = self._converter.convert(
                    current_data, "json", target_format, field_mapping
                )
        else:
            output, meta = self._converter.convert(
                current_data, "json", target_format, field_mapping
            )

        if output:
            return [{"content": output, "_format": target_format, "_conversion_meta": meta}]

        return current_data

    def get_execution(self, pipeline_id: str) -> Optional[PipelineExecution]:
        return self._active_executions.get(pipeline_id)

    def get_active_execution_count(self) -> int:
        return len(self._active_executions)

    def cancel_execution(self, pipeline_id: str) -> bool:
        execution = self._active_executions.get(pipeline_id)
        if execution and execution.status == StepStatus.RUNNING:
            execution.status = StepStatus.FAILED
            execution.error_message = "用户取消"
            return True
        return False

    def _execute_filter(
        self, config: Dict, current_data: List[Dict]
    ) -> List[Dict]:
        field = config.get("field", "threat_level")
        operator = config.get("operator", "in")
        value = config.get("value", [])

        filtered = []
        for item in current_data:
            item_val = item.get(field)
            if operator == "in" and item_val in value:
                filtered.append(item)
            elif operator == "not_in" and item_val not in value:
                filtered.append(item)
            elif operator == "equals" and item_val == value:
                filtered.append(item)
            elif operator == "not_equals" and item_val != value:
                filtered.append(item)
            elif operator == "contains" and isinstance(item_val, str) and value in item_val:
                filtered.append(item)
            elif operator == "gte" and item_val is not None and item_val >= value:
                filtered.append(item)
            elif operator == "lte" and item_val is not None and item_val <= value:
                filtered.append(item)
            elif operator == "exists" and item_val is not None:
                filtered.append(item)
            elif operator == "not_exists" and item_val is None:
                filtered.append(item)

        return filtered

    async def _execute_conditional(
        self,
        config: Dict,
        current_data: List[Dict],
        all_steps: List[Dict],
        current_index: int,
    ) -> List[Dict]:
        condition_field = config.get("condition_field", "threat_level")
        condition_value = config.get("condition_value")
        then_steps = config.get("then_steps", [])
        else_steps = config.get("else_steps", [])

        matched_count = sum(1 for item in current_data if item.get(condition_field) == condition_value)

        if matched_count > len(current_data) * 0.5:
            steps_to_run = then_steps
        else:
            steps_to_run = else_steps

        if not steps_to_run:
            return current_data

        for sub_step in steps_to_run:
            sub_type = sub_step.get("step_type", "")
            sub_config = sub_step.get("config", {})

            ALLOWED_CONDITIONAL_STEPS = {"clean", "label", "augment", "filter", "format_convert"}
            if sub_type not in ALLOWED_CONDITIONAL_STEPS:
                continue

            if sub_type == "clean":
                current_data = await self._execute_clean(sub_config, current_data)
            elif sub_type == "label":
                current_data = await self._execute_label(sub_config, current_data)
            elif sub_type == "augment":
                current_data = await self._execute_augment(sub_config, current_data)
            elif sub_type == "filter":
                current_data = self._execute_filter(sub_config, current_data)
            elif sub_type == "format_convert":
                current_data = await self._execute_convert(sub_config, current_data)

        return current_data

    def _execute_merge(
        self, config: Dict, current_data: List[Dict]
    ) -> List[Dict]:
        merge_field = config.get("merge_field", "id")
        strategy = config.get("strategy", "deduplicate")

        if strategy == "deduplicate":
            seen = set()
            result = []
            for item in current_data:
                key = item.get(merge_field, "")
                if key not in seen:
                    seen.add(key)
                    result.append(item)
            return result
        elif strategy == "concat":
            return current_data
        elif strategy == "latest":
            grouped = defaultdict(list)
            for item in current_data:
                key = item.get(merge_field, "")
                grouped[key].append(item)
            result = []
            for key, items in grouped.items():
                items.sort(key=lambda x: x.get("updated_at", x.get("created_at", "")), reverse=True)
                result.append(items[0])
            return result

        return current_data

    def _execute_sample(
        self, config: Dict, current_data: List[Dict]
    ) -> List[Dict]:
        sample_size = config.get("size", 100)
        method = config.get("method", "random")
        seed = config.get("seed", 42)

        if method == "random":
            import random
            rng = random.Random(seed)
            return rng.sample(current_data, min(sample_size, len(current_data)))
        elif method == "stratified":
            stratify_field = config.get("stratify_field", "threat_level")
            groups = defaultdict(list)
            for item in current_data:
                key = item.get(stratify_field, "unknown")
                groups[key].append(item)

            per_group = max(1, sample_size // max(len(groups), 1))
            result = []
            import random
            rng = random.Random(seed)
            for key, items in groups.items():
                result.extend(rng.sample(items, min(per_group, len(items))))
            return result[:sample_size]
        elif method == "first":
            return current_data[:sample_size]
        elif method == "last":
            return current_data[-sample_size:]

        return current_data
