import asyncio
import hashlib
import json
import re
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from loguru import logger
from sqlalchemy.exc import OperationalError

from app.core.threat_intel_service import THREAT_CATEGORIES


class PipelineStage(str, Enum):
    INGEST = "ingest"
    CLEAN = "clean"
    DEDUP = "dedup"
    CLASSIFY = "classify"
    EXTRACT = "extract"
    RISK_SCORE = "risk_score"
    PATTERN_ANALYZE = "pattern_analyze"
    CHAIN_ANALYZE = "chain_analyze"
    STORE = "store"
    ALERT = "alert"
    REPORT = "report"


class IntentLevel(str, Enum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    CRITICAL = "critical"


STAGE_ORDER = [
    PipelineStage.INGEST,
    PipelineStage.CLEAN,
    PipelineStage.DEDUP,
    PipelineStage.CLASSIFY,
    PipelineStage.EXTRACT,
    PipelineStage.RISK_SCORE,
    PipelineStage.PATTERN_ANALYZE,
    PipelineStage.CHAIN_ANALYZE,
    PipelineStage.STORE,
    PipelineStage.ALERT,
    PipelineStage.REPORT,
]

CHEATING_SCENARIOS = {
    "exam_cheating": {
        "label": "考试作弊",
        "keywords": ["代考", "替考", "枪手", "作弊器", "隐形耳机", "考试答案", "题库泄露", "考前答案", "包过"],
        "severity": "high",
    },
    "thesis_mill": {
        "label": "论文代写",
        "keywords": ["代写论文", "论文代发", "代写毕业", "论文枪手", "代写硕士", "代写博士", "查重降重"],
        "severity": "high",
    },
    "credential_forgery": {
        "label": "证件造假",
        "keywords": ["办证", "假证", "伪造", "仿制证书", "学历造假", "假文凭", "刻章"],
        "severity": "critical",
    },
    "brush_order": {
        "label": "刷单炒信",
        "keywords": ["刷单", "刷好评", "刷销量", "刷信誉", "水军", "控评", "刷流量"],
        "severity": "medium",
    },
    "coupon_fraud": {
        "label": "薅羊毛",
        "keywords": ["薅羊毛", "漏洞券", "批量注册", "新用户优惠", "黑产羊毛", "套利"],
        "severity": "medium",
    },
    "account_trading": {
        "label": "账号交易",
        "keywords": ["卖号", "买号", "账号转让", "成品号", "白号", "老号", "实名号"],
        "severity": "high",
    },
    "traffic_fraud": {
        "label": "流量造假",
        "keywords": ["刷量", "假流量", "刷播放", "刷粉丝", "刷点赞", "引流", "色流"],
        "severity": "medium",
    },
    "platform_exploit": {
        "label": "平台漏洞利用",
        "keywords": ["漏洞利用", "绕过", "破解", "外挂", "辅助脚本", "自动化工具", "接口滥用"],
        "severity": "critical",
    },
    "malware_attack": {
        "label": "恶意软件攻击",
        "keywords": ["勒索", "勒索软件", "木马", "后门", "远控", "RAT", "Ransomware", "僵尸网络", "botnet", "挖矿", "恶意程序", "恶意软件"],
        "severity": "critical",
    },
    "underground_economy": {
        "label": "地下经济",
        "keywords": ["跑分", "洗钱", "套现", "四件套", "八件套", "接单", "代收", "代付", "走账", "对公", "实名认证", "猫池", "GOIP", "接码"],
        "severity": "critical",
    },
}

HIGH_RISK_INTENT_PATTERNS = {
    "direct_solicitation": {
        "label": "直接招揽",
        "indicators": ["出售", "出售中", "接单", "长期接", "价格面议", "私聊", "VX", "TG联系", "有偿", "代办", "代考", "代写", "代做", "包过", "办证", "刻章", "办卡"],
        "weight": 0.3,
    },
    "tool_distribution": {
        "label": "工具传播",
        "indicators": ["下载", "免费分享", "破解版", "绿色版", "安装包", "教程", "使用说明", "接码平台", "猫池", "GOIP"],
        "weight": 0.25,
    },
    "service_advertising": {
        "label": "服务推广",
        "indicators": ["专业团队", "包教包会", "售后保障", "长期合作", "量大从优", "一手货源", "跑分", "洗钱", "套现", "提现", "代收", "代付", "走账", "对公", "四件套", "八件套", "实名认证"],
        "weight": 0.3,
    },
    "evidence_of_operation": {
        "label": "运营痕迹",
        "indicators": ["客户反馈", "成功案例", "到账截图", "收益截图", "提现记录", "交易记录"],
        "weight": 0.25,
    },
    "malware_distribution": {
        "label": "恶意软件传播",
        "indicators": ["勒索软件", "木马", "后门", "RAT", "远控", "Ransomware", "恶意程序", "挖矿", "botnet", "僵尸网络"],
        "weight": 0.35,
    },
    "cheating_service": {
        "label": "作弊服务",
        "indicators": ["刷单", "炒信", "刷评", "刷量", "水军", "控评", "刷粉", "涨粉", "互推", "互刷"],
        "weight": 0.3,
    },
}

CRYPTO_PATTERNS = {
    "btc": re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'),
    "eth": re.compile(r'\b0x[a-fA-F0-9]{40}\b'),
    "tron": re.compile(r'\bT[A-Za-z1-9]{33}\b'),
    "bch": re.compile(r'\b(q|p)[a-z0-9]{41}\b'),
    "xmr": re.compile(r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b'),
}

ACCOUNT_PATTERNS_EXTENDED = {
    "telegram": re.compile(r'@[\w]{5,32}|t\.me/[\w]+'),
    "wechat": re.compile(r'(?:微信|vx|VX|WeChat|wechat)[：:\s]*([a-zA-Z0-9_-]{6,20})|(wxid_[a-zA-Z0-9_]+)'),
    "qq": re.compile(r'(?:QQ|qq)[：:\s]*(\d{5,12})'),
    "phone": re.compile(r'(?:电话|手机|tel|phone)[：:\s]*(1[3-9]\d{9})'),
    "email": re.compile(r'\b[\w.-]+@[\w.-]+\.\w+\b'),
    "discord": re.compile(r'discord\.gg/[\w]+|Discord[：:]\s*[\w#]+'),
    "skype": re.compile(r'(?:Skype|skype)[：:]\s*[\w.-]+'),
    "whatsapp": re.compile(r'(?:WhatsApp|whatsapp)[：:]\s*\+?\d{10,15}'),
    "twitter": re.compile(r'twitter\.com/[\w]+|@[\w]{4,15}(?=\s|$)'),
    "github": re.compile(r'github\.com/[\w-]+'),
}

TOOL_PATTERNS_EXTENDED = [
    (re.compile(r'(远控|RAT|木马|后门|抓鸡|提权|扫描器|爆破工具|黑页|webshell)', re.IGNORECASE), "远程控制/后门"),
    (re.compile(r'(猫池|GOIP|短信机|验证码接收|接码平台|群控)', re.IGNORECASE), "通信设备/接码"),
    (re.compile(r'(洗钱工具|跑分平台|虚拟币[\s]*mixer|tumbler|混币器)', re.IGNORECASE), "洗钱工具"),
    (re.compile(r'(四件套|银行卡|U盾|实名认证|人脸识别[\s]*绕过)', re.IGNORECASE), "身份伪造工具"),
    (re.compile(r'(钓鱼[\s]*工具|钓鱼[\s]*页面|仿冒[\s]*网站|克隆[\s]*页面)', re.IGNORECASE), "钓鱼工具"),
    (re.compile(r'(勒索[\s]*软件|加密[\s]*锁定|ransomware)', re.IGNORECASE), "勒索软件"),
    (re.compile(r'(DDoS[\s]*工具|压力测试|CC攻击|流量攻击)', re.IGNORECASE), "DDoS攻击工具"),
    (re.compile(r'(社工库|撞库|拖库|数据[\s]*清洗|数据[\s]*脱敏)', re.IGNORECASE), "数据窃取工具"),
    (re.compile(r'(养号|批量注册|自动注册|号商|白号|老号)', re.IGNORECASE), "养号工具"),
    (re.compile(r'(外挂|辅助|脚本|自动化|挂机|刷量)', re.IGNORECASE), "作弊外挂"),
]

SLANG_DICTIONARY_EXTENDED = {
    "跑分": "为诈骗团伙转移资金的中间人/洗钱通道",
    "四件套": "身份证+银行卡+手机卡+U盾的合称",
    "杀猪盘": "长期培养感情后实施诈骗的模式",
    "料子": "被盗的个人信息数据",
    "水房": "专门负责洗钱的环节/团队",
    "车手": "负责取现的底层人员",
    "猫池": "可同时操控多张SIM卡的设备",
    "接码": "接收验证码的服务",
    "养号": "批量培育账号提高权重",
    "黑料": "非法获取的个人隐私数据",
    "卡商": "银行卡贩卖者",
    "料商": "数据贩卖者",
    "马仔": "底层执行者",
    "菠菜": "网络赌博(谐音)",
    "色流": "色情内容引流",
    "引流": "为黑产输送用户/流量",
    "肉鸡": "被控制的僵尸主机",
    "黑卡": "非法银行卡/信用卡",
    "话术": "诈骗话术模板",
    "资金盘": "庞氏骗局/资金盘",
    "套路贷": "欺诈性贷款",
    "裸贷": "以裸照抵押的借贷",
    "薅羊毛": "利用规则漏洞获取利益",
    "刷单": "虚假交易提升信誉",
    "白号": "新注册未实名的账号",
    "老号": "注册时间长、权重高的账号",
    "一手": "直接来源、未经转手",
    "出货": "出售非法数据/账号",
    "收料": "收购非法数据",
    "洗料": "对非法数据进行整理加工",
    "开料": "使用非法数据进行操作",
    "通道": "支付/资金转移渠道",
    "码商": "提供验证码服务的商家",
    "号商": "批量贩卖账号的商家",
    "档口": "黑产交易摊位/渠道",
    "盘口": "赌博下注平台",
    "上线": "黑产链条中的上级",
    "下线": "黑产链条中的下级",
    "代理": "黑产服务的分销商",
    "分润": "利益分成",
    "对公": "对公账户(用于大额洗钱)",
    "私对私": "个人间转账",
    "公对私": "对公转个人",
    "走账": "通过账户进行资金流转",
    "断卡": "打击银行卡/电话卡黑产行动",
}


@dataclass
class PipelineItemResult:
    item_id: str
    source: str
    stage: str
    status: str
    original_content: str = ""
    cleaned_content: str = ""
    is_duplicate: bool = False
    duplicate_of: str = ""
    threat_categories: List[Dict] = field(default_factory=list)
    intent_level: str = IntentLevel.BENIGN.value
    intent_indicators: List[str] = field(default_factory=list)
    cheating_scenarios: List[Dict] = field(default_factory=list)
    entities: List[Dict] = field(default_factory=list)
    risk_score: float = 0.0
    crime_patterns: List[Dict] = field(default_factory=list)
    tech_chains: List[Dict] = field(default_factory=list)
    summary: str = ""
    quality_score: float = 0.0
    processing_time_ms: float = 0.0
    error: str = ""

    def to_dict(self) -> Dict:
        return {
            "item_id": self.item_id,
            "source": self.source,
            "stage": self.stage,
            "status": self.status,
            "original_content": self.original_content[:500] if self.original_content else "",
            "cleaned_content": self.cleaned_content[:500] if self.cleaned_content else "",
            "is_duplicate": self.is_duplicate,
            "duplicate_of": self.duplicate_of,
            "threat_categories": self.threat_categories,
            "intent_level": self.intent_level,
            "intent_indicators": self.intent_indicators,
            "cheating_scenarios": self.cheating_scenarios,
            "entities": self.entities,
            "risk_score": round(self.risk_score, 4),
            "crime_patterns": self.crime_patterns,
            "tech_chains": self.tech_chains,
            "summary": self.summary,
            "quality_score": round(self.quality_score, 4),
            "processing_time_ms": round(self.processing_time_ms, 2),
            "error": self.error,
        }


@dataclass
class PipelineBatchResult:
    batch_id: str
    total_input: int = 0
    total_processed: int = 0
    total_duplicates: int = 0
    total_high_risk: int = 0
    total_critical: int = 0
    by_source: Dict[str, int] = field(default_factory=dict)
    by_intent: Dict[str, int] = field(default_factory=dict)
    by_category: Dict[str, int] = field(default_factory=dict)
    item_results: List[PipelineItemResult] = field(default_factory=list)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    total_time_ms: float = 0.0

    def to_dict(self) -> Dict:
        return {
            "batch_id": self.batch_id,
            "total_input": self.total_input,
            "total_processed": self.total_processed,
            "total_duplicates": self.total_duplicates,
            "total_high_risk": self.total_high_risk,
            "total_critical": self.total_critical,
            "by_source": self.by_source,
            "by_intent": self.by_intent,
            "by_category": self.by_category,
            "item_results": [r.to_dict() for r in self.item_results],
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "total_time_ms": round(self.total_time_ms, 2),
        }


class TextCleaner:
    def __init__(self):
        self._noise_patterns = [
            (re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]'), ''),
            (re.compile(r'[\ufeff\u200b\u200c\u200d]'), ''),
            (re.compile(r'(.)\1{4,}'), r'\1\1\1'),
            (re.compile(r'\s+'), ' '),
        ]
        self._ad_patterns = [
            re.compile(r'(加[\s]*VX|加[\s]*微信|加[\s]*QQ|扫码[\s]*关注)[\s：:]*[\w-]+'),
            re.compile(r'(关注[\s]*公众号|回复[\s]*关键字|点击[\s]*链接)[\s：:]*[\w-]+'),
        ]

    def clean(self, text: str) -> Tuple[str, Dict[str, Any]]:
        if not text:
            return "", {"original_length": 0, "cleaned_length": 0, "operations": []}

        operations = []
        original_len = len(text)
        cleaned = text.strip()

        for pattern, replacement in self._noise_patterns:
            before = len(cleaned)
            cleaned = pattern.sub(replacement, cleaned)
            if len(cleaned) != before:
                operations.append(f"noise_removal_{before - len(cleaned)}")

        ad_count = 0
        for ad_pat in self._ad_patterns:
            matches = ad_pat.findall(cleaned)
            ad_count += len(matches)
        if ad_count > 0:
            operations.append(f"ad_detected_{ad_count}")

        cleaned = cleaned.strip()
        return cleaned, {
            "original_length": original_len,
            "cleaned_length": len(cleaned),
            "operations": operations,
            "ad_count": ad_count,
        }


class PersistentDeduplicator:
    def __init__(self, similarity_threshold: float = 0.92, max_cache: int = 50000):
        self._similarity_threshold = similarity_threshold
        self._max_cache = max_cache
        self._content_hashes: Dict[str, str] = {}
        self._minhash_sigs: Dict[str, List[int]] = {}
        self._num_perm = 128
        self._source_index: Dict[str, List[str]] = defaultdict(list)
        self._buckets: Dict[str, List[str]] = defaultdict(list)
        self._lock = asyncio.Lock()
        self._max_content_entries = 50000

    def _compute_content_hash(self, text: str) -> str:
        normalized = re.sub(r'\s+', '', text.lower())
        return hashlib.sha256(normalized.encode()).hexdigest()

    def _compute_minhash(self, text: str) -> List[int]:
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

    def _estimate_similarity(self, sig_a: List[int], sig_b: List[int]) -> float:
        if not sig_a or not sig_b or len(sig_a) != len(sig_b):
            return 0.0
        matches = sum(1 for a, b in zip(sig_a, sig_b) if a == b)
        return matches / len(sig_a)

    def check_duplicate(self, text: str, source: str = "", doc_id: str = "") -> Tuple[bool, str, float]:
        content_hash = self._compute_content_hash(text)

        if content_hash in self._content_hashes:
            existing_doc_id = self._content_hashes.pop(content_hash)
            self._content_hashes[content_hash] = existing_doc_id
            return True, existing_doc_id, 1.0

        minhash_sig = self._compute_minhash(text)

        best_match_id = ""
        best_similarity = 0.0

        bucket_key = content_hash[:2]
        search_pool = list(self._buckets.get(bucket_key, []))
        if source and source in self._source_index:
            priority_ids = [sid for sid in self._source_index[source] if sid in self._minhash_sigs]
            other_ids = [sid for sid in search_pool if sid not in set(priority_ids)]
            search_pool = priority_ids + other_ids

        for existing_id in search_pool:
            if existing_id not in self._minhash_sigs:
                continue
            sim = self._estimate_similarity(minhash_sig, self._minhash_sigs[existing_id])
            if sim > best_similarity:
                best_similarity = sim
                best_match_id = existing_id

        if best_similarity >= self._similarity_threshold:
            return True, best_match_id, best_similarity

        doc_id = doc_id or content_hash[:16]
        self._content_hashes[content_hash] = doc_id
        self._minhash_sigs[doc_id] = minhash_sig
        if source:
            self._source_index[source].append(doc_id)
        self._buckets[bucket_key].append(doc_id)

        if len(self._content_hashes) > self._max_content_entries:
            self._content_hashes.clear()
            self._minhash_sigs.clear()
            self._source_index.clear()
            self._buckets.clear()

        while len(self._content_hashes) > self._max_cache:
            oldest_hash = next(iter(self._content_hashes))
            evicted_doc_id = self._content_hashes.pop(oldest_hash)
            if evicted_doc_id in self._minhash_sigs:
                del self._minhash_sigs[evicted_doc_id]
            evicted_bucket = oldest_hash[:2]
            if evicted_bucket in self._buckets:
                self._buckets[evicted_bucket] = [
                    sid for sid in self._buckets[evicted_bucket] if sid != evicted_doc_id
                ]
            for src_list in self._source_index.values():
                if evicted_doc_id in src_list:
                    src_list.remove(evicted_doc_id)

        return False, "", best_similarity

    async def batch_deduplicate(self, items: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
        async with self._lock:
            unique = []
            duplicates = []
            for item in items:
                text = item.get("content", "")
                source = item.get("source", "")
                doc_id = item.get("id", hashlib.md5(text.encode()).hexdigest()[:16])
                is_dup, dup_of, similarity = self.check_duplicate(text, source, doc_id)
                if is_dup:
                    item["_is_duplicate"] = True
                    item["_duplicate_of"] = dup_of
                    item["_similarity"] = similarity
                    duplicates.append(item)
                else:
                    item["_dedup_checked"] = True
                    unique.append(item)
            return unique, duplicates

    def get_stats(self) -> Dict:
        return {
            "total_documents": len(self._content_hashes),
            "total_sources": len(self._source_index),
            "cache_utilization": len(self._content_hashes) / self._max_cache,
        }


class EnhancedThreatClassifier:
    def __init__(self, llm_service=None):
        self._llm = llm_service
        self._categories = THREAT_CATEGORIES
        self._cheating_scenarios = CHEATING_SCENARIOS
        self._intent_patterns = HIGH_RISK_INTENT_PATTERNS

    async def classify(self, text: str, use_llm: bool = True) -> Dict[str, Any]:
        rule_result = self._rule_based_classify(text)
        intent_result = self._classify_intent(text)
        cheating_result = self._detect_cheating_scenarios(text)

        if use_llm and self._llm and rule_result.get("confidence", 0) < 0.85:
            try:
                llm_result = await self._llm_classify(text)
                if llm_result.get("confidence", 0) > rule_result.get("confidence", 0):
                    rule_result = llm_result
            except Exception as exc:
                logger.warning(f"LLM分类降级到规则: {exc}")

        rule_result["intent_level"] = intent_result["intent_level"]
        rule_result["intent_indicators"] = intent_result["indicators"]
        rule_result["intent_confidence"] = intent_result["confidence"]
        rule_result["cheating_scenarios"] = cheating_result

        return rule_result

    def _rule_based_classify(self, text: str) -> Dict:
        text_lower = text.lower()
        results = []

        for cat_key, cat_info in self._categories.items():
            matched = [kw for kw in cat_info["keywords"] if kw.lower() in text_lower]
            if matched:
                score = len(matched) / len(cat_info["keywords"])
                results.append({
                    "category": cat_key,
                    "category_label": cat_info["label"],
                    "threat_level": cat_info["level"],
                    "confidence": min(1.0, 0.4 + score * 0.6),
                    "matched_keywords": matched,
                    "reasoning": f"匹配到{cat_key}类威胁关键词: {', '.join(matched)}",
                })

        if not results:
            return {
                "category": "unknown",
                "category_label": "未分类",
                "threat_level": "info",
                "confidence": 0.0,
                "matched_keywords": [],
                "reasoning": "未匹配到已知威胁类别",
            }

        results.sort(key=lambda x: x["confidence"], reverse=True)
        primary = results[0].copy()
        other_categories = []
        for r in results[1:]:
            other_categories.append({
                "category": r["category"],
                "category_label": r["category_label"],
                "threat_level": r["threat_level"],
                "confidence": r["confidence"],
            })
        primary["all_categories"] = [
            {
                "category": primary["category"],
                "category_label": primary["category_label"],
                "threat_level": primary["threat_level"],
                "confidence": primary["confidence"],
            }
        ] + other_categories
        return primary

    def _classify_intent(self, text: str) -> Dict:
        text_lower = text.lower()
        total_weight = 0.0
        matched_indicators = []

        for pattern_key, pattern_info in self._intent_patterns.items():
            for indicator in pattern_info["indicators"]:
                if indicator.lower() in text_lower:
                    total_weight += pattern_info["weight"]
                    matched_indicators.append(f"{pattern_info['label']}: {indicator}")
                    break

        if total_weight >= 0.5:
            intent_level = IntentLevel.CRITICAL.value
        elif total_weight >= 0.3:
            intent_level = IntentLevel.MALICIOUS.value
        elif total_weight >= 0.15:
            intent_level = IntentLevel.SUSPICIOUS.value
        else:
            intent_level = IntentLevel.BENIGN.value

        return {
            "intent_level": intent_level,
            "confidence": min(1.0, total_weight * 2),
            "indicators": matched_indicators,
            "total_weight": round(total_weight, 4),
        }

    def _detect_cheating_scenarios(self, text: str) -> List[Dict]:
        text_lower = text.lower()
        detected = []

        for scenario_key, scenario_info in self._cheating_scenarios.items():
            matched = [kw for kw in scenario_info["keywords"] if kw.lower() in text_lower]
            if matched:
                detected.append({
                    "scenario": scenario_key,
                    "label": scenario_info["label"],
                    "severity": scenario_info["severity"],
                    "matched_keywords": matched,
                    "confidence": min(1.0, len(matched) / len(scenario_info["keywords"]) + 0.3),
                })

        return detected

    async def _llm_classify(self, text: str) -> Dict:
        categories_desc = "\n".join([f"- {k}: {v['label']}({v['level']}级)" for k, v in self._categories.items()])
        cheating_desc = "\n".join([f"- {k}: {v['label']}({v['severity']}级)" for k, v in self._cheating_scenarios.items()])

        prompt = (
            f"请对以下黑灰产情报文本进行威胁分类和高危意图判断：\n\n"
            f"威胁类别:\n{categories_desc}\n\n"
            f"作弊场景:\n{cheating_desc}\n\n"
            f"情报文本:\n{text[:1500]}\n\n"
            f"请以JSON格式返回: {{\"category\": \"类别key\", \"threat_level\": \"critical/high/medium/low/info\", "
            f"\"confidence\": 0.0-1.0, \"reasoning\": \"分类理由\", "
            f"\"intent_level\": \"benign/suspicious/malicious/critical\", "
            f"\"cheating_scenarios\": [\"场景key1\", \"场景key2\"]}}"
        )
        try:
            response = await self._llm.chat(prompt)
            llm_text = response if isinstance(response, str) else str(response)
            json_match = re.search(r'\{[^}]+\}', llm_text)
            if json_match:
                parsed = json.loads(json_match.group())
                cat = parsed.get("category", "unknown")
                cat_info = self._categories.get(cat, {})
                return {
                    "category": cat,
                    "category_label": cat_info.get("label", parsed.get("category", "未知")),
                    "threat_level": parsed.get("threat_level", "medium"),
                    "confidence": min(1.0, max(0.0, float(parsed.get("confidence", 0.5)))),
                    "matched_keywords": [],
                    "reasoning": parsed.get("reasoning", ""),
                }
        except Exception as exc:
            logger.warning(f"LLM分类失败: {exc}")

        return self._rule_based_classify(text)


class EnhancedEntityExtractor:
    def __init__(self, llm_service=None):
        self._llm = llm_service
        self._slang_dict = SLANG_DICTIONARY_EXTENDED
        self._crypto_patterns = CRYPTO_PATTERNS
        self._account_patterns = ACCOUNT_PATTERNS_EXTENDED
        self._tool_patterns_extended = TOOL_PATTERNS_EXTENDED

    async def extract(self, text: str, use_llm: bool = True) -> List[Dict]:
        entities = []
        entities.extend(self._extract_urls(text))
        entities.extend(self._extract_accounts(text))
        entities.extend(self._extract_crypto(text))
        entities.extend(self._extract_tools(text))
        entities.extend(self._extract_slang(text))
        entities.extend(self._extract_contact_info(text))
        entities.extend(self._extract_organizations(text))

        if use_llm and self._llm:
            try:
                llm_entities = await self._llm_extract(text)
                existing_values = {e.get("value", "") for e in entities}
                for e in llm_entities:
                    if e.get("value", "") not in existing_values:
                        entities.append(e)
                        existing_values.add(e["value"])
            except Exception as exc:
                logger.warning(f"LLM实体抽取降级: {exc}")

        return entities

    def _extract_urls(self, text: str) -> List[Dict]:
        url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
        entities = []
        for url in url_pattern.findall(text):
            is_suspicious = any(d in url.lower() for d in [".onion", ".tk", ".ml", ".ga", ".cf", "temp", "throwaway", "pastebin"])
            is_c2 = any(d in url.lower() for d in ["panel", "gate", "admin", "cmd", "c2", "beacon"])
            entities.append({
                "entity_type": "url",
                "entity_label": "恶意链接" if (is_suspicious or is_c2) else "链接",
                "value": url,
                "context": text[max(0, text.find(url) - 30):text.find(url) + len(url) + 30],
                "confidence": 0.95 if is_c2 else (0.9 if is_suspicious else 0.6),
                "metadata": {"is_suspicious": is_suspicious, "is_c2": is_c2},
            })
        return entities

    def _extract_accounts(self, text: str) -> List[Dict]:
        entities = []
        for platform, pattern in self._account_patterns.items():
            for match in pattern.findall(text):
                if isinstance(match, tuple):
                    match = match[0] if match[0] else (match[1] if len(match) > 1 else str(match))
                if not match:
                    continue
                entities.append({
                    "entity_type": "account",
                    "entity_label": f"{platform}账号",
                    "value": match,
                    "context": text[max(0, text.find(match) - 30):text.find(match) + len(match) + 30],
                    "confidence": 0.85,
                    "metadata": {"platform": platform},
                })
        return entities

    def _extract_crypto(self, text: str) -> List[Dict]:
        entities = []
        for crypto_type, pattern in self._crypto_patterns.items():
            for match in pattern.findall(text):
                entities.append({
                    "entity_type": "crypto_address",
                    "entity_label": f"{crypto_type.upper()}地址",
                    "value": match,
                    "context": text[max(0, text.find(match) - 30):text.find(match) + len(match) + 30],
                    "confidence": 0.9,
                    "metadata": {"crypto_type": crypto_type},
                })
        return entities

    def _extract_tools(self, text: str) -> List[Dict]:
        entities = []
        for pattern, tool_category in self._tool_patterns_extended:
            for match in pattern.findall(text):
                entities.append({
                    "entity_type": "tool",
                    "entity_label": f"作案工具({tool_category})",
                    "value": match,
                    "context": text[max(0, text.find(match) - 30):text.find(match) + len(match) + 30],
                    "confidence": 0.75,
                    "metadata": {"tool_category": tool_category},
                })
        return entities

    def _extract_slang(self, text: str) -> List[Dict]:
        entities = []
        for slang, meaning in self._slang_dict.items():
            if slang in text:
                entities.append({
                    "entity_type": "slang",
                    "entity_label": "黑话术语",
                    "value": slang,
                    "context": text[max(0, text.find(slang) - 30):text.find(slang) + len(slang) + 30],
                    "confidence": 0.92,
                    "metadata": {"meaning": meaning},
                })
        return entities

    def _extract_contact_info(self, text: str) -> List[Dict]:
        entities = []
        ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
        email_pattern = re.compile(r'\b[\w.-]+@[\w.-]+\.\w+\b')
        phone_pattern = re.compile(r'\b1[3-9]\d{9}\b')

        for ip in ip_pattern.findall(text):
            if not ip.startswith(("192.168.", "10.", "172.16.", "127.0")):
                entities.append({
                    "entity_type": "ip",
                    "entity_label": "IP地址",
                    "value": ip,
                    "context": text[max(0, text.find(ip) - 20):text.find(ip) + len(ip) + 20],
                    "confidence": 0.7,
                    "metadata": {"type": "ip"},
                })

        for email in email_pattern.findall(text):
            entities.append({
                "entity_type": "email",
                "entity_label": "邮箱地址",
                "value": email,
                "context": text[max(0, text.find(email) - 20):text.find(email) + len(email) + 20],
                "confidence": 0.7,
                "metadata": {"type": "email"},
            })

        for phone in phone_pattern.findall(text):
            entities.append({
                "entity_type": "phone",
                "entity_label": "手机号",
                "value": phone,
                "context": text[max(0, text.find(phone) - 20):text.find(phone) + len(phone) + 20],
                "confidence": 0.75,
                "metadata": {"type": "phone"},
            })

        return entities

    def _extract_organizations(self, text: str) -> List[Dict]:
        entities = []
        org_patterns = [
            (re.compile(r'(团伙|组织|团队|工作室|公司|集团)[\s]*[：:]*[\s]*[\u4e00-\u9fff]{2,10}'), "黑产组织"),
            (re.compile(r'[\u4e00-\u9fff]{2,6}[\s]*(团伙|组织|团队|工作室|集团)'), "黑产组织"),
        ]
        for pattern, org_type in org_patterns:
            for match in pattern.findall(text):
                if isinstance(match, tuple):
                    match = match[0] + match[1] if len(match) > 1 else match[0]
                if len(match) > 2:
                    entities.append({
                        "entity_type": "organization",
                        "entity_label": org_type,
                        "value": match,
                        "context": text[max(0, text.find(match) - 20):text.find(match) + len(match) + 20],
                        "confidence": 0.6,
                        "metadata": {"type": org_type},
                    })
        return entities

    async def _llm_extract(self, text: str) -> List[Dict]:
        entity_types_desc = (
            "slang:黑话术语, url:恶意链接, account:黑产账号, tool:作案工具, "
            "organization:黑产组织, technique:作案手法, target:攻击目标, "
            "channel:传播渠道, crypto_address:加密货币地址, ip:IP地址, "
            "phone:手机号, email:邮箱地址"
        )
        prompt = (
            f"请从以下黑灰产情报文本中抽取关键实体：\n\n"
            f"实体类型:\n{entity_types_desc}\n\n"
            f"文本:\n{text[:1500]}\n\n"
            f"请以JSON数组格式返回: [{{\"entity_type\": \"实体类型\", \"value\": \"实体值\", "
            f"\"context\": \"上下文片段\", \"confidence\": 0.0-1.0, \"metadata\": {{}}}}]"
        )
        try:
            response = await self._llm.chat(prompt)
            llm_text = response if isinstance(response, str) else str(response)
            entities = []
            json_match = re.search(r'\[[\s\S]*?\]', llm_text)
            if json_match:
                parsed = json.loads(json_match.group())
                for item in parsed[:25]:
                    entities.append({
                        "entity_type": item.get("entity_type", "slang"),
                        "entity_label": item.get("entity_type", "slang"),
                        "value": item.get("value", ""),
                        "context": item.get("context", ""),
                        "confidence": min(1.0, max(0.0, float(item.get("confidence", 0.5)))),
                        "metadata": item.get("metadata", {}),
                    })
            return entities
        except Exception as exc:
            logger.warning(f"LLM实体抽取JSON解析失败: {exc}")
            return []


class RiskScorer:
    def __init__(self):
        self._level_weights = {
            "critical": 0.4, "high": 0.3, "medium": 0.2, "low": 0.1, "info": 0.0
        }
        self._intent_weights = {
            IntentLevel.CRITICAL.value: 0.35,
            IntentLevel.MALICIOUS.value: 0.25,
            IntentLevel.SUSPICIOUS.value: 0.15,
            IntentLevel.BENIGN.value: 0.0,
        }

    def compute_risk_score(
        self,
        classification: Dict,
        entities: List[Dict],
        patterns: List[Dict],
        cheating_scenarios: List[Dict] = None,
    ) -> float:
        score = 0.0

        score += self._level_weights.get(classification.get("threat_level", "info"), 0.0)
        score += self._intent_weights.get(classification.get("intent_level", "benign"), 0.0)

        high_conf_entities = [e for e in entities if e.get("confidence", 0) >= 0.8]
        score += min(0.15, len(high_conf_entities) * 0.02)

        crypto_entities = [e for e in entities if e.get("entity_type") == "crypto_address"]
        if crypto_entities:
            score += 0.1

        org_entities = [e for e in entities if e.get("entity_type") == "organization"]
        if org_entities:
            score += 0.05

        if patterns:
            max_severity = max(self._level_weights.get(p.get("severity", "medium"), 0.2) for p in patterns)
            score += max_severity * 0.2

        if cheating_scenarios:
            critical_scenarios = [s for s in cheating_scenarios if s.get("severity") == "critical"]
            high_scenarios = [s for s in cheating_scenarios if s.get("severity") == "high"]
            score += len(critical_scenarios) * 0.1
            score += len(high_scenarios) * 0.05

        return min(1.0, score)

    def compute_quality_score(self, text: str, entities: List[Dict], classification: Dict) -> float:
        score = 1.0

        if len(text) < 20:
            score -= 0.3
        elif len(text) < 50:
            score -= 0.1

        if not entities:
            score -= 0.2

        if classification.get("confidence", 0) < 0.3:
            score -= 0.2

        has_chinese = bool(re.search(r'[\u4e00-\u9fff]', text))
        if not has_chinese and not entities:
            score -= 0.1

        unique_chars = len(set(text))
        total_chars = len(text)
        if total_chars > 0 and unique_chars / total_chars < 0.15:
            score -= 0.3

        return max(0.0, min(1.0, score))


class IntelligencePipeline:
    def __init__(self, llm_service=None, db_session_factory=None, vector_store=None, knowledge_graph=None, alert_engine=None):
        self._llm = llm_service
        self._db_session_factory = db_session_factory
        self._vector_store = vector_store
        self._knowledge_graph = knowledge_graph
        self._alert_engine = alert_engine

        self._cleaner = TextCleaner()
        self._deduplicator = PersistentDeduplicator()
        self._classifier = EnhancedThreatClassifier(llm_service)
        self._extractor = EnhancedEntityExtractor(llm_service)
        self._risk_scorer = RiskScorer()

        self._rule_extractor = None
        self._rule_classifier = None
        try:
            from app.core.rule_extractor import RuleBasedEntityExtractor
            from app.core.rule_classifier import RuleBasedClassifier
            self._rule_extractor = RuleBasedEntityExtractor()
            self._rule_classifier = RuleBasedClassifier()
        except Exception as exc:
            logger.debug(f"Rule-based extractor/classifier init failed: {exc}")

        self._llm_circuit_open = False
        self._llm_consecutive_failures = 0
        self._llm_max_consecutive_failures = 3
        self.LLM_AVAILABLE: bool = self._compute_llm_available()

        self._running = False
        self._batch_count = 0
        self._total_processed = 0
        self._total_duplicates = 0
        self._total_high_risk = 0
        self._by_intent: Dict[str, int] = defaultdict(int)

    def _compute_llm_available(self) -> bool:
        if self._llm is None:
            return False
        if self._llm_circuit_open:
            return False
        try:
            from app.config import settings
            if not settings.LLM_API_KEY:
                return False
        except Exception:
            return False
        return True

    def open_llm_circuit(self, reason: str = "") -> None:
        self._llm_circuit_open = True
        self.LLM_AVAILABLE = False
        if reason:
            logger.warning(f"LLM circuit opened: {reason}")

    def close_llm_circuit(self) -> None:
        self._llm_circuit_open = False
        self._llm_consecutive_failures = 0
        self.LLM_AVAILABLE = self._compute_llm_available()
        logger.info("LLM circuit closed")

    def _llm_call_succeeded(self) -> None:
        self._llm_consecutive_failures = 0

    def _llm_call_failed(self, exc: Exception) -> None:
        self._llm_consecutive_failures += 1
        msg = str(exc) if exc else ""
        if "402" in msg or "Payment Required" in msg or "insufficient balance" in msg.lower():
            self.open_llm_circuit(reason=f"402/payment error: {msg[:100]}")
        elif self._llm_consecutive_failures >= self._llm_max_consecutive_failures:
            self.open_llm_circuit(reason=f"reached {self._llm_max_consecutive_failures} consecutive failures")

    async def process_single(self, item: Dict, use_llm: bool = True, retry: int = 0) -> PipelineItemResult:
        start_time = time.time()
        item_id = item.get("id", uuid.uuid4().hex)
        source = item.get("source", "unknown")
        content = item.get("content", "")

        result = PipelineItemResult(
            item_id=item_id,
            source=source,
            stage=PipelineStage.INGEST.value,
            status="processing",
            original_content=content,
        )

        try:
            cleaned_content, clean_meta = self._cleaner.clean(content)
            result.cleaned_content = cleaned_content
            result.stage = PipelineStage.CLEAN.value

            if not cleaned_content or len(cleaned_content) < 10:
                result.status = "skipped"
                result.error = "内容过短或为空"
                result.quality_score = 0.0
                result.processing_time_ms = (time.time() - start_time) * 1000
                return result

            is_dup, dup_of, similarity = self._deduplicator.check_duplicate(cleaned_content, source, item_id)
            result.stage = PipelineStage.DEDUP.value

            llm_in_scope = bool(use_llm) and bool(self.LLM_AVAILABLE) and (self._llm is not None) and (not self._llm_circuit_open)

            rule_extracted_entities: List[Dict] = []
            if self._rule_extractor is not None:
                try:
                    rule_extracted_entities = self._rule_extractor.extract_flat(cleaned_content)
                except Exception as exc:
                    logger.debug(f"Rule-based entity extraction failed: {exc}")
                    rule_extracted_entities = []

            rule_classification: Dict = {"category": "unknown", "confidence": 0.0, "severity": "info"}
            if self._rule_classifier is not None:
                try:
                    rule_classification = self._rule_classifier.classify(cleaned_content)
                except Exception as exc:
                    logger.debug(f"Rule-based classification failed: {exc}")

            if is_dup:
                result.is_duplicate = True
                result.duplicate_of = dup_of
                result.status = "duplicate"
                result.cleaned_content = cleaned_content
                classification = self._classifier._rule_based_classify(cleaned_content)
                intent_result = self._classifier._classify_intent(cleaned_content)
                cheating_result = self._classifier._detect_cheating_scenarios(cleaned_content)
                classification["intent_level"] = intent_result["intent_level"]
                classification["intent_indicators"] = intent_result["indicators"]
                classification["intent_confidence"] = intent_result["confidence"]
                classification["cheating_scenarios"] = cheating_result
                classification["severity"] = rule_classification.get("severity", classification.get("threat_level", "info"))
                result.threat_categories = [classification] if classification.get("category") else []
                if "all_categories" in classification:
                    result.threat_categories = classification["all_categories"]
                result.intent_level = classification.get("intent_level", IntentLevel.BENIGN.value)
                result.intent_indicators = classification.get("intent_indicators", [])
                result.cheating_scenarios = classification.get("cheating_scenarios", [])
                entities = await self._extractor.extract(cleaned_content, use_llm=False)
                if not entities and rule_extracted_entities:
                    entities = self._format_rule_entities_for_pipeline(rule_extracted_entities)
                if isinstance(entities, list):
                    result.entities = entities
                result.risk_score = self._compute_rule_based_risk_score(rule_classification, entities)
                result.quality_score = self._risk_scorer.compute_quality_score(
                    cleaned_content, result.entities, classification
                )
                self._total_duplicates += 1
                self._by_intent[result.intent_level] += 1
                result.processing_time_ms = (time.time() - start_time) * 1000
                return result

            last_error = None
            for attempt in range(retry + 1):
                try:
                    classification = await self._classifier.classify(cleaned_content, use_llm=llm_in_scope)
                    result.threat_categories = [classification]
                    if "all_categories" in classification:
                        result.threat_categories = classification["all_categories"]
                    result.intent_level = classification.get("intent_level", IntentLevel.BENIGN.value)
                    result.intent_indicators = classification.get("intent_indicators", [])
                    result.cheating_scenarios = classification.get("cheating_scenarios", [])
                    result.stage = PipelineStage.CLASSIFY.value

                    if rule_classification.get("severity") in ("critical", "high", "medium", "low", "info"):
                        classification["severity"] = rule_classification["severity"]
                        if classification.get("threat_level") in (None, "info"):
                            classification["threat_level"] = rule_classification["severity"]

                    entities = await self._extractor.extract(cleaned_content, use_llm=llm_in_scope)
                    if not entities and rule_extracted_entities:
                        entities = self._format_rule_entities_for_pipeline(rule_extracted_entities)
                    result.entities = entities
                    result.stage = PipelineStage.EXTRACT.value

                    risk_score = self._compute_rule_based_risk_score(rule_classification, entities)
                    if classification.get("confidence", 0):
                        risk_score = max(risk_score, min(1.0, risk_score * 0.6 + float(classification.get("confidence", 0)) * 0.4))
                    quality_score = self._risk_scorer.compute_quality_score(cleaned_content, entities, classification)
                    result.risk_score = risk_score
                    result.quality_score = quality_score
                    result.stage = PipelineStage.RISK_SCORE.value

                    if llm_in_scope and self._llm and risk_score >= 0.5:
                        try:
                            summary = await self._generate_summary(cleaned_content, classification, entities)
                            result.summary = summary
                            self._llm_call_succeeded()
                        except Exception as exc:
                            self._llm_call_failed(exc)
                            logger.warning(f"摘要生成降级到规则: {exc}")
                            result.summary = self._rule_based_summary(classification, entities)
                    else:
                        result.summary = self._rule_based_summary(classification, entities)

                    result.status = "completed"
                    result.stage = PipelineStage.STORE.value
                    self._total_processed += 1
                    self._by_intent[result.intent_level] += 1
                    if result.risk_score >= 0.7:
                        self._total_high_risk += 1
                    break
                except Exception as exc:
                    last_error = exc
                    if llm_in_scope:
                        self._llm_call_failed(exc)
                    if attempt < retry:
                        logger.warning(f"Pipeline处理重试 [{item_id}] 第{attempt + 1}次: {exc}")
                        continue
                    raise

        except Exception as exc:
            result.status = "error"
            result.error = "情报管线操作失败"
            logger.error(f"Pipeline处理失败 [{item_id}]: {exc}")

        result.processing_time_ms = (time.time() - start_time) * 1000
        return result

    def _format_rule_entities_for_pipeline(self, rule_entities: List[Dict]) -> List[Dict]:
        out: List[Dict] = []
        for ent in rule_entities:
            ent_type = ent.get("type", "unknown")
            ent_value = ent.get("value", "")
            if not ent_value:
                continue
            out.append({
                "entity_type": ent_type,
                "entity_label": ent_type,
                "value": ent_value,
                "context": "",
                "confidence": 0.7,
                "metadata": {"source": "rule_based"},
            })
        return out

    def _compute_rule_based_risk_score(self, rule_classification: Dict, entities: List[Dict]) -> float:
        score = 0.0
        severity = (rule_classification or {}).get("severity", "info")
        severity_weight = {
            "critical": 0.4, "high": 0.3, "medium": 0.2, "low": 0.1, "info": 0.0,
        }.get(severity, 0.0)
        score += severity_weight

        rule_conf = float((rule_classification or {}).get("confidence", 0.0) or 0.0)
        score += min(0.3, rule_conf * 0.3)

        if entities:
            high_conf = sum(1 for e in entities if (e.get("confidence", 0) or 0) >= 0.8)
            score += min(0.2, high_conf * 0.03)
            score += min(0.1, len(entities) * 0.01)

        return min(1.0, max(0.0, score))

    async def process_batch(self, items: List[Dict], use_llm: bool = True, max_concurrent: int = 5) -> PipelineBatchResult:
        batch_id = uuid.uuid4().hex[:12]
        batch_result = PipelineBatchResult(
            batch_id=batch_id,
            total_input=len(items),
            started_at=datetime.now(timezone.utc),
        )

        self._batch_count += 1
        semaphore = asyncio.Semaphore(max_concurrent)

        async def _process_with_semaphore(item):
            async with semaphore:
                return await self.process_single(item, use_llm=use_llm)

        tasks = [_process_with_semaphore(item) for item in items]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, Exception):
                batch_result.item_results.append(PipelineItemResult(
                    item_id="error",
                    source="unknown",
                    stage="error",
                    status="error",
                    error=str(r),
                ))
                continue
            batch_result.item_results.append(r)

            if r.is_duplicate:
                batch_result.total_duplicates += 1
            elif r.status == "completed":
                batch_result.total_processed += 1
                if r.risk_score >= 0.7:
                    batch_result.total_high_risk += 1
                if r.intent_level in (IntentLevel.CRITICAL.value, IntentLevel.MALICIOUS.value):
                    batch_result.total_critical += 1

            source = r.source
            batch_result.by_source[source] = batch_result.by_source.get(source, 0) + 1
            batch_result.by_intent[r.intent_level] = batch_result.by_intent.get(r.intent_level, 0) + 1

            for cat in r.threat_categories:
                cat_key = cat.get("category", "unknown")
                batch_result.by_category[cat_key] = batch_result.by_category.get(cat_key, 0) + 1

        batch_result.completed_at = datetime.now(timezone.utc)
        batch_result.total_time_ms = (batch_result.completed_at - batch_result.started_at).total_seconds() * 1000

        logger.info(
            f"Pipeline batch [{batch_id}] completed: "
            f"input={batch_result.total_input}, processed={batch_result.total_processed}, "
            f"duplicates={batch_result.total_duplicates}, high_risk={batch_result.total_high_risk}, "
            f"critical={batch_result.total_critical}, time={batch_result.total_time_ms:.0f}ms"
        )

        return batch_result

    async def _generate_summary(self, text: str, classification: Dict, entities: List[Dict]) -> str:
        if not self._llm:
            return self._rule_based_summary(classification, entities)

        entity_desc = "\n".join([f"- {e.get('entity_label', e.get('entity_type', ''))}: {e.get('value', '')}" for e in entities[:15]])
        intent_desc = classification.get("intent_level", "benign")
        cheating_desc = ", ".join([s.get("label", "") for s in classification.get("cheating_scenarios", [])])

        prompt = (
            f"请基于以下黑灰产情报分析结果生成简洁的分析总结：\n\n"
            f"威胁分类: {classification.get('category_label', '未知')}({classification.get('threat_level', 'info')}级)\n"
            f"高危意图: {intent_desc}\n"
            f"作弊场景: {cheating_desc or '无'}\n"
            f"风险评分: {classification.get('confidence', 0):.2f}\n"
            f"识别实体:\n{entity_desc or '无'}\n\n"
            f"请生成200字以内的分析总结，包含威胁定性、关键发现和处置建议。"
        )

        try:
            response = await self._llm.chat(prompt)
            if isinstance(response, str):
                return response[:500]
            return str(response)[:500]
        except Exception as exc:
            logger.warning(f"LLM摘要生成失败: {exc}")
            return self._rule_based_summary(classification, entities)

    def _rule_based_summary(self, classification: Dict, entities: List[Dict]) -> str:
        parts = [f"该情报涉及{classification.get('category_label', '未知')}类威胁，威胁等级为{classification.get('threat_level', 'info')}级。"]
        intent = classification.get("intent_level", "benign")
        if intent in (IntentLevel.CRITICAL.value, IntentLevel.MALICIOUS.value):
            parts.append(f"高危意图判定为{intent}级。")

        cheating = classification.get("cheating_scenarios", [])
        if cheating:
            scenario_names = [s.get("label", "") for s in cheating[:3]]
            parts.append(f"涉及作弊场景: {', '.join(scenario_names)}。")

        if entities:
            entity_summary = defaultdict(list)
            for e in entities:
                entity_summary[e.get("entity_label", e.get("entity_type", "unknown"))].append(e.get("value", ""))
            for label, values in list(entity_summary.items())[:4]:
                parts.append(f"识别到{label}: {', '.join(values[:3])}。")

        return "".join(parts)

    def get_stats(self) -> Dict:
        return {
            "batch_count": self._batch_count,
            "total_processed": self._total_processed,
            "total_duplicates": self._total_duplicates,
            "total_high_risk": self._total_high_risk,
            "by_intent": dict(self._by_intent),
            "dedup_stats": self._deduplicator.get_stats(),
            "is_running": self._running,
        }

    async def store_results(self, results: List[PipelineItemResult]) -> int:
        if not self._db_session_factory:
            return 0

        stored = 0
        max_retries = 3
        retry_delay = 0.5  # 秒

        for attempt in range(max_retries):
            try:
                from app.db.tables import RawIntelligenceTable, CleanedIntelligenceTable, AnalyzedIntelligenceTable
                from sqlalchemy import select

                async with self._db_session_factory() as session:
                    for r in results:
                        if r.status != "completed" or r.is_duplicate:
                            continue
                        try:
                            async with session.begin_nested():
                                existing = await session.execute(
                                    select(RawIntelligenceTable).where(RawIntelligenceTable.id == r.item_id).limit(1)
                                )
                                if existing.scalar():
                                    continue

                                raw = RawIntelligenceTable(
                                    id=r.item_id,
                                    source=r.source,
                                    content=r.cleaned_content,
                                    raw_content=r.cleaned_content,
                                    status="analyzed",
                                    metadata_json=json.dumps({
                                        "pipeline_version": "2.0",
                                        "quality_score": r.quality_score,
                                        "processing_time_ms": r.processing_time_ms,
                                    }, ensure_ascii=False),
                                )
                                session.add(raw)

                                cleaned = CleanedIntelligenceTable(
                                    id=uuid.uuid4().hex,
                                    raw_id=r.item_id,
                                    content=r.cleaned_content,
                                    decoded_content=r.cleaned_content,
                                    blacktalk_terms_json=json.dumps(
                                        {e["value"]: e.get("metadata", {}).get("meaning", "")
                                         for e in r.entities if e.get("entity_type") == "slang"},
                                        ensure_ascii=False
                                    ),
                                    entities_json=json.dumps(r.entities, ensure_ascii=False),
                                    threat_level=r.threat_categories[0].get("threat_level", "info") if r.threat_categories else "info",
                                )
                                session.add(cleaned)

                                analyzed = AnalyzedIntelligenceTable(
                                    id=uuid.uuid4().hex,
                                    cleaned_id=cleaned.id,
                                    threat_level=r.threat_categories[0].get("threat_level", "info") if r.threat_categories else "info",
                                    threat_categories_json=json.dumps(r.threat_categories, ensure_ascii=False),
                                    attack_patterns_json=json.dumps(r.crime_patterns, ensure_ascii=False),
                                    technique_chain_json=json.dumps(r.tech_chains, ensure_ascii=False),
                                    confidence_score=r.risk_score,
                                    analysis_summary=r.summary,
                                    evidence_refs_json=json.dumps({
                                        "intent_level": r.intent_level,
                                        "intent_indicators": r.intent_indicators,
                                        "cheating_scenarios": r.cheating_scenarios,
                                        "quality_score": r.quality_score,
                                    }, ensure_ascii=False),
                                )
                                session.add(analyzed)
                                stored += 1
                        except Exception as exc:
                            logger.warning(f"单条记录存储失败 [{r.item_id}]: {exc}")
                            continue

                    await session.commit()

                    # 触发告警评估
                    if self._alert_engine and stored > 0:
                        await self._trigger_alerts_for_results(results, session)

                # 成功执行，跳出重试循环
                break

            except OperationalError as exc:
                if "database is locked" in str(exc).lower():
                    if attempt < max_retries - 1:
                        wait_time = retry_delay * (2 ** attempt)
                        logger.warning(f"数据库锁定，{wait_time:.1f}秒后重试 ({attempt + 1}/{max_retries})")
                        await asyncio.sleep(wait_time)
                        stored = 0  # 重置计数
                        continue
                    else:
                        logger.error(f"数据库锁定，已达最大重试次数: {exc}")
                else:
                    logger.error(f"数据库操作错误: {exc}")
                    break
            except Exception as exc:
                logger.error(f"存储分析结果失败: {exc}")
                break

        return stored

    async def _trigger_alerts_for_results(self, results: List[PipelineItemResult], session) -> int:
        """为处理完成的情报触发告警评估"""
        if not self._alert_engine:
            return 0

        triggered_count = 0
        try:
            for r in results:
                if r.status != "completed" or r.is_duplicate:
                    continue

                # 构建告警评估数据
                threat_level = "info"
                if r.threat_categories:
                    threat_level = r.threat_categories[0].get("threat_level", "info")

                intel_data = {
                    "id": r.item_id,
                    "content": r.cleaned_content,
                    "threat_level": threat_level,
                    "confidence": r.risk_score,
                    "entity_count": len(r.entities),
                    "entity_type": r.entities[0].get("entity_type", "") if r.entities else "",
                    "value": r.entities[0].get("value", "") if r.entities else "",
                    "source": r.source,
                }

                try:
                    alerts = await self._alert_engine.evaluate_intelligence(intel_data)
                    if alerts:
                        triggered_count += len(alerts)
                        logger.info(f"情报 [{r.item_id}] 触发 {len(alerts)} 个告警")
                except Exception as exc:
                    logger.warning(f"告警评估失败 [{r.item_id}]: {exc}")

        except Exception as exc:
            logger.error(f"批量告警评估失败: {exc}")

        return triggered_count
