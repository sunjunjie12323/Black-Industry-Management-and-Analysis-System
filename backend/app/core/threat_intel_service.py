import asyncio
import hashlib
import json
import re
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from loguru import logger


THREAT_CATEGORIES = {
    "fraud": {"label": "网络诈骗", "level": "high", "keywords": ["杀猪盘", "套路贷", "裸贷", "资金盘", "庞氏", "传销", "电信诈骗", "投资理财", "虚假平台"]},
    "underground_economy": {"label": "地下经济", "level": "high", "keywords": ["跑分", "洗钱", "四件套", "卡商", "水房", "车手", "套现", "代付", "黑卡", "实名"]},
    "cybercrime_tools": {"label": "网络犯罪工具", "level": "critical", "keywords": ["木马", "远控", "RAT", "勒索", "ransomware", "DDoS", "僵尸网络", "肉鸡", "猫池", "接码"]},
    "data_theft": {"label": "数据窃取", "level": "critical", "keywords": ["拖库", "撞库", "社工库", "料子", "黑料", "数据泄露", "隐私贩卖", "信息倒卖"]},
    "phishing": {"label": "钓鱼攻击", "level": "high", "keywords": ["钓鱼", "phishing", "仿冒", "伪造", "假冒", "钓鱼网站", "短信钓鱼"]},
    "gambling": {"label": "网络赌博", "level": "medium", "keywords": ["博彩", "菠菜", "赌场", "下注", "盘口", "赔率", "代理"]},
    "porn_traffic": {"label": "色情引流", "level": "medium", "keywords": ["色流", "引流", "裸聊", "交友", "约炮"]},
    "account_farming": {"label": "养号黑产", "level": "medium", "keywords": ["养号", "批量注册", "号商", "接码", "验证码", "代注册"]},
    "darkweb_trade": {"label": "暗网交易", "level": "critical", "keywords": ["暗网", "darkweb", "洋葱路由", "tor", "比特币", "门罗币"]},
    "cheating": {"label": "作弊服务", "level": "medium", "keywords": ["代考", "代写", "作弊器", "外挂", "辅助", "脚本", "刷单", "炒信", "刷评", "刷量", "水军", "控评", "刷粉", "涨粉"]},
    "malware_attack": {"label": "恶意软件攻击", "level": "critical", "keywords": ["勒索", "勒索软件", "ransomware", "木马", "后门", "远控", "RAT", "僵尸网络", "botnet", "挖矿", "恶意程序"]},
}

INDUSTRY_THREAT_MAPPING = {
    "threat_intel": {
        "name": "威胁情报",
        "description": "黑灰产情报分析场景",
        "threat_focus": ["电信诈骗", "网络黑产", "数据泄露", "恶意软件", "暗网交易"],
        "keywords": ["黑产", "灰产", "木马", "钓鱼", "洗钱", "诈骗", "黑卡", "跑分", "接码", "养号", "薅羊毛", "刷单"],
        "analysis_prompt": "你专注于黑灰产情报分析，重点关注电信网络诈骗、网络黑产链条、数据泄露与贩卖、恶意软件传播、暗网交易活动。分析时需结合黑产技术手段和组织模式。",
        "qa_system_prompt": "你是黑灰产情报分析专家。你专注于分析电信诈骗、网络黑产、数据泄露、恶意软件、暗网交易等威胁。请基于情报数据提供专业分析和防护建议。",
        "translation_terms": {"跑分": "Money laundering relay", "洗钱": "Money laundering", "四件套": "Four-piece identity kit", "杀猪盘": "Pig butchering scam", "套现": "Cash out", "接码": "SMS verification", "养号": "Account farming", "黑卡": "Black market card"},
    },
    "general": {
        "name": "通用",
        "description": "通用威胁情报场景",
        "threat_focus": ["网络攻击", "数据泄露", "恶意软件", "社会工程", "漏洞利用"],
        "keywords": ["攻击", "漏洞", "恶意", "钓鱼", "社工", "泄露", "后门", "木马"],
        "analysis_prompt": "你专注于通用网络安全威胁情报分析，重点关注网络攻击、数据泄露、恶意软件、社会工程、漏洞利用等常见威胁。分析时需结合攻击链和威胁模型。",
        "qa_system_prompt": "你是网络安全威胁情报分析专家。你专注于分析各类网络攻击、数据泄露、恶意软件传播、社会工程攻击等威胁。请基于情报数据提供专业分析和安全建议。",
        "translation_terms": {"零日漏洞": "Zero-day vulnerability", "社会工程": "Social engineering", "钓鱼攻击": "Phishing attack", "恶意软件": "Malware", "后门": "Backdoor"},
    },
    "manufacturing": {
        "name": "智能制造",
        "description": "设备故障预测、产线优化、供应链风险、工控安全",
        "threat_focus": ["工控攻击", "供应链风险", "设备安全", "产线破坏", "数据窃取"],
        "keywords": ["工控", "PLC", "SCADA", "供应链", "产线", "设备故障", "固件", "OT网络", "传感器"],
        "analysis_prompt": "你专注于智能制造领域的威胁情报分析，重点关注工控系统攻击、供应链安全风险、设备故障与破坏、产线安全、工业数据窃取。分析时需结合工业控制协议和制造流程。",
        "qa_system_prompt": "你是智能制造安全分析专家。你专注于分析工控系统攻击、供应链风险、设备安全、产线安全等威胁。请基于情报数据提供专业分析和安全建议。",
        "translation_terms": {"工控": "Industrial control", "供应链攻击": "Supply chain attack", "固件篡改": "Firmware tampering", "产线破坏": "Production line sabotage"},
    },
    "education": {
        "name": "智慧教育",
        "description": "考试安全、学术诚信、在线教育平台安全",
        "threat_focus": ["考试作弊", "学术欺诈", "平台安全", "数据泄露", "内容盗版"],
        "keywords": ["代考", "代写", "作弊", "外挂", "学术不端", "论文抄袭", "考试安全", "在线教育"],
        "analysis_prompt": "你专注于智慧教育领域的威胁情报分析，重点关注考试安全、学术诚信、在线教育平台安全、教育数据泄露。分析时需结合教育场景和技术手段。",
        "qa_system_prompt": "你是智慧教育安全分析专家。你专注于分析考试作弊、学术欺诈、教育平台安全等威胁。请基于情报数据提供专业分析和安全建议。",
        "translation_terms": {"代考": "Proxy exam-taking", "代写": "Ghostwriting", "学术不端": "Academic misconduct", "论文抄袭": "Plagiarism"},
    },
    "healthcare": {
        "name": "医疗健康",
        "description": "医疗数据安全、药品追溯、医保欺诈检测",
        "threat_focus": ["医疗数据泄露", "医保欺诈", "药品安全", "设备安全", "隐私侵犯"],
        "keywords": ["医疗数据", "医保", "药品", "患者隐私", "HIS系统", "电子病历", "医保欺诈", "假药"],
        "analysis_prompt": "你专注于医疗健康领域的威胁情报分析，重点关注医疗数据安全、医保欺诈、药品追溯与安全、医疗设备安全、患者隐私保护。分析时需结合医疗法规和数据敏感性。",
        "qa_system_prompt": "你是医疗健康安全分析专家。你专注于分析医疗数据泄露、医保欺诈、药品安全等威胁。请基于情报数据提供专业分析和安全建议。",
        "translation_terms": {"医保欺诈": "Medical insurance fraud", "电子病历": "Electronic health record", "假药": "Counterfeit drugs", "患者隐私": "Patient privacy"},
    },
    "finance": {
        "name": "金融服务",
        "description": "金融欺诈、反洗钱、交易安全、合规风险",
        "threat_focus": ["金融欺诈", "反洗钱", "交易安全", "合规风险", "信用卡犯罪"],
        "keywords": ["金融欺诈", "洗钱", "信用卡", "套现", "非法集资", "内幕交易", "合规", "反洗钱", "AML"],
        "analysis_prompt": "你专注于金融服务领域的威胁情报分析，重点关注金融欺诈、反洗钱、交易安全、合规风险、信用卡犯罪。分析时需结合金融监管要求和交易模式。",
        "qa_system_prompt": "你是金融服务安全分析专家。你专注于分析金融欺诈、反洗钱、交易安全等威胁。请基于情报数据提供专业分析和安全建议。",
        "translation_terms": {"反洗钱": "Anti-money laundering (AML)", "非法集资": "Illegal fundraising", "内幕交易": "Insider trading", "套现": "Cash out"},
    },
}

ENTITY_TYPES = {
    "slang": {"label": "黑话术语", "color": "#ff6b6b", "icon": "chat"},
    "url": {"label": "恶意链接", "color": "#ffa502", "icon": "link"},
    "account": {"label": "黑产账号", "color": "#7c4dff", "icon": "user"},
    "tool": {"label": "作案工具", "color": "#00b894", "icon": "tool"},
    "organization": {"label": "黑产组织", "color": "#e84393", "icon": "group"},
    "technique": {"label": "作案手法", "color": "#0984e3", "icon": "code"},
    "target": {"label": "攻击目标", "color": "#fdcb6e", "icon": "target"},
    "channel": {"label": "传播渠道", "color": "#6c5ce7", "icon": "share"},
}


@dataclass
class ThreatClassification:
    category: str
    category_label: str
    threat_level: str
    confidence: float
    matched_keywords: List[str]
    reasoning: str

    def to_dict(self) -> Dict:
        return {
            "category": self.category,
            "category_label": self.category_label,
            "threat_level": self.threat_level,
            "confidence": round(self.confidence, 4),
            "matched_keywords": self.matched_keywords,
            "reasoning": self.reasoning,
        }


@dataclass
class ExtractedEntity:
    entity_type: str
    entity_label: str
    value: str
    context: str
    confidence: float
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "entity_type": self.entity_type,
            "entity_label": self.entity_label,
            "value": self.value,
            "context": self.context[:200],
            "confidence": round(self.confidence, 4),
            "metadata": self.metadata,
        }


@dataclass
class CrimePattern:
    pattern_type: str
    description: str
    techniques: List[str]
    targets: List[str]
    indicators: List[str]
    severity: str
    confidence: float

    def to_dict(self) -> Dict:
        return {
            "pattern_type": self.pattern_type,
            "description": self.description,
            "techniques": self.techniques,
            "targets": self.targets,
            "indicators": self.indicators[:10],
            "severity": self.severity,
            "confidence": round(self.confidence, 4),
        }


@dataclass
class TechChain:
    chain_type: str
    steps: List[Dict[str, str]]
    tools_involved: List[str]
    detection_points: List[str]
    severity: str

    def to_dict(self) -> Dict:
        return {
            "chain_type": self.chain_type,
            "steps": self.steps,
            "tools_involved": self.tools_involved,
            "detection_points": self.detection_points,
            "severity": self.severity,
        }


@dataclass
class IntelligenceAnalysisResult:
    intelligence_id: str
    threat_classification: Optional[ThreatClassification] = None
    entities: List[ExtractedEntity] = field(default_factory=list)
    crime_patterns: List[CrimePattern] = field(default_factory=list)
    tech_chains: List[TechChain] = field(default_factory=list)
    summary: str = ""
    risk_score: float = 0.0
    analyzed_at: Optional[datetime] = None

    def to_dict(self) -> Dict:
        return {
            "intelligence_id": self.intelligence_id,
            "threat_classification": self.threat_classification.to_dict() if self.threat_classification else None,
            "entities": [e.to_dict() for e in self.entities],
            "crime_patterns": [p.to_dict() for p in self.crime_patterns],
            "tech_chains": [c.to_dict() for c in self.tech_chains],
            "summary": self.summary,
            "risk_score": round(self.risk_score, 4),
            "analyzed_at": self.analyzed_at.isoformat() if self.analyzed_at else None,
        }


class ThreatClassifier:
    def __init__(self, llm_service=None):
        self._llm = llm_service
        self._categories = THREAT_CATEGORIES

    async def classify(self, text: str, use_llm: bool = True) -> ThreatClassification:
        rule_result = self._rule_based_classify(text)
        if rule_result.confidence >= 0.9 or not use_llm or not self._llm:
            return rule_result

        try:
            llm_result = await self._llm_classify(text)
            if llm_result.confidence > rule_result.confidence:
                return llm_result
        except Exception as exc:
            logger.warning(f"LLM分类失败，使用规则结果: {exc}")

        return rule_result

    def _rule_based_classify(self, text: str) -> ThreatClassification:
        text_lower = text.lower()
        best_category = "unknown"
        best_level = "info"
        best_keywords = []
        best_score = 0.0

        for cat_key, cat_info in self._categories.items():
            matched = [kw for kw in cat_info["keywords"] if kw.lower() in text_lower]
            if matched:
                score = len(matched) / len(cat_info["keywords"])
                if score > best_score or (score == best_score and cat_info["level"] in ("critical", "high")):
                    best_score = score
                    best_category = cat_key
                    best_level = cat_info["level"]
                    best_keywords = matched

        if best_score == 0:
            return ThreatClassification(
                category="unknown",
                category_label="未分类",
                threat_level="info",
                confidence=0.0,
                matched_keywords=[],
                reasoning="未匹配到已知威胁类别",
            )

        confidence = min(1.0, 0.4 + best_score * 0.6)
        return ThreatClassification(
            category=best_category,
            category_label=self._categories[best_category]["label"],
            threat_level=best_level,
            confidence=confidence,
            matched_keywords=best_keywords,
            reasoning=f"匹配到{best_category}类威胁关键词: {', '.join(best_keywords)}",
        )

    async def _llm_classify(self, text: str) -> ThreatClassification:
        categories_desc = "\n".join([f"- {k}: {v['label']}({v['level']}级)" for k, v in self._categories.items()])
        prompt = (
            f"请对以下黑灰产情报文本进行威胁分类：\n\n"
            f"可选类别:\n{categories_desc}\n\n"
            f"情报文本:\n{text[:1500]}\n\n"
            f"请以JSON格式返回: {{\"category\": \"类别key\", \"threat_level\": \"critical/high/medium/low/info\", \"confidence\": 0.0-1.0, \"reasoning\": \"分类理由\"}}"
        )
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
            cat = parsed.get("category", "unknown")
            cat_info = self._categories.get(cat, {})
            return ThreatClassification(
                category=cat,
                category_label=cat_info.get("label", parsed.get("category", "未知")),
                threat_level=parsed.get("threat_level", "medium"),
                confidence=min(1.0, max(0.0, float(parsed.get("confidence", 0.5)))),
                matched_keywords=[],
                reasoning=parsed.get("reasoning", ""),
            )

        return self._rule_based_classify(text)


class EntityExtractor:
    URL_PATTERN = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
    EMAIL_PATTERN = re.compile(r'\b[\w.-]+@[\w.-]+\.\w+\b')
    IP_PATTERN = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
    PHONE_PATTERN = re.compile(r'\b1[3-9]\d{9}\b')
    ACCOUNT_PATTERNS = {
        "telegram": re.compile(r'@[\w]{5,32}|t\.me/[\w]+'),
        "wechat": re.compile(r'微信[：:]\s*[\w-]{6,20}|wxid_[\w]+'),
        "qq": re.compile(r'QQ[：:]\s*\d{5,12}'),
    }
    TOOL_PATTERNS = [
        re.compile(r'(远控|RAT|木马|后门|抓鸡|提权|扫描器|爆破工具|黑页|webshell)', re.IGNORECASE),
        re.compile(r'(猫池|GOIP|短信机|验证码接收|接码平台)', re.IGNORECASE),
        re.compile(r'(洗钱工具|跑分平台|虚拟币 mixer|tumbler)', re.IGNORECASE),
    ]
    SLANG_PATTERNS = {
        "跑分": "为诈骗团伙转移资金的中间人",
        "四件套": "身份证+银行卡+手机卡+U盾的合称",
        "杀猪盘": "长期培养感情后实施诈骗的模式",
        "料子": "被盗的个人信息数据",
        "水房": "专门负责洗钱的环节",
        "车手": "负责取现的底层人员",
        "猫池": "可同时操控多张SIM卡的设备",
        "接码": "接收验证码的服务",
        "养号": "批量培育账号的行为",
        "黑料": "非法获取的个人隐私数据",
    }

    def __init__(self, llm_service=None):
        self._llm = llm_service

    async def extract(self, text: str, use_llm: bool = True) -> List[ExtractedEntity]:
        entities = []
        entities.extend(self._extract_urls(text))
        entities.extend(self._extract_accounts(text))
        entities.extend(self._extract_tools(text))
        entities.extend(self._extract_slang(text))
        entities.extend(self._extract_contact_info(text))

        if use_llm and self._llm:
            try:
                llm_entities = await self._llm_extract(text)
                existing_values = {e.value for e in entities}
                for e in llm_entities:
                    if e.value not in existing_values:
                        entities.append(e)
                        existing_values.add(e.value)
            except Exception as exc:
                logger.warning(f"LLM实体抽取失败: {exc}")

        return entities

    def _extract_urls(self, text: str) -> List[ExtractedEntity]:
        entities = []
        for url in self.URL_PATTERN.findall(text):
            is_suspicious = any(d in url.lower() for d in [".onion", ".tk", ".ml", ".ga", ".cf", "temp", "throwaway"])
            entities.append(ExtractedEntity(
                entity_type="url",
                entity_label=ENTITY_TYPES["url"]["label"],
                value=url,
                context=text[max(0, text.find(url)-30):text.find(url)+len(url)+30],
                confidence=0.9 if is_suspicious else 0.6,
                metadata={"is_suspicious": is_suspicious},
            ))
        return entities

    def _extract_accounts(self, text: str) -> List[ExtractedEntity]:
        entities = []
        for platform, pattern in self.ACCOUNT_PATTERNS.items():
            for match in pattern.findall(text):
                entities.append(ExtractedEntity(
                    entity_type="account",
                    entity_label=ENTITY_TYPES["account"]["label"],
                    value=match,
                    context=text[max(0, text.find(match)-30):text.find(match)+len(match)+30],
                    confidence=0.8,
                    metadata={"platform": platform},
                ))
        return entities

    def _extract_tools(self, text: str) -> List[ExtractedEntity]:
        entities = []
        for pattern in self.TOOL_PATTERNS:
            for match in pattern.findall(text):
                entities.append(ExtractedEntity(
                    entity_type="tool",
                    entity_label=ENTITY_TYPES["tool"]["label"],
                    value=match,
                    context=text[max(0, text.find(match)-30):text.find(match)+len(match)+30],
                    confidence=0.7,
                ))
        return entities

    def _extract_slang(self, text: str) -> List[ExtractedEntity]:
        entities = []
        for slang, meaning in self.SLANG_PATTERNS.items():
            if slang in text:
                entities.append(ExtractedEntity(
                    entity_type="slang",
                    entity_label=ENTITY_TYPES["slang"]["label"],
                    value=slang,
                    context=text[max(0, text.find(slang)-30):text.find(slang)+len(slang)+30],
                    confidence=0.9,
                    metadata={"meaning": meaning},
                ))
        return entities

    def _extract_contact_info(self, text: str) -> List[ExtractedEntity]:
        entities = []
        for email in self.EMAIL_PATTERN.findall(text):
            entities.append(ExtractedEntity(
                entity_type="account", entity_label=ENTITY_TYPES["account"]["label"],
                value=email, context=text[max(0, text.find(email)-20):text.find(email)+len(email)+20],
                confidence=0.7, metadata={"type": "email"},
            ))
        for ip in self.IP_PATTERN.findall(text):
            if not ip.startswith(("192.168.", "10.", "172.16.", "127.0")):
                entities.append(ExtractedEntity(
                    entity_type="url", entity_label="IP地址",
                    value=ip, context=text[max(0, text.find(ip)-20):text.find(ip)+len(ip)+20],
                    confidence=0.6, metadata={"type": "ip"},
                ))
        return entities

    async def _llm_extract(self, text: str) -> List[ExtractedEntity]:
        entity_types_desc = "\n".join([f"- {k}: {v['label']}" for k, v in ENTITY_TYPES.items()])
        prompt = (
            f"请从以下黑灰产情报文本中抽取关键实体：\n\n"
            f"实体类型:\n{entity_types_desc}\n\n"
            f"文本:\n{text[:1500]}\n\n"
            f"请以JSON数组格式返回: [{{\"type\": \"实体类型key\", \"value\": \"实体值\", \"context\": \"上下文片段\", \"confidence\": 0.0-1.0}}]"
        )
        response = await self._llm.chat(prompt)
        if isinstance(response, dict):
            llm_text = response.get("content", "")
        elif isinstance(response, str):
            llm_text = response
        else:
            llm_text = str(response)

        entities = []
        json_match = re.search(r'\[[\s\S]*?\]', llm_text)
        if json_match:
            try:
                parsed = json.loads(json_match.group())
                for item in parsed[:20]:
                    etype = item.get("type", "slang")
                    etype_info = ENTITY_TYPES.get(etype, ENTITY_TYPES["slang"])
                    entities.append(ExtractedEntity(
                        entity_type=etype,
                        entity_label=etype_info["label"],
                        value=item.get("value", ""),
                        context=item.get("context", ""),
                        confidence=min(1.0, max(0.0, float(item.get("confidence", 0.5)))),
                    ))
            except (json.JSONDecodeError, TypeError) as exc:
                logger.warning(f"LLM实体JSON解析失败: {exc}")
        return entities


class CrimePatternAnalyzer:
    def __init__(self, llm_service=None):
        self._llm = llm_service
        self._pattern_templates = {
            "fraud_chain": {"label": "诈骗链路", "steps": ["引流→建立信任→诱导投资→收割跑路"]},
            "money_laundering": {"label": "洗钱链路", "steps": ["入金→分账→多层转移→提现"]},
            "data_theft_chain": {"label": "数据窃取链路", "steps": ["入侵→窃取→清洗→贩卖"]},
            "account_farming": {"label": "养号链路", "steps": ["批量注册→养号→出售→使用"]},
            "phishing_operation": {"label": "钓鱼运营", "steps": ["搭建→投放→收集→利用"]},
        }

    async def analyze_patterns(self, text: str, entities: List[ExtractedEntity] = None) -> List[CrimePattern]:
        patterns = []
        rule_patterns = self._rule_based_analyze(text, entities)
        patterns.extend(rule_patterns)

        if self._llm:
            try:
                llm_patterns = await self._llm_analyze(text, entities)
                existing_types = {p.pattern_type for p in patterns}
                for p in llm_patterns:
                    if p.pattern_type not in existing_types:
                        patterns.append(p)
                        existing_types.add(p.pattern_type)
            except Exception as exc:
                logger.warning(f"LLM犯罪模式分析失败: {exc}")

        return patterns

    def _rule_based_analyze(self, text: str, entities: List[ExtractedEntity] = None) -> List[CrimePattern]:
        patterns = []
        text_lower = text.lower()

        fraud_indicators = ["杀猪盘", "投资", "理财", "高回报", "稳赚", "提现困难"]
        if sum(1 for ind in fraud_indicators if ind in text_lower) >= 2:
            patterns.append(CrimePattern(
                pattern_type="fraud_chain",
                description="检测到投资诈骗链路特征",
                techniques=["社交工程", "信任建立", "虚假平台"],
                targets=["投资者", "理财用户"],
                indicators=[ind for ind in fraud_indicators if ind in text_lower],
                severity="high",
                confidence=0.8,
            ))

        laundering_indicators = ["跑分", "洗钱", "四件套", "代付", "套现", "虚拟币"]
        if sum(1 for ind in laundering_indicators if ind in text_lower) >= 2:
            patterns.append(CrimePattern(
                pattern_type="money_laundering",
                description="检测到洗钱链路特征",
                techniques=["资金分账", "多层转移", "虚拟币混币"],
                targets=["银行账户", "支付平台"],
                indicators=[ind for ind in laundering_indicators if ind in text_lower],
                severity="critical",
                confidence=0.85,
            ))

        data_indicators = ["拖库", "社工库", "料子", "数据", "泄露", "贩卖"]
        if sum(1 for ind in data_indicators if ind in text_lower) >= 2:
            patterns.append(CrimePattern(
                pattern_type="data_theft_chain",
                description="检测到数据窃取贩卖链路特征",
                techniques=["SQL注入", "社工攻击", "内鬼泄露"],
                targets=["数据库", "用户隐私"],
                indicators=[ind for ind in data_indicators if ind in text_lower],
                severity="critical",
                confidence=0.8,
            ))

        return patterns

    async def _llm_analyze(self, text: str, entities: List[ExtractedEntity] = None) -> List[CrimePattern]:
        entity_desc = ""
        if entities:
            entity_desc = "\n已识别实体:\n" + "\n".join([f"- {e.entity_label}: {e.value}" for e in entities[:15]])

        prompt = (
            f"请分析以下黑灰产情报中的犯罪模式和作恶手法：\n\n"
            f"情报文本:\n{text[:1500]}\n"
            f"{entity_desc}\n\n"
            f"请以JSON数组格式返回犯罪模式: [{{\"pattern_type\": \"模式类型\", \"description\": \"描述\", "
            f"\"techniques\": [\"手法1\"], \"targets\": [\"目标1\"], \"indicators\": [\"指标1\"], "
            f"\"severity\": \"critical/high/medium\", \"confidence\": 0.0-1.0}}]"
        )
        response = await self._llm.chat(prompt)
        if isinstance(response, dict):
            llm_text = response.get("content", "")
        elif isinstance(response, str):
            llm_text = response
        else:
            llm_text = str(response)

        patterns = []
        json_match = re.search(r'\[[\s\S]*?\]', llm_text)
        if json_match:
            try:
                parsed = json.loads(json_match.group())
                for item in parsed[:5]:
                    patterns.append(CrimePattern(
                        pattern_type=item.get("pattern_type", "unknown"),
                        description=item.get("description", ""),
                        techniques=item.get("techniques", []),
                        targets=item.get("targets", []),
                        indicators=item.get("indicators", []),
                        severity=item.get("severity", "medium"),
                        confidence=min(1.0, max(0.0, float(item.get("confidence", 0.5)))),
                    ))
            except (json.JSONDecodeError, TypeError) as exc:
                logger.warning(f"LLM犯罪模式JSON解析失败: {exc}")
        return patterns


class TechChainAnalyzer:
    def __init__(self, llm_service=None):
        self._llm = llm_service

    async def analyze(self, text: str, entities: List[ExtractedEntity] = None) -> List[TechChain]:
        chains = []
        rule_chains = self._rule_based_analyze(text, entities)
        chains.extend(rule_chains)

        if self._llm:
            try:
                llm_chains = await self._llm_analyze(text, entities)
                existing_types = {c.chain_type for c in chains}
                for c in llm_chains:
                    if c.chain_type not in existing_types:
                        chains.append(c)
                        existing_types.add(c.chain_type)
            except Exception as exc:
                logger.warning(f"LLM技术链路分析失败: {exc}")

        return chains

    def _rule_based_analyze(self, text: str, entities: List[ExtractedEntity] = None) -> List[TechChain]:
        chains = []
        text_lower = text.lower()

        if any(kw in text_lower for kw in ["远控", "RAT", "木马", "后门"]):
            chains.append(TechChain(
                chain_type="remote_access",
                steps=[
                    {"step": "投递", "technique": "钓鱼邮件/漏洞利用", "detail": "通过社工或漏洞植入远控"},
                    {"step": "驻留", "technique": "持久化机制", "detail": "注册表/计划任务/服务"},
                    {"step": "通信", "technique": "C2回连", "detail": "加密通道与控制端通信"},
                    {"step": "行动", "technique": "数据窃取/横向移动", "detail": "执行攻击者指令"},
                ],
                tools_involved=[e.value for e in (entities or []) if e.entity_type == "tool"][:5],
                detection_points=["网络流量异常", "可疑进程", "注册表修改", "C2通信特征"],
                severity="critical",
            ))

        if any(kw in text_lower for kw in ["跑分", "洗钱", "代付", "套现"]):
            chains.append(TechChain(
                chain_type="money_laundering",
                steps=[
                    {"step": "入金", "technique": "受害者转账", "detail": "诈骗所得进入一级卡"},
                    {"step": "分账", "technique": "多卡分流", "detail": "通过四件套分散资金"},
                    {"step": "转移", "technique": "虚拟币/第三方", "detail": "混币或跨境转移"},
                    {"step": "提现", "technique": "车手取现", "detail": "ATM或柜台取现"},
                ],
                tools_involved=[e.value for e in (entities or []) if e.entity_type == "tool"][:5],
                detection_points=["大额异常转账", "频繁小额分散", "跨行快速转移", "虚拟币兑换"],
                severity="critical",
            ))

        return chains

    async def _llm_analyze(self, text: str, entities: List[ExtractedEntity] = None) -> List[TechChain]:
        entity_desc = ""
        if entities:
            entity_desc = "\n已识别实体:\n" + "\n".join([f"- {e.entity_label}: {e.value}" for e in entities[:10]])

        prompt = (
            f"请分析以下黑灰产情报中的技术链路和作案流程：\n\n"
            f"情报文本:\n{text[:1500]}\n"
            f"{entity_desc}\n\n"
            f"请以JSON数组格式返回技术链路: [{{\"chain_type\": \"链路类型\", "
            f"\"steps\": [{{\"step\": \"步骤名\", \"technique\": \"技术手段\", \"detail\": \"详情\"}}], "
            f"\"tools_involved\": [\"工具1\"], \"detection_points\": [\"检测点1\"], "
            f"\"severity\": \"critical/high/medium\"}}]"
        )
        response = await self._llm.chat(prompt)
        if isinstance(response, dict):
            llm_text = response.get("content", "")
        elif isinstance(response, str):
            llm_text = response
        else:
            llm_text = str(response)

        chains = []
        json_match = re.search(r'\[[\s\S]*?\]', llm_text)
        if json_match:
            try:
                parsed = json.loads(json_match.group())
                for item in parsed[:3]:
                    chains.append(TechChain(
                        chain_type=item.get("chain_type", "unknown"),
                        steps=item.get("steps", []),
                        tools_involved=item.get("tools_involved", []),
                        detection_points=item.get("detection_points", []),
                        severity=item.get("severity", "medium"),
                    ))
            except (json.JSONDecodeError, TypeError) as exc:
                logger.warning(f"LLM技术链路JSON解析失败: {exc}")
        return chains


class ThreatIntelService:
    def __init__(self, llm_service=None):
        self._llm = llm_service
        self._classifier = ThreatClassifier(llm_service)
        self._extractor = EntityExtractor(llm_service)
        self._pattern_analyzer = CrimePatternAnalyzer(llm_service)
        self._chain_analyzer = TechChainAnalyzer(llm_service)

    async def analyze(self, text: str, intelligence_id: str = "", industry: str = "") -> IntelligenceAnalysisResult:
        import time
        start = time.time()
        intel_id = intelligence_id or uuid.uuid4().hex

        classification = await self._classifier.classify(text)
        entities = await self._extractor.extract(text)
        patterns = await self._pattern_analyzer.analyze_patterns(text, entities)
        chains = await self._chain_analyzer.analyze(text, entities)

        risk_score = self._compute_risk_score(classification, entities, patterns)
        summary = await self._generate_summary(text, classification, entities, patterns, chains, industry)

        result = IntelligenceAnalysisResult(
            intelligence_id=intel_id,
            threat_classification=classification,
            entities=entities,
            crime_patterns=patterns,
            tech_chains=chains,
            summary=summary,
            risk_score=risk_score,
            analyzed_at=datetime.now(timezone.utc),
        )

        elapsed = (time.time() - start) * 1000
        logger.info(f"Intelligence analysis completed: {intel_id[:8]}, risk={risk_score:.2f}, entities={len(entities)}, elapsed={elapsed:.0f}ms")
        return result

    async def classify_only(self, text: str) -> ThreatClassification:
        return await self._classifier.classify(text)

    async def extract_entities_only(self, text: str) -> List[ExtractedEntity]:
        return await self._extractor.extract(text)

    def _compute_risk_score(self, classification: ThreatClassification, entities: List[ExtractedEntity], patterns: List[CrimePattern]) -> float:
        score = 0.0
        level_weights = {"critical": 0.4, "high": 0.3, "medium": 0.2, "low": 0.1, "info": 0.0}
        score += level_weights.get(classification.threat_level, 0.0)
        score += min(0.2, len(entities) * 0.02)
        if patterns:
            max_severity = max(level_weights.get(p.severity, 0.0) for p in patterns)
            score += max_severity * 0.4
        return min(1.0, score)

    async def _generate_summary(self, text: str, classification: ThreatClassification, entities: List[ExtractedEntity], patterns: List[CrimePattern], chains: List[TechChain], industry: str = "") -> str:
        if not self._llm:
            return self._rule_based_summary(classification, entities, patterns, chains)

        industry_context = ""
        if industry and industry in INDUSTRY_THREAT_MAPPING:
            industry_info = INDUSTRY_THREAT_MAPPING[industry]
            industry_context = f"\n行业背景: {industry_info['name']}，重点关注: {', '.join(industry_info['threat_focus'])}"

        entity_desc = "\n".join([f"- {e.entity_label}: {e.value}" for e in entities[:15]])
        pattern_desc = "\n".join([f"- {p.description}(严重性:{p.severity})" for p in patterns])
        chain_desc = "\n".join([f"- {c.chain_type}: {'→'.join(s.get('step','') for s in c.steps)}" for c in chains])

        prompt = (
            f"请基于以下黑灰产情报分析结果生成简洁的分析总结：\n\n"
            f"威胁分类: {classification.category_label}({classification.threat_level}级)\n"
            f"风险评分: {self._compute_risk_score(classification, entities, patterns):.2f}\n"
            f"识别实体:\n{entity_desc or '无'}\n"
            f"犯罪模式:\n{pattern_desc or '无'}\n"
            f"技术链路:\n{chain_desc or '无'}\n"
            f"{industry_context}\n\n"
            f"请生成200字以内的分析总结，包含威胁定性、关键发现和处置建议。"
        )

        try:
            response = await self._llm.chat(prompt)
            if isinstance(response, dict):
                return response.get("content", "")[:500]
            elif isinstance(response, str):
                return response[:500]
        except Exception as exc:
            logger.warning(f"LLM摘要生成失败: {exc}")

        return self._rule_based_summary(classification, entities, patterns, chains)

    def _rule_based_summary(self, classification: ThreatClassification, entities: List[ExtractedEntity], patterns: List[CrimePattern], chains: List[TechChain]) -> str:
        parts = [f"该情报涉及{classification.category_label}类威胁，威胁等级为{classification.threat_level}级。"]
        if entities:
            entity_summary = defaultdict(list)
            for e in entities:
                entity_summary[e.entity_label].append(e.value)
            for label, values in entity_summary.items():
                parts.append(f"识别到{label}: {', '.join(values[:3])}。")
        if patterns:
            parts.append(f"发现{len(patterns)}个犯罪模式。")
        if chains:
            parts.append(f"发现{len(chains)}条技术链路。")
        return "".join(parts)

    def get_industry_config(self, industry: str) -> Optional[Dict]:
        return INDUSTRY_THREAT_MAPPING.get(industry)

    def get_all_industries(self) -> Dict[str, Dict]:
        return dict(INDUSTRY_THREAT_MAPPING)

    def get_threat_categories(self) -> Dict[str, Dict]:
        return dict(THREAT_CATEGORIES)

    def get_entity_types(self) -> Dict[str, Dict]:
        return dict(ENTITY_TYPES)
