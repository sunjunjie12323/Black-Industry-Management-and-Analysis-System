import re
from typing import Dict, List, Optional, Tuple
from loguru import logger


_EMOJI_RANGES = [
    (0x1F600, 0x1F64F),
    (0x1F300, 0x1F5FF),
    (0x1F680, 0x1F6FF),
    (0x1F1E0, 0x1F1FF),
    (0x2702, 0x27B0),
    (0x1F900, 0x1F9FF),
    (0x2600, 0x26FF),
    (0x2700, 0x27BF),
    (0xFE00, 0xFE0F),
    (0x1FA00, 0x1FA6F),
    (0x1FA70, 0x1FAFF),
    (0x200D,),
    (0x20E3,),
    (0xE0020, 0xE007F),
]


def _strip_emojis(text: str) -> str:
    result = []
    for ch in text:
        cp = ord(ch)
        is_emoji = False
        for rng in _EMOJI_RANGES:
            if len(rng) == 1:
                if cp == rng[0]:
                    is_emoji = True
                    break
            else:
                if rng[0] <= cp <= rng[1]:
                    is_emoji = True
                    break
        if not is_emoji:
            result.append(ch)
    return ''.join(result)


_IPV4_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)
_IPV4_PRIVATE = re.compile(
    r'\b(?:(?:10|127)\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
    r'(?:172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}|'
    r'192\.168\.\d{1,3}\.\d{1,3})\b'
)
_DOMAIN_PATTERN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)'
    r'+(?:com|net|org|io|cn|cc|tk|ml|ga|cf|gq|xyz|top|club|online|site|info|biz|ru|uk|de|fr|jp|kr|tw|hk|me|tv|co|app|dev)\b'
)
_URL_PATTERN = re.compile(
    r'https?://[^\s<>"\']+', re.IGNORECASE
)
_PHONE_CN_PATTERN = re.compile(
    r'\b1[3-9]\d{9}\b'
)
_PHONE_INTERNATIONAL_PATTERN = re.compile(
    r'\b\+\d{1,3}[-\s]?\d{4,14}\b'
)
_EMAIL_PATTERN = re.compile(
    r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
)
_BTC_ADDRESS_PATTERN = re.compile(
    r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'
)
_BTC_BECH32_PATTERN = re.compile(
    r'\bbc1[a-zA-HJ-NP-Z0-9]{25,90}\b'
)
_ETH_ADDRESS_PATTERN = re.compile(
    r'\b0x[a-fA-F0-9]{40}\b'
)
_TRON_ADDRESS_PATTERN = re.compile(
    r'\bT[A-Za-z1-9]{33}\b'
)
_QQ_PATTERN = re.compile(
    r'(?:QQ|qq|企鹅)[：:\s]*(\d{5,12})\b'
)
_WECHAT_PATTERN = re.compile(
    r'(?:微信|vx|weixin|wechat)[：:\s]*([a-zA-Z0-9_-]{5,20})\b',
    re.IGNORECASE,
)
_TELEGRAM_PATTERN = re.compile(
    r'(?:telegram|tg|电报)[：:\s]*@?([a-zA-Z0-9_]{5,32})\b',
    re.IGNORECASE,
)
_BANK_CARD_PATTERN = re.compile(
    r'\b(?:62|4|5)\d{14,18}\b'
)
_CVE_PATTERN = re.compile(
    r'CVE-\d{4}-\d{4,}', re.IGNORECASE
)
_MD5_PATTERN = re.compile(
    r'\b[a-fA-F0-9]{32}\b'
)
_SHA256_PATTERN = re.compile(
    r'\b[a-fA-F0-9]{64}\b'
)
_ACCOUNT_GENERIC_PATTERN = re.compile(
    r'(?:账号|账户|account)[：:\s]*([a-zA-Z0-9_-]{3,30})\b',
    re.IGNORECASE,
)
_TOOL_NAME_PATTERN = re.compile(
    r'(?:工具|tool|软件|software)[：:\s]*([a-zA-Z0-9_\-\u4e00-\u9fff]{2,40})\b',
    re.IGNORECASE,
)

_HIGH_RISK_KEYWORDS = {
    "fraud": [
        "诈骗", "杀猪盘", "套路贷", "电信诈骗", "刷单", "兼职诈骗",
        "投资理财", "虚假平台", "跑路", "庞氏", "传销", "资金盘",
        "骗", "割韭菜", "P2P", "套路", "返利",
    ],
    "gambling": [
        "赌博", "菠菜", "博彩", "盘口", "代理", "下注", "赔率",
        "赌场", "百家乐", "老虎机", "彩票", "六合彩",
    ],
    "hacking": [
        "入侵", "渗透", "提权", "后门", "木马", "RAT", "远控",
        "webshell", "0day", "漏洞", "exploit", "撞库", "脱裤",
        "拖库", "洗库", "注入", "XSS", "CSRF", "SSRF",
    ],
    "money_laundering": [
        "洗钱", "跑分", "水房", "过桥", "套现", "四件套",
        "黑卡", "码商", "通道", "走账", "对敲", "虚拟币洗",
    ],
    "phishing": [
        "钓鱼", "仿冒", "伪造", "假冒", "钓鱼网站", "仿冒页面",
        "盗号", "盗取", "窃取", "credential", "phishing",
    ],
    "ransomware": [
        "勒索", "加密", "lockbit", "ransomware", "赎金", "解密",
    ],
    "data_theft": [
        "脱库", "数据泄露", "信息贩卖", "社工库", "开房数据",
        "快递数据", "学生数据", "车主数据", "泄露", "数据买卖",
    ],
    "tool_sales": [
        "出售", "售卖", "代开", "代办", "黑产工具", "接码",
        "猫池", "群控", "养号", "秒杀", "抢单",
    ],
    "drug": [
        "毒品", "大麻", "冰毒", "海洛因", "摇头丸", "K粉",
    ],
}

_TOOL_KEYWORDS = {
    "猫池", "群控", "接码平台", "秒杀器", "抢单软件", "养号工具",
    "撞库工具", "扫描器", "爆破工具", "代理池", "VPN", "暗网浏览器",
    "加密通讯", "虚拟机", "沙箱", "抓包", "中间人", "键盘记录",
    "远控木马", "RAT", "webshell", "一句话木马", "冰蝎", "蚁剑",
    "哥斯拉", "Cobalt Strike", "CS", "Metasploit", "Nmap",
    "Hydra", "Sqlmap", "BurpSuite",
}

_ORG_KEYWORDS = {
    "团伙", "组织", "工作室", "团队", "公司", "集团",
    "黑产", "灰产", "地下", "暗网",
}

_TYPE_CONFIDENCE = {
    "ip": 0.95,
    "domain": 0.9,
    "url": 0.95,
    "email": 0.92,
    "phone": 0.88,
    "crypto_address": 0.85,
    "account": 0.75,
    "tool_name": 0.65,
}


class RuleBasedExtractor:
    def extract(self, text: str) -> list[dict]:
        if not text:
            return []

        entities: list[dict] = []
        seen: Dict[str, str] = {}

        for entity in self.extract_ips(text):
            val = entity["value"]
            if val not in seen:
                seen[val] = "ip"
                entities.append(entity)

        for entity in self.extract_urls(text):
            val = entity["value"]
            if val not in seen:
                seen[val] = "url"
                entities.append(entity)

        for entity in self.extract_domains(text):
            val = entity["value"]
            if val not in seen and not _URL_PATTERN.search(val):
                seen[val] = "domain"
                entities.append(entity)

        for entity in self.extract_emails(text):
            val = entity["value"]
            if val not in seen:
                seen[val] = "email"
                entities.append(entity)

        for entity in self.extract_phones(text):
            val = entity["value"]
            if val not in seen:
                seen[val] = "phone"
                entities.append(entity)

        for entity in self.extract_crypto_addresses(text):
            val = entity["value"]
            if val not in seen:
                seen[val] = "crypto_address"
                entities.append(entity)

        for entity in self._extract_accounts(text):
            val = entity["value"]
            if val not in seen:
                seen[val] = "account"
                entities.append(entity)

        for entity in self._extract_tool_names(text):
            val = entity["value"]
            if val not in seen:
                seen[val] = "tool_name"
                entities.append(entity)

        for entity in self._extract_cves(text):
            val = entity["value"]
            if val not in seen:
                seen[val] = "cve"
                entities.append(entity)

        for entity in self._extract_hashes(text):
            val = entity["value"]
            if val not in seen:
                seen[val] = "hash"
                entities.append(entity)

        for entity in self._extract_organizations(text):
            val = entity["value"]
            if val not in seen:
                seen[val] = "organization"
                entities.append(entity)

        return entities

    def extract_ips(self, text: str) -> list[dict]:
        results = []
        for match in _IPV4_PATTERN.finditer(text):
            val = match.group()
            is_private = bool(_IPV4_PRIVATE.fullmatch(val))
            confidence = 0.6 if is_private else _TYPE_CONFIDENCE["ip"]
            results.append({
                "type": "ip",
                "value": val,
                "start": match.start(),
                "end": match.end(),
                "confidence": confidence,
            })
        return results

    def extract_domains(self, text: str) -> list[dict]:
        results = []
        for match in _DOMAIN_PATTERN.finditer(text):
            val = match.group()
            results.append({
                "type": "domain",
                "value": val,
                "start": match.start(),
                "end": match.end(),
                "confidence": _TYPE_CONFIDENCE["domain"],
            })
        return results

    def extract_urls(self, text: str) -> list[dict]:
        results = []
        for match in _URL_PATTERN.finditer(text):
            val = match.group()
            results.append({
                "type": "url",
                "value": val,
                "start": match.start(),
                "end": match.end(),
                "confidence": _TYPE_CONFIDENCE["url"],
            })
        return results

    def extract_emails(self, text: str) -> list[dict]:
        results = []
        for match in _EMAIL_PATTERN.finditer(text):
            val = match.group()
            results.append({
                "type": "email",
                "value": val,
                "start": match.start(),
                "end": match.end(),
                "confidence": _TYPE_CONFIDENCE["email"],
            })
        return results

    def extract_phones(self, text: str) -> list[dict]:
        results = []
        for match in _PHONE_CN_PATTERN.finditer(text):
            val = match.group()
            results.append({
                "type": "phone",
                "value": val,
                "start": match.start(),
                "end": match.end(),
                "confidence": _TYPE_CONFIDENCE["phone"],
            })
        for match in _PHONE_INTERNATIONAL_PATTERN.finditer(text):
            val = match.group()
            if val not in {r["value"] for r in results}:
                results.append({
                    "type": "phone",
                    "value": val,
                    "start": match.start(),
                    "end": match.end(),
                    "confidence": 0.8,
                })
        return results

    def extract_crypto_addresses(self, text: str) -> list[dict]:
        results = []
        for match in _BTC_ADDRESS_PATTERN.finditer(text):
            val = match.group()
            if not _IPV4_PATTERN.fullmatch(val):
                results.append({
                    "type": "crypto_address",
                    "value": val,
                    "start": match.start(),
                    "end": match.end(),
                    "confidence": 0.82,
                    "crypto_type": "btc",
                })
        for match in _BTC_BECH32_PATTERN.finditer(text):
            val = match.group()
            if val not in {r["value"] for r in results}:
                results.append({
                    "type": "crypto_address",
                    "value": val,
                    "start": match.start(),
                    "end": match.end(),
                    "confidence": 0.88,
                    "crypto_type": "btc_bech32",
                })
        for match in _ETH_ADDRESS_PATTERN.finditer(text):
            val = match.group()
            if val not in {r["value"] for r in results}:
                results.append({
                    "type": "crypto_address",
                    "value": val,
                    "start": match.start(),
                    "end": match.end(),
                    "confidence": 0.87,
                    "crypto_type": "eth",
                })
        for match in _TRON_ADDRESS_PATTERN.finditer(text):
            val = match.group()
            if val not in {r["value"] for r in results}:
                results.append({
                    "type": "crypto_address",
                    "value": val,
                    "start": match.start(),
                    "end": match.end(),
                    "confidence": 0.85,
                    "crypto_type": "tron",
                })
        return results

    def _extract_accounts(self, text: str) -> list[dict]:
        results = []
        for match in _QQ_PATTERN.finditer(text):
            val = match.group(1)
            results.append({
                "type": "account",
                "value": f"QQ:{val}",
                "start": match.start(),
                "end": match.end(),
                "confidence": _TYPE_CONFIDENCE["account"],
                "account_type": "qq",
            })
        for match in _WECHAT_PATTERN.finditer(text):
            val = match.group(1)
            results.append({
                "type": "account",
                "value": f"微信:{val}",
                "start": match.start(),
                "end": match.end(),
                "confidence": _TYPE_CONFIDENCE["account"],
                "account_type": "wechat",
            })
        for match in _TELEGRAM_PATTERN.finditer(text):
            val = match.group(1)
            results.append({
                "type": "account",
                "value": f"TG:@{val}",
                "start": match.start(),
                "end": match.end(),
                "confidence": _TYPE_CONFIDENCE["account"],
                "account_type": "telegram",
            })
        for match in _ACCOUNT_GENERIC_PATTERN.finditer(text):
            val = match.group(1)
            if val not in {r["value"] for r in results}:
                results.append({
                    "type": "account",
                    "value": val,
                    "start": match.start(),
                    "end": match.end(),
                    "confidence": 0.6,
                    "account_type": "generic",
                })
        return results

    def _extract_tool_names(self, text: str) -> list[dict]:
        results = []
        content_lower = text.lower()
        for tool in _TOOL_KEYWORDS:
            if tool.lower() in content_lower:
                idx = content_lower.index(tool.lower())
                results.append({
                    "type": "tool_name",
                    "value": tool,
                    "start": idx,
                    "end": idx + len(tool),
                    "confidence": _TYPE_CONFIDENCE["tool_name"],
                })
        for match in _TOOL_NAME_PATTERN.finditer(text):
            val = match.group(1)
            if val not in {r["value"] for r in results}:
                results.append({
                    "type": "tool_name",
                    "value": val,
                    "start": match.start(),
                    "end": match.end(),
                    "confidence": 0.55,
                })
        return results

    def _extract_cves(self, text: str) -> list[dict]:
        results = []
        for match in _CVE_PATTERN.finditer(text):
            val = match.group()
            results.append({
                "type": "cve",
                "value": val,
                "start": match.start(),
                "end": match.end(),
                "confidence": 0.95,
            })
        return results

    def _extract_hashes(self, text: str) -> list[dict]:
        results = []
        for match in _SHA256_PATTERN.finditer(text):
            val = match.group()
            results.append({
                "type": "hash",
                "value": val,
                "start": match.start(),
                "end": match.end(),
                "confidence": 0.9,
                "hash_type": "sha256",
            })
        for match in _MD5_PATTERN.finditer(text):
            val = match.group()
            existing_vals = {r["value"] for r in results}
            if val not in existing_vals:
                results.append({
                    "type": "hash",
                    "value": val,
                    "start": match.start(),
                    "end": match.end(),
                    "confidence": 0.8,
                    "hash_type": "md5",
                })
        return results

    def _extract_organizations(self, text: str) -> list[dict]:
        results = []
        for org in _ORG_KEYWORDS:
            if org in text:
                idx = text.index(org)
                results.append({
                    "type": "organization",
                    "value": org,
                    "start": idx,
                    "end": idx + len(org),
                    "confidence": 0.6,
                })
        return results

    def extract_entities(self, content: str) -> List[Dict]:
        if not content:
            return []

        entities: List[Dict] = []
        seen: Dict[str, str] = {}

        for match in _IPV4_PATTERN.finditer(content):
            val = match.group()
            if val not in seen:
                seen[val] = "ip"
                entities.append({
                    "type": "ip",
                    "value": val,
                    "start": match.start(),
                    "end": match.end(),
                    "confidence": _TYPE_CONFIDENCE["ip"],
                    "context": self._get_context(content, match.start(), match.end()),
                })

        for match in _URL_PATTERN.finditer(content):
            val = match.group()
            if val not in seen:
                seen[val] = "url"
                entities.append({
                    "type": "url",
                    "value": val,
                    "start": match.start(),
                    "end": match.end(),
                    "confidence": _TYPE_CONFIDENCE["url"],
                    "context": self._get_context(content, match.start(), match.end()),
                })

        for match in _DOMAIN_PATTERN.finditer(content):
            val = match.group()
            if val not in seen and not _URL_PATTERN.search(val):
                seen[val] = "domain"
                entities.append({
                    "type": "domain",
                    "value": val,
                    "start": match.start(),
                    "end": match.end(),
                    "confidence": _TYPE_CONFIDENCE["domain"],
                    "context": self._get_context(content, match.start(), match.end()),
                })

        for match in _PHONE_CN_PATTERN.finditer(content):
            val = match.group()
            if val not in seen:
                seen[val] = "phone"
                entities.append({
                    "type": "phone",
                    "value": val,
                    "start": match.start(),
                    "end": match.end(),
                    "confidence": _TYPE_CONFIDENCE["phone"],
                    "context": self._get_context(content, match.start(), match.end()),
                })

        for match in _EMAIL_PATTERN.finditer(content):
            val = match.group()
            if val not in seen:
                seen[val] = "email"
                entities.append({
                    "type": "email",
                    "value": val,
                    "start": match.start(),
                    "end": match.end(),
                    "confidence": _TYPE_CONFIDENCE["email"],
                    "context": self._get_context(content, match.start(), match.end()),
                })

        for match in _BTC_ADDRESS_PATTERN.finditer(content):
            val = match.group()
            if val not in seen and not _IPV4_PATTERN.fullmatch(val):
                seen[val] = "crypto_wallet"
                entities.append({
                    "type": "crypto_wallet",
                    "value": val,
                    "start": match.start(),
                    "end": match.end(),
                    "confidence": 0.82,
                    "context": self._get_context(content, match.start(), match.end()),
                })

        for match in _ETH_ADDRESS_PATTERN.finditer(content):
            val = match.group()
            if val not in seen:
                seen[val] = "crypto_wallet"
                entities.append({
                    "type": "crypto_wallet",
                    "value": val,
                    "start": match.start(),
                    "end": match.end(),
                    "confidence": 0.87,
                    "context": self._get_context(content, match.start(), match.end()),
                })

        for match in _QQ_PATTERN.finditer(content):
            val = match.group(1)
            if val not in seen:
                seen[val] = "account"
                entities.append({
                    "type": "account",
                    "value": f"QQ:{val}",
                    "start": match.start(),
                    "end": match.end(),
                    "confidence": _TYPE_CONFIDENCE["account"],
                    "context": self._get_context(content, match.start(), match.end()),
                })

        for match in _WECHAT_PATTERN.finditer(content):
            val = match.group(1)
            if val not in seen:
                seen[val] = "account"
                entities.append({
                    "type": "account",
                    "value": f"微信:{val}",
                    "start": match.start(),
                    "end": match.end(),
                    "confidence": _TYPE_CONFIDENCE["account"],
                    "context": self._get_context(content, match.start(), match.end()),
                })

        for match in _TELEGRAM_PATTERN.finditer(content):
            val = match.group(1)
            if val not in seen:
                seen[val] = "account"
                entities.append({
                    "type": "account",
                    "value": f"TG:@{val}",
                    "start": match.start(),
                    "end": match.end(),
                    "confidence": _TYPE_CONFIDENCE["account"],
                    "context": self._get_context(content, match.start(), match.end()),
                })

        for match in _BANK_CARD_PATTERN.finditer(content):
            val = match.group()
            if val not in seen and not _PHONE_CN_PATTERN.fullmatch(val):
                seen[val] = "payment_method"
                entities.append({
                    "type": "payment_method",
                    "value": val,
                    "start": match.start(),
                    "end": match.end(),
                    "confidence": 0.7,
                    "context": self._get_context(content, match.start(), match.end()),
                })

        for match in _CVE_PATTERN.finditer(content):
            val = match.group()
            if val not in seen:
                seen[val] = "cve"
                entities.append({
                    "type": "tool",
                    "value": val,
                    "start": match.start(),
                    "end": match.end(),
                    "confidence": 0.95,
                    "context": self._get_context(content, match.start(), match.end()),
                })

        for match in _SHA256_PATTERN.finditer(content):
            val = match.group()
            if val not in seen:
                seen[val] = "hash"
                entities.append({
                    "type": "tool",
                    "value": f"SHA256:{val[:16]}...",
                    "start": match.start(),
                    "end": match.end(),
                    "confidence": 0.9,
                    "context": self._get_context(content, match.start(), match.end()),
                })

        for match in _MD5_PATTERN.finditer(content):
            val = match.group()
            if val not in seen and val not in {e["value"] for e in entities}:
                seen[val] = "hash"
                entities.append({
                    "type": "tool",
                    "value": f"MD5:{val[:16]}...",
                    "start": match.start(),
                    "end": match.end(),
                    "confidence": 0.8,
                    "context": self._get_context(content, match.start(), match.end()),
                })

        content_lower = content.lower()
        for tool in _TOOL_KEYWORDS:
            if tool.lower() in content_lower:
                if tool not in seen:
                    seen[tool] = "tool"
                    idx = content_lower.index(tool.lower())
                    entities.append({
                        "type": "tool",
                        "value": tool,
                        "start": idx,
                        "end": idx + len(tool),
                        "confidence": _TYPE_CONFIDENCE["tool_name"],
                        "context": self._get_context(content, idx, idx + len(tool)),
                    })

        for org in _ORG_KEYWORDS:
            if org in content:
                if org not in seen:
                    seen[org] = "organization"
                    idx = content.index(org)
                    entities.append({
                        "type": "organization",
                        "value": org,
                        "start": idx,
                        "end": idx + len(org),
                        "confidence": 0.6,
                        "context": self._get_context(content, idx, idx + len(org)),
                    })

        return entities

    def classify_threat(self, content: str) -> Tuple[List[str], float]:
        if not content:
            return [], 0.0

        content_lower = content.lower()
        category_scores: Dict[str, float] = {}

        for category, keywords in _HIGH_RISK_KEYWORDS.items():
            score = 0.0
            for kw in keywords:
                count = content_lower.count(kw.lower())
                if count > 0:
                    score += count * (1.0 + (0.5 if len(kw) >= 3 else 0.0))
            if score > 0:
                category_scores[category] = score

        if not category_scores:
            return [], 0.0

        max_score = max(category_scores.values())
        total_score = sum(category_scores.values())

        threshold = max(max_score * 0.3, 1.0)
        categories = [cat for cat, sc in category_scores.items() if sc >= threshold]
        categories.sort(key=lambda c: category_scores[c], reverse=True)

        confidence = min(total_score / 10.0, 1.0)

        return categories, confidence

    def assess_threat_level(
        self,
        content: str,
        blacktalk_terms: Dict[str, str] = None,
        categories: List[str] = None,
    ) -> Tuple[str, float]:
        if not content:
            return "info", 0.0

        score = 0.0

        if categories is None:
            categories, _ = self.classify_threat(content)

        blacktalk_density = 0.0
        if blacktalk_terms and content:
            total_hits = sum(content.count(term) for term in blacktalk_terms.keys())
            density = min(total_hits / max(len(content) / 50.0, 1.0), 1.0)
            blacktalk_density = density
            score += density * 0.3

        if categories:
            critical_cats = {"drug", "ransomware"}
            high_cats = {"fraud", "hacking", "money_laundering"}
            medium_cats = {"phishing", "data_theft", "tool_sales"}
            low_cats = {"gambling"}

            if any(c in critical_cats for c in categories):
                score += 0.5
            elif any(c in high_cats for c in categories):
                score += 0.35
            elif any(c in medium_cats for c in categories):
                score += 0.2
            elif any(c in low_cats for c in categories):
                score += 0.1

        entity_count = len(self.extract(content))
        score += min(entity_count / 20.0, 0.2)

        has_url = bool(_URL_PATTERN.search(content))
        has_ip = bool(_IPV4_PATTERN.search(content))
        has_phone = bool(_PHONE_CN_PATTERN.search(content))
        has_payment = bool(_BANK_CARD_PATTERN.search(content))

        if has_url:
            score += 0.05
        if has_ip:
            score += 0.05
        if has_phone:
            score += 0.05
        if has_payment:
            score += 0.1

        score = max(0.0, min(1.0, score))

        if score >= 0.7:
            return "critical", score
        elif score >= 0.5:
            return "high", score
        elif score >= 0.3:
            return "medium", score
        elif score >= 0.1:
            return "low", score
        else:
            return "info", score

    def remove_noise_rule_based(self, content: str) -> str:
        if not content:
            return content

        cleaned = _strip_emojis(content)

        lines = cleaned.split('\n')
        meaningful_lines = []
        ad_patterns = [
            '加微信', '扫码关注', '点击关注', '推广', '广告',
            '领取红包', '转发有奖', '关注公众号', '扫码领',
            '限时优惠', '点击链接', '免费领取',
        ]
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if len(line) < 3:
                continue
            if any(p in line for p in ad_patterns):
                continue
            meaningful_lines.append(line)

        result = '\n'.join(meaningful_lines)

        cleaned = re.sub(r'\s+', ' ', result).strip()

        return cleaned if cleaned else content

    def _get_context(self, content: str, start: int, end: int, window: int = 30) -> str:
        ctx_start = max(0, start - window)
        ctx_end = min(len(content), end + window)
        return content[ctx_start:ctx_end].strip()


rule_extractor = RuleBasedExtractor()
