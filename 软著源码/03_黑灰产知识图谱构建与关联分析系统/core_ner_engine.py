import ipaddress
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from loguru import logger

from app.core.rule_based_extractor import RuleBasedExtractor


@dataclass
class NEREntity:
    entity_type: str
    value: str
    start: int
    end: int
    confidence: float
    source: str = "rule"
    context: str = ""
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        d = {
            "type": self.entity_type,
            "value": self.value,
            "start": self.start,
            "end": self.end,
            "confidence": round(self.confidence, 4),
            "source": self.source,
        }
        if self.context:
            d["context"] = self.context
        if self.metadata:
            d["metadata"] = self.metadata
        return d


_VALID_TLDS = {
    "com", "net", "org", "io", "cn", "cc", "tk", "ml", "ga", "cf", "gq",
    "xyz", "top", "club", "online", "site", "info", "biz", "ru", "uk", "de",
    "fr", "jp", "kr", "tw", "hk", "me", "tv", "co", "app", "dev", "onion",
    "mobi", "pro", "asia", "name", "ws", "am", "fm", "cd", "dj", "la", "ms",
    "nu", "sc", "tg", "vc", "ag", "bz", "lc", "mn", "ph", "pk", "sg", "th",
    "vn", "id", "my", "in", "br", "mx", "ar", "cl", "pe", "ec", "ve", "co",
    "au", "nz", "za", "ng", "ke", "eg", "sa", "ae", "il", "tr", "ir", "pk",
    "bd", "lk", "mm", "kh", "la", "kp", "mn", "kz", "uz", "tj", "tm", "az",
    "ge", "am", "by", "ua", "md", "ro", "bg", "rs", "hr", "si", "sk", "cz",
    "pl", "lt", "lv", "ee", "fi", "se", "no", "dk", "is", "ie", "pt", "es",
    "it", "gr", "al", "mk", "ba", "me", "xk", "mt", "cy", "lu", "be", "nl",
    "at", "ch", "li", "hu", "sk", "si",
}

_ID_CARD_WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
_ID_CARD_CHECK = "10X98765432"

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
    r'+(?:[a-zA-Z]{2,})\b'
)
_URL_PATTERN = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)
_EMAIL_PATTERN = re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')
_PHONE_CN_PATTERN = re.compile(r'\b1[3-9]\d{9}\b')
_ID_CARD_PATTERN = re.compile(r'\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b')
_BANK_CARD_PATTERN = re.compile(r'\b(?:62|4|5)\d{14,18}\b')
_CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
_MD5_PATTERN = re.compile(r'\b[a-fA-F0-9]{32}\b')
_SHA256_PATTERN = re.compile(r'\b[a-fA-F0-9]{64}\b')
_BTC_PATTERN = re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b')
_BTC_BECH32_PATTERN = re.compile(r'\bbc1[a-zA-HJ-NP-Z0-9]{25,90}\b')
_ETH_PATTERN = re.compile(r'\b0x[a-fA-F0-9]{40}\b')
_TRON_PATTERN = re.compile(r'\bT[A-Za-z1-9]{33}\b')
_TELEGRAM_CHANNEL_PATTERN = re.compile(r'@([a-zA-Z]\w{4,31})')
_DARKWEB_MARKET_PATTERN = re.compile(
    r'(?:暗网市场|darkweb\s*market|黑市|暗市|underground\s*market)',
    re.IGNORECASE,
)
_THREAT_ACTOR_PATTERN = re.compile(
    r'(?:APT\d{1,4}|Lazarus|Kimsuky|Carbanak|FIN\d{1,4}|TA\d{1,4}|'
    r'黑产团伙|灰产组织|黑客组织|攻击组织|威胁行为者)',
    re.IGNORECASE,
)
_MALWARE_NAME_PATTERN = re.compile(
    r'(?:木马|病毒|蠕虫|勒索软件|远控|RAT|botnet|trojan|worm|ransomware|'
    r'malware|backdoor|rootkit|keylogger|spyware|adware|dropper|loader|'
    r'冰蝎|蚁剑|哥斯拉|Cobalt\s*Strike|Metasploit|Emotet|TrickBot|'
    r'QakBot|IcedID|Dridex|Zeus|SpyEye|Carberp|Flame|Stuxnet)',
    re.IGNORECASE,
)
_TOOL_NAME_CONTEXT_PATTERN = re.compile(
    r'(?:工具|tool|软件|software|程序|program)[：:\s]*([a-zA-Z0-9_\-\u4e00-\u9fff]{2,40})\b',
    re.IGNORECASE,
)


def _validate_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return not (
            addr.is_private or addr.is_reserved or addr.is_loopback
            or addr.is_multicast or addr.is_link_local
        )
    except ValueError:
        return False


def _validate_domain(domain: str) -> bool:
    parts = domain.split(".")
    if len(parts) < 2:
        return False
    tld = parts[-1].lower()
    return tld in _VALID_TLDS


def _luhn_check(number_str: str) -> bool:
    digits = [int(d) for d in number_str if d.isdigit()]
    if not digits:
        return False
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    total = sum(odd_digits)
    for d in even_digits:
        total += sum(divmod(d * 2, 10))
    return total % 10 == 0


def _validate_id_card(id_str: str) -> bool:
    if len(id_str) != 18:
        return False
    digits = id_str[:17]
    if not digits.isdigit():
        return False
    try:
        total = sum(int(d) * w for d, w in zip(digits, _ID_CARD_WEIGHTS))
        check_char = _ID_CARD_CHECK[total % 11]
        return id_str[-1].upper() == check_char
    except (ValueError, IndexError):
        return False


class EnhancedRuleNER:
    def extract(self, text: str) -> List[NEREntity]:
        if not text:
            return []
        entities: List[NEREntity] = []
        seen: Dict[str, str] = {}
        extractors = [
            self._extract_ips,
            self._extract_domains,
            self._extract_urls,
            self._extract_emails,
            self._extract_phones,
            self._extract_id_cards,
            self._extract_bank_cards,
            self._extract_cves,
            self._extract_md5,
            self._extract_sha256,
            self._extract_crypto_wallets,
            self._extract_telegram_channels,
            self._extract_darkweb_markets,
            self._extract_threat_actors,
            self._extract_malware_names,
            self._extract_tool_names,
        ]
        for extractor in extractors:
            for entity in extractor(text):
                key = f"{entity.entity_type}:{entity.value}"
                if key not in seen:
                    seen[key] = entity.entity_type
                    entities.append(entity)
        return entities

    def _extract_ips(self, text: str) -> List[NEREntity]:
        results = []
        for match in _IPV4_PATTERN.finditer(text):
            val = match.group()
            is_valid = _validate_ip(val)
            is_private = bool(_IPV4_PRIVATE.fullmatch(val))
            confidence = 0.6 if is_private else (0.95 if is_valid else 0.7)
            results.append(NEREntity(
                entity_type="IP", value=val,
                start=match.start(), end=match.end(),
                confidence=confidence, source="rule",
                metadata={"is_private": is_private, "is_valid_public": is_valid},
            ))
        return results

    def _extract_domains(self, text: str) -> List[NEREntity]:
        results = []
        for match in _DOMAIN_PATTERN.finditer(text):
            val = match.group()
            if _URL_PATTERN.search(val):
                continue
            is_valid = _validate_domain(val)
            confidence = 0.9 if is_valid else 0.5
            results.append(NEREntity(
                entity_type="DOMAIN", value=val,
                start=match.start(), end=match.end(),
                confidence=confidence, source="rule",
                metadata={"tld_valid": is_valid},
            ))
        return results

    def _extract_urls(self, text: str) -> List[NEREntity]:
        results = []
        for match in _URL_PATTERN.finditer(text):
            val = match.group()
            results.append(NEREntity(
                entity_type="URL", value=val,
                start=match.start(), end=match.end(),
                confidence=0.95, source="rule",
            ))
        return results

    def _extract_emails(self, text: str) -> List[NEREntity]:
        results = []
        for match in _EMAIL_PATTERN.finditer(text):
            val = match.group()
            results.append(NEREntity(
                entity_type="EMAIL", value=val,
                start=match.start(), end=match.end(),
                confidence=0.92, source="rule",
            ))
        return results

    def _extract_phones(self, text: str) -> List[NEREntity]:
        results = []
        for match in _PHONE_CN_PATTERN.finditer(text):
            val = match.group()
            results.append(NEREntity(
                entity_type="PHONE", value=val,
                start=match.start(), end=match.end(),
                confidence=0.88, source="rule",
            ))
        return results

    def _extract_id_cards(self, text: str) -> List[NEREntity]:
        results = []
        for match in _ID_CARD_PATTERN.finditer(text):
            val = match.group()
            is_valid = _validate_id_card(val)
            confidence = 0.93 if is_valid else 0.4
            results.append(NEREntity(
                entity_type="ID_CARD", value=val[:6] + "********" + val[-4:],
                start=match.start(), end=match.end(),
                confidence=confidence, source="rule",
                metadata={"luhn_valid": is_valid},
            ))
        return results

    def _extract_bank_cards(self, text: str) -> List[NEREntity]:
        results = []
        for match in _BANK_CARD_PATTERN.finditer(text):
            val = match.group()
            if _PHONE_CN_PATTERN.fullmatch(val):
                continue
            is_valid = _luhn_check(val)
            confidence = 0.9 if is_valid else 0.5
            results.append(NEREntity(
                entity_type="BANK_CARD", value=val[:4] + "****" + val[-4:],
                start=match.start(), end=match.end(),
                confidence=confidence, source="rule",
                metadata={"luhn_valid": is_valid},
            ))
        return results

    def _extract_cves(self, text: str) -> List[NEREntity]:
        results = []
        for match in _CVE_PATTERN.finditer(text):
            val = match.group()
            results.append(NEREntity(
                entity_type="CVE", value=val,
                start=match.start(), end=match.end(),
                confidence=0.95, source="rule",
            ))
        return results

    def _extract_md5(self, text: str) -> List[NEREntity]:
        results = []
        for match in _MD5_PATTERN.finditer(text):
            val = match.group()
            results.append(NEREntity(
                entity_type="MD5", value=val,
                start=match.start(), end=match.end(),
                confidence=0.8, source="rule",
            ))
        return results

    def _extract_sha256(self, text: str) -> List[NEREntity]:
        results = []
        for match in _SHA256_PATTERN.finditer(text):
            val = match.group()
            results.append(NEREntity(
                entity_type="SHA256", value=val,
                start=match.start(), end=match.end(),
                confidence=0.9, source="rule",
            ))
        return results

    def _extract_crypto_wallets(self, text: str) -> List[NEREntity]:
        results = []
        for match in _BTC_PATTERN.finditer(text):
            val = match.group()
            if _IPV4_PATTERN.fullmatch(val):
                continue
            results.append(NEREntity(
                entity_type="CRYPTO_WALLET", value=val,
                start=match.start(), end=match.end(),
                confidence=0.82, source="rule",
                metadata={"crypto_type": "btc"},
            ))
        for match in _BTC_BECH32_PATTERN.finditer(text):
            val = match.group()
            results.append(NEREntity(
                entity_type="CRYPTO_WALLET", value=val,
                start=match.start(), end=match.end(),
                confidence=0.88, source="rule",
                metadata={"crypto_type": "btc_bech32"},
            ))
        for match in _ETH_PATTERN.finditer(text):
            val = match.group()
            results.append(NEREntity(
                entity_type="CRYPTO_WALLET", value=val,
                start=match.start(), end=match.end(),
                confidence=0.87, source="rule",
                metadata={"crypto_type": "eth"},
            ))
        for match in _TRON_PATTERN.finditer(text):
            val = match.group()
            results.append(NEREntity(
                entity_type="CRYPTO_WALLET", value=val,
                start=match.start(), end=match.end(),
                confidence=0.85, source="rule",
                metadata={"crypto_type": "tron"},
            ))
        return results

    def _extract_telegram_channels(self, text: str) -> List[NEREntity]:
        results = []
        for match in _TELEGRAM_CHANNEL_PATTERN.finditer(text):
            val = match.group(1)
            results.append(NEREntity(
                entity_type="TELEGRAM_CHANNEL", value=f"@{val}",
                start=match.start(), end=match.end(),
                confidence=0.75, source="rule",
            ))
        return results

    def _extract_darkweb_markets(self, text: str) -> List[NEREntity]:
        results = []
        for match in _DARKWEB_MARKET_PATTERN.finditer(text):
            val = match.group()
            results.append(NEREntity(
                entity_type="DARKWEB_MARKET", value=val,
                start=match.start(), end=match.end(),
                confidence=0.7, source="rule",
            ))
        return results

    def _extract_threat_actors(self, text: str) -> List[NEREntity]:
        results = []
        for match in _THREAT_ACTOR_PATTERN.finditer(text):
            val = match.group()
            results.append(NEREntity(
                entity_type="THREAT_ACTOR", value=val,
                start=match.start(), end=match.end(),
                confidence=0.8, source="rule",
            ))
        return results

    def _extract_malware_names(self, text: str) -> List[NEREntity]:
        results = []
        for match in _MALWARE_NAME_PATTERN.finditer(text):
            val = match.group()
            results.append(NEREntity(
                entity_type="MALWARE_NAME", value=val,
                start=match.start(), end=match.end(),
                confidence=0.75, source="rule",
            ))
        return results

    def _extract_tool_names(self, text: str) -> List[NEREntity]:
        results = []
        for match in _TOOL_NAME_CONTEXT_PATTERN.finditer(text):
            val = match.group(1)
            results.append(NEREntity(
                entity_type="TOOL_NAME", value=val,
                start=match.start(), end=match.end(),
                confidence=0.65, source="rule",
            ))
        return results


class LLMNERExtractor:
    def __init__(self, llm_service=None):
        self._llm = llm_service

    async def extract(self, text: str) -> List[NEREntity]:
        if self._llm is None:
            return []
        if not text or not text.strip():
            return []
        prompt = self._build_prompt(text)
        try:
            result = await self._llm.generate_json(
                prompt=prompt,
                system_prompt="你是黑产威胁情报实体提取专家。只返回JSON，不要其他内容。",
                temperature=0.1,
            )
            return self._parse_result(result, text)
        except Exception as exc:
            logger.warning(f"LLM NER extraction failed: {exc}")
            return []

    async def extract_batch(self, texts: List[str]) -> List[List[NEREntity]]:
        if self._llm is None:
            return [[] for _ in texts]
        if not texts:
            return []
        combined = "\n---\n".join(
            f"[情报{i+1}] {t[:500]}" for i, t in enumerate(texts)
        )
        prompt = (
            f"请从以下{len(texts)}条情报中提取实体。每条情报单独返回实体列表。\n"
            f"实体类型：IP, DOMAIN, URL, EMAIL, PHONE, ID_CARD, BANK_CARD, "
            f"CRYPTO_WALLET, CVE, MD5, SHA256, THREAT_ACTOR, MALWARE_NAME, "
            f"DARKWEB_MARKET, TELEGRAM_CHANNEL, TOOL_NAME, PERSON, ORGANIZATION\n"
            f"对于人名代称（如'老陈'、'张总'），提取为PERSON类型。\n\n"
            f"返回JSON格式：\n"
            f'{{"results": [{{"index": 1, "entities": [{{"type": "...", "value": "...", "confidence": 0.0-1.0}}]}}]}}\n\n'
            f"情报内容：\n{combined}"
        )
        try:
            result = await self._llm.generate_json(
                prompt=prompt,
                system_prompt="你是黑产威胁情报实体提取专家。只返回JSON。",
                temperature=0.1,
            )
            all_entities: List[List[NEREntity]] = [[] for _ in texts]
            results = result.get("results", [])
            for item in results:
                idx = item.get("index", 0) - 1
                if 0 <= idx < len(texts):
                    for ent in item.get("entities", []):
                        entity_type = ent.get("type", "")
                        value = ent.get("value", "")
                        confidence = float(ent.get("confidence", 0.5))
                        start = texts[idx].find(value) if value in texts[idx] else -1
                        end = start + len(value) if start >= 0 else start
                        all_entities[idx].append(NEREntity(
                            entity_type=entity_type, value=value,
                            start=max(0, start), end=max(0, end),
                            confidence=confidence, source="llm",
                        ))
            return all_entities
        except Exception as exc:
            logger.warning(f"LLM batch NER failed: {exc}")
            return [[] for _ in texts]

    def _build_prompt(self, text: str) -> str:
        return (
            f"请从以下黑产威胁情报文本中提取所有实体。\n"
            f"实体类型：IP, DOMAIN, URL, EMAIL, PHONE, ID_CARD, BANK_CARD, "
            f"CRYPTO_WALLET, CVE, MD5, SHA256, THREAT_ACTOR, MALWARE_NAME, "
            f"DARKWEB_MARKET, TELEGRAM_CHANNEL, TOOL_NAME, PERSON, ORGANIZATION\n"
            f"注意上下文消歧：如'老陈'应提取为PERSON，'那个群'结合上下文可能为TELEGRAM_CHANNEL。\n\n"
            f"返回JSON格式：\n"
            f'{{"entities": [{{"type": "...", "value": "...", "confidence": 0.0-1.0}}]}}\n\n'
            f"文本：\n{text[:3000]}"
        )

    def _parse_result(self, result: Dict, text: str) -> List[NEREntity]:
        entities = []
        for ent in result.get("entities", []):
            entity_type = ent.get("type", "")
            value = ent.get("value", "")
            confidence = float(ent.get("confidence", 0.5))
            if not entity_type or not value:
                continue
            start = text.find(value) if value in text else -1
            end = start + len(value) if start >= 0 else start
            entities.append(NEREntity(
                entity_type=entity_type, value=value,
                start=max(0, start), end=max(0, end),
                confidence=confidence, source="llm",
            ))
        return entities


class NERFusion:
    def fuse(
        self,
        rule_entities: List[NEREntity],
        llm_entities: List[NEREntity],
    ) -> List[NEREntity]:
        fused: List[NEREntity] = []
        seen: Dict[str, NEREntity] = {}

        for entity in rule_entities:
            key = f"{entity.entity_type}:{entity.value}"
            if key in seen:
                existing = seen[key]
                if entity.confidence > existing.confidence:
                    seen[key] = entity
            else:
                seen[key] = entity

        for entity in llm_entities:
            key = f"{entity.entity_type}:{entity.value}"
            if key in seen:
                existing = seen[key]
                if existing.source == "rule":
                    continue
                if entity.confidence > existing.confidence:
                    seen[key] = entity
            else:
                seen[key] = entity

        position_map: Dict[Tuple[int, int, str], NEREntity] = {}
        for entity in seen.values():
            pos_key = (entity.start, entity.end, entity.entity_type)
            if pos_key in position_map:
                existing = position_map[pos_key]
                if entity.source == "rule":
                    position_map[pos_key] = entity
                elif entity.confidence > existing.confidence:
                    position_map[pos_key] = entity
            else:
                position_map[pos_key] = entity

        fused = sorted(position_map.values(), key=lambda e: e.start)
        return fused


class ThreatNEREngine:
    def __init__(self, llm_service=None):
        self._rule_ner = EnhancedRuleNER()
        self._llm_ner = LLMNERExtractor(llm_service)
        self._fusion = NERFusion()
        self._legacy_extractor = RuleBasedExtractor()
        self._spacy_nlp = None
        self._init_spacy()

    def _init_spacy(self):
        try:
            import spacy
            try:
                self._spacy_nlp = spacy.load("zh_core_web_sm")
                logger.info("spaCy NER loaded: zh_core_web_sm")
            except OSError:
                try:
                    self._spacy_nlp = spacy.load("threat_intel_ner")
                    logger.info("spaCy NER loaded: threat_intel_ner (custom)")
                except OSError:
                    logger.info("spaCy NER model not found, using rule+LLM pipeline")
        except ImportError:
            logger.info("spaCy not installed, using rule+LLM pipeline")

    async def extract(self, text: str, use_llm: bool = True) -> List[NEREntity]:
        if not text:
            return []

        rule_entities = self._rule_ner.extract(text)

        spacy_entities: List[NEREntity] = []
        if self._spacy_nlp:
            try:
                doc = self._spacy_nlp(text)
                for ent in doc.ents:
                    spacy_entities.append(NEREntity(
                        entity_type=ent.label_,
                        value=ent.text,
                        start=ent.start_char,
                        end=ent.end_char,
                        confidence=0.7,
                        source="spacy",
                    ))
            except Exception as exc:
                logger.warning(f"spaCy NER failed: {exc}")

        llm_entities: List[NEREntity] = []
        if use_llm and self._llm_ner._llm is not None:
            try:
                llm_entities = await self._llm_ner.extract(text)
            except Exception as exc:
                logger.warning(f"LLM NER failed: {exc}")

        combined_rule = self._fusion.fuse(rule_entities, spacy_entities)
        final = self._fusion.fuse(combined_rule, llm_entities)
        return final

    async def extract_batch(self, texts: List[str], use_llm: bool = True) -> List[List[NEREntity]]:
        if not texts:
            return []

        all_rule_entities = [self._rule_ner.extract(t) for t in texts]

        all_llm_entities: List[List[NEREntity]] = [[] for _ in texts]
        if use_llm and self._llm_ner._llm is not None:
            try:
                all_llm_entities = await self._llm_ner.extract_batch(texts)
            except Exception as exc:
                logger.warning(f"LLM batch NER failed: {exc}")

        results = []
        for i, text in enumerate(texts):
            fused = self._fusion.fuse(all_rule_entities[i], all_llm_entities[i])
            results.append(fused)
        return results

    def extract_sync(self, text: str) -> List[Dict]:
        entities = self._rule_ner.extract(text)
        return [e.to_dict() for e in entities]

    def extract_legacy(self, text: str) -> list:
        return self._legacy_extractor.extract(text)

    def extract_entities_legacy(self, content: str) -> list:
        return self._legacy_extractor.extract_entities(content)
