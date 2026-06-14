import asyncio
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from uuid import uuid4

from loguru import logger

from app.core.llm import LLMService
from app.core.vector_store import VectorStore


class BlackTalkTerm:
    def __init__(
        self,
        id: str,
        term: str,
        meaning: str,
        category: str,
        context_examples: Optional[List[str]] = None,
        confidence: float = 1.0,
        source: str = "manual",
        created_at: Optional[datetime] = None,
        updated_at: Optional[datetime] = None,
    ):
        self.id = id
        self.term = term
        self.meaning = meaning
        self.category = category
        self.context_examples = context_examples or []
        self.confidence = confidence
        self.source = source
        self.created_at = created_at or datetime.now(timezone.utc)
        self.updated_at = updated_at or datetime.now(timezone.utc)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "term": self.term,
            "meaning": self.meaning,
            "category": self.category,
            "context_examples": self.context_examples,
            "confidence": self.confidence,
            "source": self.source,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "BlackTalkTerm":
        return cls(
            id=data["id"],
            term=data["term"],
            meaning=data["meaning"],
            category=data["category"],
            context_examples=data.get("context_examples", []),
            confidence=data.get("confidence", 1.0),
            source=data.get("source", "manual"),
            created_at=datetime.fromisoformat(data["created_at"]) if isinstance(data.get("created_at"), str) else data.get("created_at", datetime.now(timezone.utc)),
            updated_at=datetime.fromisoformat(data["updated_at"]) if isinstance(data.get("updated_at"), str) else data.get("updated_at", datetime.now(timezone.utc)),
        )


class BlackTalkEngine:
    VALID_CATEGORIES = (
        "drug", "fraud", "gambling", "hacking",
        "money_laundering", "general",
    )
    AUTO_LEARN_CONFIDENCE_THRESHOLD = 0.7
    SEMANTIC_SEARCH_THRESHOLD = 0.35

    def __init__(self, vector_store: VectorStore, llm: Optional[LLMService] = None,
                 data_file: str = "./model_data/blacktalk/dictionary.json",
                 max_terms: int = 5000):
        self.llm = llm
        self.vector_store = vector_store
        self._data_file = data_file
        self._max_terms = max_terms
        self._dictionary: Dict[str, BlackTalkTerm] = {}
        self._term_index: Dict[str, str] = {}
        self._last_accessed: Dict[str, datetime] = {}
        self._lock = asyncio.Lock()
        seed = self._init_seed_dictionary()
        for term_id, bt in seed.items():
            self._dictionary[term_id] = bt
            self._term_index[bt.term] = term_id
            self._last_accessed[term_id] = bt.created_at
        self._load_from_disk()
        logger.info(f"BlackTalkEngine initialized with {len(self._dictionary)} terms")

    async def initialize_vectors(self):
        for term_id, bt in self._dictionary.items():
            content = f"{bt.term}：{bt.meaning}"
            metadata = {
                "term": bt.term,
                "meaning": bt.meaning,
                "category": bt.category,
                "confidence": bt.confidence,
                "source": bt.source,
            }
            try:
                await self.vector_store.add_blacktalk(
                    term_id=bt.id,
                    content=content,
                    metadata=metadata,
                )
            except Exception as exc:
                logger.warning(f"Failed to add seed term '{bt.term}' to vector store: {exc}")

    async def decode(self, text: str) -> Tuple[str, Dict[str, str]]:
        decoded_terms: Dict[str, str] = {}

        for term, term_id in self._term_index.items():
            if term in text:
                bt = self._dictionary[term_id]
                decoded_terms[term] = bt.meaning
                self._last_accessed[term_id] = datetime.now(timezone.utc)

        try:
            semantic_results = await self.vector_store.search_blacktalk(text, n_results=5)
            for result in semantic_results:
                distance = result.get("distance", 1.0)
                if distance is not None and distance < self.SEMANTIC_SEARCH_THRESHOLD:
                    metadata = result.get("metadata", {})
                    term_str = metadata.get("term", "")
                    meaning = metadata.get("meaning", "")
                    if term_str and term_str in text and term_str not in decoded_terms:
                        decoded_terms[term_str] = meaning
                        term_id = self._term_index.get(term_str)
                        if term_id:
                            self._last_accessed[term_id] = datetime.now(timezone.utc)
        except Exception as exc:
            logger.warning(f"Semantic blacktalk search failed: {exc}")

        if decoded_terms:
            decoded_text = text
            for term, meaning in decoded_terms.items():
                decoded_text = decoded_text.replace(term, f"{term}({meaning})")
            return decoded_text, decoded_terms

        try:
            llm_decoded = await self._llm_decode(text)
            if llm_decoded:
                decoded_terms.update(llm_decoded)
                decoded_text = text
                for term, meaning in decoded_terms.items():
                    decoded_text = decoded_text.replace(term, f"{term}({meaning})")
                return decoded_text, decoded_terms
        except Exception as exc:
            logger.warning(f"LLM blacktalk decode failed: {exc}")
            if decoded_terms:
                decoded_text = text
                for term, meaning in decoded_terms.items():
                    decoded_text = decoded_text.replace(term, f"{term}({meaning})")
                return decoded_text, decoded_terms

        return text, decoded_terms

    async def _llm_decode(self, text: str) -> Dict[str, str]:
        system_prompt = (
            "你是一个黑灰产黑话解码专家。分析以下文本中可能包含的黑话/暗语，"
            "并返回JSON格式的结果。如果文本中没有黑话，返回空对象{}。\n"
            "返回格式：{\"黑话1\": \"含义1\", \"黑话2\": \"含义2\"}\n"
            "只返回JSON，不要其他内容。"
        )
        prompt = f"分析以下文本中的黑话：\n\n{text}"
        try:
            result = await self.llm.generate_json(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=0.2,
            )
            if isinstance(result, dict) and result:
                return {str(k): str(v) for k, v in result.items()}
        except Exception as exc:
            logger.warning(f"LLM decode JSON parse failed: {exc}")
        return {}

    async def learn(
        self,
        term: str,
        meaning: str,
        context: str,
        source: str = "manual",
    ) -> BlackTalkTerm:
        existing_id = self._term_index.get(term)
        if existing_id and existing_id in self._dictionary:
            bt = self._dictionary[existing_id]
            bt.meaning = meaning
            bt.updated_at = datetime.now(timezone.utc)
            self._last_accessed[existing_id] = datetime.now(timezone.utc)
            if context and context not in bt.context_examples:
                bt.context_examples.append(context)
                if len(bt.context_examples) > 10:
                    bt.context_examples = bt.context_examples[-10:]
            if source == "manual":
                bt.source = "manual"
                bt.confidence = 1.0
            elif source == "cross_validated":
                bt.source = "cross_validated"
                bt.confidence = min(bt.confidence + 0.1, 1.0)
            else:
                if bt.source == "manual":
                    pass
                else:
                    bt.confidence = min(bt.confidence + 0.05, 0.95)
            logger.info(f"Updated blacktalk term: {term} -> {meaning} (source={source})")
        else:
            self._evict_if_needed()
            term_id = uuid4().hex
            initial_confidence = 1.0 if source == "manual" else 0.5
            bt = BlackTalkTerm(
                id=term_id,
                term=term,
                meaning=meaning,
                category=self._infer_category(meaning),
                context_examples=[context] if context else [],
                confidence=initial_confidence,
                source=source,
            )
            self._dictionary[term_id] = bt
            self._term_index[term] = term_id
            self._last_accessed[term_id] = datetime.now(timezone.utc)
            if len(self._dictionary) > self._max_terms:
                oldest_term = min(self._last_accessed, key=self._last_accessed.get) if self._last_accessed else next(iter(self._dictionary))
                self._term_index.pop(self._dictionary[oldest_term].term if hasattr(self._dictionary[oldest_term], 'term') else oldest_term, None)
                self._last_accessed.pop(oldest_term, None)
                del self._dictionary[oldest_term]
            logger.info(f"Learned new blacktalk term: {term} -> {meaning} (source={source})")

        try:
            content = f"{bt.term}：{bt.meaning}"
            metadata = {
                "term": bt.term,
                "meaning": bt.meaning,
                "category": bt.category,
                "confidence": bt.confidence,
                "source": bt.source,
            }
            await self.vector_store.add_blacktalk(
                term_id=bt.id,
                content=content,
                metadata=metadata,
            )
        except Exception as exc:
            logger.warning(f"Failed to sync learned term to vector store: {exc}")

        self._save_to_disk()
        return bt

    def _evict_if_needed(self):
        if len(self._dictionary) < self._max_terms:
            return
        evict_count = max(1, len(self._dictionary) - self._max_terms + 1)
        sorted_terms = sorted(self._last_accessed.items(), key=lambda x: x[1])
        for term_id, _ in sorted_terms[:evict_count]:
            if term_id in self._dictionary:
                term_str = self._dictionary[term_id].term
                del self._dictionary[term_id]
                self._term_index.pop(term_str, None)
                self._last_accessed.pop(term_id, None)
                logger.info(f"Evicted least-recently-accessed term: {term_str}")

    def _infer_category(self, meaning: str) -> str:
        category_keywords = {
            "drug": ["毒品", "大麻", "冰毒", "海洛因", "摇头丸", "K粉", "麻古"],
            "fraud": ["诈骗", "骗", "套路", "杀猪", "裸条", "套路贷", "电信诈骗"],
            "gambling": ["赌博", "赌", "菠菜", "盘口", "菜农", "代理", "返水"],
            "hacking": ["黑客", "木马", "挂马", "漏洞", "入侵", "后门", "提权"],
            "money_laundering": ["洗钱", "跑分", "水房", "套现", "资金盘", "四件套"],
        }
        for category, keywords in category_keywords.items():
            for kw in keywords:
                if kw in meaning:
                    return category
        return "general"

    async def auto_learn(self, text: str, decoded_terms: Dict[str, str]) -> List[BlackTalkTerm]:
        learned: List[BlackTalkTerm] = []
        async with self._lock:
            for term, meaning in decoded_terms.items():
                if term in self._term_index:
                    continue
                try:
                    cross_validated = await self._cross_validate(term, meaning)
                    if cross_validated:
                        bt = await self.learn(
                            term=term,
                            meaning=meaning,
                            context=text,
                            source="cross_validated",
                        )
                        learned.append(bt)
                        logger.info(f"Auto-learned cross-validated term: {term}")
                    else:
                        bt = await self.learn(
                            term=term,
                            meaning=meaning,
                            context=text,
                            source="llm_inferred",
                        )
                        learned.append(bt)
                        logger.info(f"Auto-learned LLM-inferred term: {term} (not yet cross-validated)")
                    self._save_to_disk()
                except Exception as exc:
                    logger.warning(f"Failed to auto-learn term '{term}': {exc}")
        return learned

    async def _cross_validate(self, term: str, meaning: str) -> bool:
        try:
            results = await self.vector_store.search_intelligence(term, n_results=5)
            if not results:
                return False
            consistent_count = 0
            for result in results:
                doc = result.get("document", "")
                if not doc:
                    continue
                prompt = (
                    f"在以下文本中，黑话「{term}」是否表示「{meaning}」？\n"
                    f"文本：{doc[:500]}\n\n"
                    f"请只回答 '是' 或 '否'。"
                )
                response = await self.llm.generate(
                    prompt=prompt,
                    system_prompt="你是一个黑灰产黑话验证专家。根据上下文判断黑话含义是否一致。",
                    temperature=0.1,
                    max_tokens=10,
                )
                if "是" in response.strip():
                    consistent_count += 1
            return consistent_count >= 2
        except Exception as exc:
            logger.warning(f"Cross-validation failed for '{term}': {exc}")
            return False

    async def search(self, query: str, n: int = 10) -> List[BlackTalkTerm]:
        try:
            results = await self.vector_store.search_blacktalk(query, n_results=n)
            terms: List[BlackTalkTerm] = []
            for result in results:
                metadata = result.get("metadata", {})
                term_str = metadata.get("term", "")
                term_id = self._term_index.get(term_str)
                if term_id and term_id in self._dictionary:
                    terms.append(self._dictionary[term_id])
                    self._last_accessed[term_id] = datetime.now(timezone.utc)
                else:
                    bt = BlackTalkTerm(
                        id=result.get("id", uuid4().hex),
                        term=term_str,
                        meaning=metadata.get("meaning", ""),
                        category=metadata.get("category", "general"),
                        confidence=metadata.get("confidence", 0.5),
                        source=metadata.get("source", "unknown"),
                    )
                    terms.append(bt)
            return terms
        except Exception as exc:
            logger.error(f"Blacktalk search failed: {exc}")
            return []

    async def get_all(self, category: Optional[str] = None) -> List[BlackTalkTerm]:
        terms = list(self._dictionary.values())
        if category:
            terms = [t for t in terms if t.category == category]
        return sorted(terms, key=lambda t: t.term)

    def _init_seed_dictionary(self) -> Dict[str, BlackTalkTerm]:
        now = datetime.now(timezone.utc)
        seed_data = [
            ("跑分", "洗钱，通过第三方支付平台转移非法资金", "money_laundering"),
            ("料", "个人信息，通常指被盗取的公民个人数据", "fraud"),
            ("黑料", "违法数据，包括被盗取的隐私信息", "fraud"),
            ("卡商", "银行卡贩卖者，专门收购和倒卖银行卡的人", "money_laundering"),
            ("猫池", "批量收发短信的设备，用于接收验证码", "fraud"),
            ("接码", "接收验证码，通常指代收短信验证码服务", "fraud"),
            ("养号", "培育账号，通过模拟正常使用提高账号权重", "fraud"),
            ("薅羊毛", "利用优惠活动漏洞非法获利", "fraud"),
            ("料主", "数据贩卖者，出售被盗个人信息的上游犯罪者", "fraud"),
            ("菠菜", "网络赌博，取谐音以规避审查", "gambling"),
            ("色流", "色情引流，利用色情内容吸引用户", "fraud"),
            ("诈骗流", "诈骗引流，为诈骗团伙输送潜在受害者", "fraud"),
            ("料子", "个人隐私数据，特指可用于诈骗的完整信息", "fraud"),
            ("四件套", "身份证+银行卡+手机卡+U盾的犯罪工具套装", "money_laundering"),
            ("拦截卡", "通过后门窃取验证码的手机卡", "fraud"),
            ("跑分平台", "洗钱中介平台，为黑产提供资金通道", "money_laundering"),
            ("套现", "非法提现，将非法资金转为合法形式", "money_laundering"),
            ("挂马", "植入木马程序到网站或文件中", "hacking"),
            ("黑SEO", "搜索引擎优化黑产，通过作弊手段提升排名", "hacking"),
            ("代购", "代为购买非法商品或服务", "general"),
            ("水房", "洗钱环节，专门负责资金清洗的团队", "money_laundering"),
            ("车手", "取款人，负责从ATM取现的底层执行者", "money_laundering"),
            ("马仔", "底层执行者，犯罪团伙中的小角色", "general"),
            ("菜农", "网络赌博运营者", "gambling"),
            ("盘口", "赌博网站或赌博平台", "gambling"),
            ("代理", "赌博代理，为赌博平台招揽客户", "gambling"),
            ("返佣", "回扣，给下游代理的利润分成", "general"),
            ("套路贷", "欺诈性贷款，通过设置陷阱使借款人深陷债务", "fraud"),
            ("裸条", "以裸照作为抵押的借贷方式", "fraud"),
            ("杀猪盘", "长期感情诈骗，通过建立感情骗取钱财", "fraud"),
            ("资金盘", "庞氏骗局，以高回报为诱饵的资金传销", "fraud"),
            ("黑产", "黑色产业链，从事违法活动的产业", "general"),
            ("灰产", "灰色产业链，游走在法律边缘的产业", "general"),
            ("洗料", "对盗取的个人信息进行加工整理", "fraud"),
            ("撞库", "用已泄露的账号密码尝试登录其他平台", "hacking"),
            ("脱库", "盗取数据库中的全部数据", "hacking"),
            ("社工", "社会工程学攻击，通过欺骗获取信息", "hacking"),
            ("肉鸡", "被植入木马受控的电脑或设备", "hacking"),
            ("抓鸡", "入侵并控制他人电脑使其成为肉鸡", "hacking"),
            ("DDoS", "分布式拒绝服务攻击", "hacking"),
            ("CC攻击", "模拟大量用户访问导致服务器瘫痪", "hacking"),
            ("黑卡", "非法获取的银行卡或信用卡", "money_laundering"),
            ("洗白", "将非法资金转为合法来源", "money_laundering"),
            ("过桥", "通过中间账户转移资金以掩盖来源", "money_laundering"),
            ("走账", "通过虚假交易转移资金", "money_laundering"),
            ("码商", "提供收款二维码用于洗钱的人", "money_laundering"),
            ("通道", "支付通道，用于资金转移的渠道", "money_laundering"),
            ("电诈", "电信诈骗，通过电话或网络实施诈骗", "fraud"),
            ("引流", "为黑产吸引潜在受害者", "fraud"),
            ("吸粉", "大量添加好友或关注者用于后续诈骗", "fraud"),
            ("话术", "诈骗脚本，精心设计的对话模板", "fraud"),
            ("猪", "杀猪盘中的诈骗目标", "fraud"),
            ("养猪", "杀猪盘中培养感情的过程", "fraud"),
            ("杀猪", "在杀猪盘中实施诈骗收割", "fraud"),
            ("操盘手", "诈骗或资金盘的实际操控者", "fraud"),
            ("上线", "犯罪团伙中的上级或供货方", "general"),
            ("下线", "犯罪团伙中的下级或分销方", "general"),
            ("分赃", "犯罪收益的分配", "general"),
            ("出货", "出售非法商品或数据", "general"),
            ("收网", "执法部门集中抓捕行动", "general"),
        ]
        dictionary: Dict[str, BlackTalkTerm] = {}
        for i, (term, meaning, category) in enumerate(seed_data):
            term_id = uuid4().hex
            bt = BlackTalkTerm(
                id=term_id,
                term=term,
                meaning=meaning,
                category=category,
                context_examples=[],
                confidence=1.0,
                source="manual",
                created_at=now,
                updated_at=now,
            )
            dictionary[term_id] = bt
        return dictionary

    def _save_to_disk(self):
        try:
            os.makedirs(os.path.dirname(self._data_file), exist_ok=True)
            data = [bt.to_dict() for bt in self._dictionary.values()]
            with open(self._data_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            logger.debug(f"Saved {len(data)} blacktalk terms to {self._data_file}")
        except Exception as exc:
            logger.warning(f"Failed to save blacktalk dictionary to disk: {exc}")

    def _load_from_disk(self):
        try:
            file_path = Path(self._data_file)
            if not file_path.exists():
                logger.debug("No persisted blacktalk dictionary found, using seed terms only")
                return
            with open(self._data_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, list):
                logger.warning("Invalid blacktalk dictionary format on disk")
                return
            for item in data:
                try:
                    bt = BlackTalkTerm.from_dict(item)
                    existing_id = self._term_index.get(bt.term)
                    if existing_id:
                        self._dictionary[existing_id] = bt
                        self._last_accessed[existing_id] = bt.updated_at
                    else:
                        self._dictionary[bt.id] = bt
                        self._term_index[bt.term] = bt.id
                        self._last_accessed[bt.id] = bt.updated_at
                except Exception as exc:
                    logger.warning(f"Failed to load blacktalk term from disk: {exc}")
            logger.info(f"Loaded {len(data)} blacktalk terms from disk, total: {len(self._dictionary)}")
        except Exception as exc:
            logger.warning(f"Failed to load blacktalk dictionary from disk: {exc}")
