from datetime import datetime
from typing import Dict, List, Optional
from uuid import uuid4

from loguru import logger

from app.config import settings
from app.agents.base import BaseAgent
from app.core.blacktalk_engine import BlackTalkEngine
from app.core.evidence_chain import EvidenceChain, Evidence
from app.core.knowledge_graph import KnowledgeGraph
from app.core.llm import LLMService
from app.core.rule_based_extractor import rule_extractor
from app.core.vector_store import VectorStore
from app.models.intelligence import (
    AnalyzedIntelligence,
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


class AnalystAgent(BaseAgent):
    def __init__(
        self,
        llm: LLMService,
        vector_store: VectorStore,
        blacktalk_engine: BlackTalkEngine,
        knowledge_graph: KnowledgeGraph,
        evidence_chain: EvidenceChain,
    ):
        super().__init__("analyst", llm, vector_store)
        self.blacktalk_engine = blacktalk_engine
        self.knowledge_graph = knowledge_graph
        self.evidence_chain = evidence_chain

    async def execute(self, task: Dict) -> Dict:
        task_type = task.get("type", "analyze")
        try:
            if task_type == "analyze":
                cleaned_intel = task.get("cleaned_intelligence")
                if not cleaned_intel:
                    return self._create_task_result(
                        status="failed",
                        data={},
                        errors=["cleaned_intelligence is required for analyze task"],
                    )
                context = task.get("context")
                analyzed = await self.analyze(cleaned_intel, context)
                result = self._create_task_result(
                    status="success",
                    data={"analyzed_intelligence": analyzed},
                )

            elif task_type == "find_patterns":
                intels = task.get("intelligences", [])
                if not intels:
                    return self._create_task_result(
                        status="failed",
                        data={},
                        errors=["intelligences list is required for find_patterns"],
                    )
                patterns = await self.find_patterns(intels)
                result = self._create_task_result(
                    status="success",
                    data={
                        "pattern_count": len(patterns),
                        "patterns": patterns,
                    },
                )

            elif task_type == "reconstruct_chain":
                intel = task.get("cleaned_intelligence")
                if not intel:
                    return self._create_task_result(
                        status="failed",
                        data={},
                        errors=["cleaned_intelligence is required for reconstruct_chain"],
                    )
                chain = await self.reconstruct_chain(intel)
                result = self._create_task_result(
                    status="success",
                    data={"technique_chain": chain},
                )

            elif task_type == "predict_trend":
                historical_intels = task.get("historical_intelligences", [])
                if not historical_intels:
                    return self._create_task_result(
                        status="failed",
                        data={},
                        errors=["historical_intelligences is required for predict_trend"],
                    )
                prediction = await self.predict_trend(historical_intels)
                result = self._create_task_result(
                    status="success",
                    data={"trend_prediction": prediction},
                )

            else:
                result = self._create_task_result(
                    status="failed",
                    data={},
                    errors=[f"Unknown task type: {task_type}"],
                )

        except Exception as exc:
            self.logger.error(f"Analyst task failed: {exc}")
            result = self._create_task_result(
                status="failed",
                data={},
                errors=[str(exc)],
            )

        await self._log_execution(task, result)
        return result

    async def analyze(
        self, cleaned_intel: Dict, context: Dict = None
    ) -> Dict:
        content = cleaned_intel.get("content", "")
        decoded_content = cleaned_intel.get("decoded_content", content)
        cleaned_id = cleaned_intel.get("id", uuid4().hex)
        blacktalk_terms = cleaned_intel.get("blacktalk_terms", {})
        initial_threat = cleaned_intel.get("threat_level", "info")

        threat_categories = await self._classify_threat(decoded_content)
        attack_patterns = await self._identify_patterns(decoded_content)
        technique_chain = await self._extract_chain(decoded_content)

        confidence_score = await self._calculate_confidence(
            content=decoded_content,
            threat_categories=threat_categories,
            attack_patterns=attack_patterns,
            blacktalk_terms=blacktalk_terms,
        )

        analysis_summary = await self._generate_analysis_summary(
            content=decoded_content,
            threat_categories=threat_categories,
            attack_patterns=attack_patterns,
            technique_chain=technique_chain,
            confidence_score=confidence_score,
        )

        evidence_refs: List[str] = []
        try:
            evidence_list = await self.evidence_chain.create_evidence_chain(
                conclusion=analysis_summary,
                analysis_result={
                    "raw_intelligence_ids": [cleaned_intel.get("raw_id", cleaned_id)],
                    "analysis_summary": analysis_summary,
                    "confidence_score": confidence_score,
                    "entity_ids": cleaned_intel.get("entities", []),
                },
            )
            evidence_refs = [e.id for e in evidence_list]

            verification = await self.evidence_chain.verify(
                conclusion=analysis_summary,
                sources=evidence_list,
            )
            confidence_score = confidence_score * verification.confidence
            confidence_score = max(0.0, min(1.0, confidence_score))
        except Exception as exc:
            self.logger.warning(f"Evidence chain verification failed: {exc}")

        final_threat = self._determine_final_threat(
            initial_threat, threat_categories, confidence_score
        )

        analyzed = AnalyzedIntelligence(
            cleaned_id=cleaned_id,
            threat_level=ThreatLevel(final_threat),
            threat_categories=threat_categories,
            attack_patterns=[p.get("name", str(p)) for p in attack_patterns],
            technique_chain=[s.get("stage", str(s)) for s in technique_chain],
            confidence_score=confidence_score,
            analysis_summary=analysis_summary,
            evidence_refs=evidence_refs,
        )

        try:
            await self.vector_store.add_intelligence(
                intel_id=analyzed.id,
                content=analysis_summary,
                metadata={
                    "cleaned_id": cleaned_id,
                    "status": "analyzed",
                    "threat_level": final_threat,
                    "threat_categories": threat_categories,
                    "confidence_score": confidence_score,
                    "analyzed_at": analyzed.analyzed_at.isoformat(),
                },
            )
        except Exception as exc:
            self.logger.warning(
                f"Failed to store analyzed intelligence: {exc}"
            )

        result = analyzed.model_dump()
        result["attack_pattern_details"] = attack_patterns
        result["technique_chain_details"] = technique_chain
        return result

    async def find_patterns(self, intels: List[Dict]) -> List[Dict]:
        if not intels:
            return []

        contents = []
        for intel in intels:
            content = intel.get("content", "") or intel.get("decoded_content", "")
            if content:
                contents.append(content)

        if not contents:
            return []

        combined = "\n---\n".join(
            f"情报{i+1}: {c[:500]}" for i, c in enumerate(contents[:20])
        )

        system_prompt = (
            "你是一个黑灰产攻击模式识别专家。分析以下多条情报，找出其中共同的攻击模式和技术特征。\n\n"
            "需要识别的模式类型：\n"
            "- 诈骗模式（杀猪盘、套路贷、电信诈骗等）\n"
            "- 洗钱模式（跑分、水房、过桥等）\n"
            "- 黑客攻击模式（撞库、挂马、DDoS等）\n"
            "- 赌博模式（菠菜、盘口、代理等）\n"
            "- 综合模式（多种犯罪手法组合）\n\n"
            "返回JSON数组，每个元素包含：\n"
            "- pattern_name: 模式名称\n"
            "- description: 模式描述\n"
            "- frequency: 出现频率（高/中/低）\n"
            "- examples: 该模式的情报示例（数组，1-3条）\n\n"
            "只返回JSON数组，不要其他内容。"
        )
        prompt = f"请分析以下情报中的攻击模式：\n\n{_sanitize_input(combined)}"

        try:
            result = await self.llm.generate_json(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=settings.LLM_TEMPERATURE_CREATIVE,
            )
            if isinstance(result, list):
                return result
            if isinstance(result, dict) and "patterns" in result:
                return result["patterns"]
            return []
        except Exception as exc:
            self.logger.error(f"Pattern finding failed: {exc}")
            return []

    async def reconstruct_chain(self, intel: Dict) -> List[Dict]:
        content = intel.get("content", "") or intel.get("decoded_content", "")
        if not content:
            return []

        related_entities: List[Dict] = []
        entities = intel.get("entities", [])
        for entity_val in entities[:5]:
            try:
                found = await self.knowledge_graph.search_entities(
                    query=entity_val, limit=3
                )
                for e in found:
                    related_entities.append({
                        "id": e.id,
                        "type": e.type.value,
                        "value": e.value,
                    })
            except Exception:
                continue

        entity_context = ""
        if related_entities:
            entity_context = "\n\n已知关联实体：\n" + "\n".join(
                f"- {e['type']}: {e['value']}" for e in related_entities[:10]
            )

        system_prompt = (
            "你是一个黑灰产攻击链重建专家。根据情报内容，重建完整的攻击技术链路。\n\n"
            "攻击链通常包含以下阶段：\n"
            "1. 资源获取阶段：获取作案所需的工具、账号、数据等资源\n"
            "2. 工具准备阶段：准备和配置攻击工具、平台等\n"
            "3. 攻击执行阶段：实施具体的攻击或犯罪行为\n"
            "4. 资金流转阶段：资金的收取、转移、清洗等\n\n"
            "返回JSON数组，按阶段顺序排列，每个元素包含：\n"
            "- stage: 阶段名称（资源获取/工具准备/攻击执行/资金流转）\n"
            "- description: 该阶段的具体行为描述\n"
            "- tools: 使用的工具或平台列表\n"
            "- indicators: 该阶段的关键指标（IOC等）\n"
            "- confidence: 该阶段推断的置信度（0-1）\n\n"
            "如果情报不足以推断某个阶段，可以省略该阶段。只返回JSON数组。"
        )
        prompt = (
            f"请重建以下情报的攻击技术链：\n\n{_sanitize_input(content)}{_sanitize_input(entity_context)}"
        )

        try:
            result = await self.llm.generate_json(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=settings.LLM_TEMPERATURE_CREATIVE,
            )
            if isinstance(result, list):
                return result
            if isinstance(result, dict) and "chain" in result:
                return result["chain"]
            return []
        except Exception as exc:
            self.logger.error(f"Chain reconstruction failed: {exc}")
            return []

    async def predict_trend(self, historical_intels: List[Dict]) -> Dict:
        if not historical_intels:
            return {
                "trends": [],
                "predictions": [],
                "confidence": 0.0,
                "summary": "无历史数据可供趋势分析",
            }

        time_grouped: Dict[str, List[str]] = {}
        for intel in historical_intels:
            content = intel.get("content", "") or intel.get("decoded_content", "")
            if not content:
                continue
            ts = intel.get("collected_at") or intel.get("cleaned_at") or intel.get("analyzed_at")
            if ts:
                if isinstance(ts, str):
                    period = ts[:7]
                else:
                    period = str(ts)[:7]
            else:
                period = "unknown"
            if period not in time_grouped:
                time_grouped[period] = []
            time_grouped[period].append(content[:300])

        timeline_summary = ""
        for period in sorted(time_grouped.keys()):
            items = time_grouped[period]
            timeline_summary += f"\n{period} ({len(items)}条): " + "; ".join(items[:5])

        system_prompt = (
            "你是一个黑灰产威胁趋势预测专家。根据提供的历史情报数据，"
            "分析威胁趋势并做出预测。\n\n"
            "返回JSON对象，包含：\n"
            "- trends: 当前趋势列表，每项包含{name, description, direction: '上升'/'下降'/'稳定', severity: '高'/'中'/'低'}\n"
            "- predictions: 未来预测列表，每项包含{threat, likelihood: '高'/'中'/'低', timeframe, description}\n"
            "- confidence: 总体预测置信度（0-1）\n"
            "- summary: 趋势分析摘要\n\n"
            "只返回JSON，不要其他内容。"
        )
        prompt = (
            f"请分析以下历史情报的趋势并做出预测：\n\n"
            f"时间线摘要：{_sanitize_input(timeline_summary)}\n\n"
            f"总情报数：{len(historical_intels)}"
        )

        try:
            result = await self.llm.generate_json(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=settings.LLM_TEMPERATURE_CREATIVE,
            )
            if isinstance(result, dict):
                return {
                    "trends": result.get("trends", []),
                    "predictions": result.get("predictions", []),
                    "confidence": result.get("confidence", 0.5),
                    "summary": result.get("summary", ""),
                }
        except Exception as exc:
            self.logger.error(f"Trend prediction failed: {exc}")

        return {
            "trends": [],
            "predictions": [],
            "confidence": 0.0,
            "summary": "趋势分析失败，数据不足或分析异常",
        }

    async def _classify_threat(self, content: str) -> List[str]:
        if not content:
            return []

        system_prompt = (
            "你是一个黑灰产威胁分类专家。对以下情报内容进行威胁类别分类。\n\n"
            "可选类别：\n"
            "- fraud: 诈骗（电信诈骗、杀猪盘、套路贷等）\n"
            "- gambling: 赌博（网络赌博、菠菜等）\n"
            "- hacking: 黑客攻击（入侵、挂马、DDoS等）\n"
            "- money_laundering: 洗钱（跑分、水房、套现等）\n"
            "- data_theft: 数据盗窃（脱库、撞库、信息贩卖等）\n"
            "- drug: 毒品相关\n"
            "- phishing: 钓鱼攻击\n"
            "- ransomware: 勒索软件\n"
            "- other: 其他黑灰产\n\n"
            "返回JSON数组，包含所有适用的类别。只返回JSON数组，不要其他内容。"
        )
        prompt = f"请对以下情报进行威胁分类：\n\n{_sanitize_input(content)}"

        try:
            result = await self.llm.generate_json(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=settings.LLM_TEMPERATURE_ANALYSIS,
            )
            if isinstance(result, list):
                return [str(item) for item in result if item]
            if isinstance(result, dict) and "categories" in result:
                return [str(c) for c in result["categories"]]
        except Exception as exc:
            self.logger.warning(f"LLM threat classification failed, using rule-based fallback: {exc}")

        rule_categories, _ = rule_extractor.classify_threat(content)
        if rule_categories:
            return rule_categories

        keyword_map = {
            "phishing": ["钓鱼", "phishing", "仿冒", "伪造网站"],
            "ransomware": ["勒索", "ransomware", "加密勒索", "赎金"],
            "money_laundering": ["洗钱", "money_laundering", "跑分", "水房", "套现", "走账"],
            "fraud": ["诈骗", "fraud", "杀猪盘", "套路贷", "电信诈骗", "骗"],
            "hacking": ["黑客", "hacking", "入侵", "挂马", "DDoS", "漏洞"],
            "gambling": ["赌博", "gambling", "菠菜", "盘口"],
            "data_theft": ["脱库", "撞库", "数据泄露", "信息贩卖"],
        }
        for category, keywords in keyword_map.items():
            if any(kw in content.lower() for kw in keywords):
                return [category]

        return ["suspicious_activity"]

    async def _identify_patterns(self, content: str) -> List[Dict]:
        if not content:
            return []

        system_prompt = (
            "你是一个黑灰产攻击手法识别专家。从以下情报中识别具体的攻击手法和模式。\n\n"
            "返回JSON数组，每个元素包含：\n"
            "- name: 攻击手法名称\n"
            "- description: 手法描述\n"
            "- indicators: 关键指标列表\n"
            "- severity: 严重程度（critical/high/medium/low）\n\n"
            "只返回JSON数组，不要其他内容。如果没有识别到攻击手法，返回空数组[]。"
        )
        prompt = f"请识别以下情报中的攻击手法：\n\n{_sanitize_input(content)}"

        try:
            result = await self.llm.generate_json(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=settings.LLM_TEMPERATURE_DEFAULT,
            )
            if isinstance(result, list):
                return result
            if isinstance(result, dict) and "patterns" in result:
                return result["patterns"]
        except Exception as exc:
            self.logger.warning(f"LLM pattern identification failed, using rule-based fallback: {exc}")

        rule_categories, rule_conf = rule_extractor.classify_threat(content)
        if rule_categories:
            category_name_map = {
                "fraud": "诈骗模式",
                "gambling": "赌博模式",
                "hacking": "黑客攻击模式",
                "money_laundering": "洗钱模式",
                "phishing": "钓鱼攻击模式",
                "ransomware": "勒索软件模式",
                "data_theft": "数据盗窃模式",
                "tool_sales": "工具售卖模式",
                "drug": "毒品相关模式",
            }
            patterns = []
            for cat in rule_categories:
                patterns.append({
                    "name": category_name_map.get(cat, cat),
                    "description": f"基于关键词匹配识别到{category_name_map.get(cat, cat)}特征",
                    "indicators": [cat],
                    "severity": "high" if cat in ("fraud", "hacking", "money_laundering", "ransomware", "drug") else "medium",
                })
            return patterns

        import re
        static_patterns: List[Dict] = []
        if re.search(r'https?://[^\s]+', content):
            static_patterns.append({
                "name": "URL模式",
                "description": "检测到URL链接，可能为钓鱼或恶意链接",
                "indicators": re.findall(r'https?://[^\s]+', content)[:5],
                "severity": "medium",
            })
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', content):
            static_patterns.append({
                "name": "IP地址模式",
                "description": "检测到IP地址，可能为C2服务器或恶意主机",
                "indicators": re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', content)[:5],
                "severity": "medium",
            })
        if re.search(r'1[3-9]\d{9}', content):
            static_patterns.append({
                "name": "手机号模式",
                "description": "检测到手机号码，可能为诈骗联系方式",
                "indicators": re.findall(r'1[3-9]\d{9}', content)[:5],
                "severity": "low",
            })
        if re.search(r'[a-fA-F0-9]{32,}', content):
            static_patterns.append({
                "name": "哈希值模式",
                "description": "检测到哈希值，可能为恶意文件特征",
                "indicators": re.findall(r'[a-fA-F0-9]{32,}', content)[:3],
                "severity": "medium",
            })
        if re.search(r'[\w.+-]+@[\w-]+\.[\w.]+', content):
            static_patterns.append({
                "name": "邮箱模式",
                "description": "检测到邮箱地址，可能为诈骗联系方式",
                "indicators": re.findall(r'[\w.+-]+@[\w-]+\.[\w.]+', content)[:5],
                "severity": "low",
            })

        return static_patterns

    async def _extract_chain(self, content: str) -> List[Dict]:
        if not content:
            return []

        system_prompt = (
            "你是一个黑灰产技术链提取专家。从以下情报中提取攻击技术链的关键环节。\n\n"
            "技术链环节类型：\n"
            "- resource_acquisition: 资源获取（获取工具、账号、数据）\n"
            "- tool_preparation: 工具准备（配置工具、搭建平台）\n"
            "- attack_execution: 攻击执行（实施攻击行为）\n"
            "- money_flow: 资金流转（收款、转账、洗钱）\n\n"
            "返回JSON数组，每个元素包含：\n"
            "- stage: 环节类型（上述之一）\n"
            "- description: 该环节的具体描述\n"
            "- confidence: 推断置信度（0-1）\n\n"
            "只返回JSON数组。如果无法提取技术链，返回空数组[]。"
        )
        prompt = f"请提取以下情报的技术链环节：\n\n{_sanitize_input(content)}"

        try:
            result = await self.llm.generate_json(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=settings.LLM_TEMPERATURE_DEFAULT,
            )
            if isinstance(result, list):
                return result
            if isinstance(result, dict) and "chain" in result:
                return result["chain"]
        except Exception as exc:
            self.logger.warning(f"LLM chain extraction failed, using rule-based fallback: {exc}")

        rule_categories, _ = rule_extractor.classify_threat(content)
        if rule_categories:
            chain = []
            stage_keywords = {
                "resource_acquisition": ["获取", "购买", "收集", "采集", "抓取", "脱库", "撞库"],
                "tool_preparation": ["搭建", "配置", "部署", "准备", "工具", "平台", "猫池", "群控"],
                "attack_execution": ["攻击", "入侵", "诈骗", "钓鱼", "勒索", "挂马", "DDoS"],
                "money_flow": ["转账", "收款", "洗钱", "跑分", "套现", "提现", "通道"],
            }
            for stage, keywords in stage_keywords.items():
                if any(kw in content for kw in keywords):
                    chain.append({
                        "stage": stage,
                        "description": f"基于关键词匹配识别到{stage}阶段特征",
                        "confidence": settings.CONFIDENCE_MEDIUM,
                    })
            return chain

        return []

    async def _calculate_confidence(
        self,
        content: str,
        threat_categories: List[str],
        attack_patterns: List[Dict],
        blacktalk_terms: Dict[str, str],
    ) -> float:
        score = 0.3

        if threat_categories:
            score += min(len(threat_categories) * 0.1, 0.2)
        if attack_patterns:
            score += min(len(attack_patterns) * 0.1, 0.2)
        if blacktalk_terms:
            score += min(len(blacktalk_terms) * 0.05, 0.15)

        specific_indicators = 0
        indicator_patterns = [
            r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
            r"[a-zA-Z0-9-]+\.[a-z]{2,}",
            r"1[3-9]\d{9}",
            r"[a-fA-F0-9]{32,}",
        ]
        import re
        for pattern in indicator_patterns:
            if re.search(pattern, content):
                specific_indicators += 1
        score += min(specific_indicators * 0.05, 0.15)

        entity_count = len(re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|1[3-9]\d{9}|[a-zA-Z0-9-]+\.[a-z]{2,}', content))
        blacktalk_density = len(blacktalk_terms) / max(len(content), 1) * 100
        rule_confidence = min(0.9, 0.3 + entity_count * 0.05 + blacktalk_density * 0.2)
        score = max(score, rule_confidence)

        return max(0.0, min(1.0, score))

    async def _generate_analysis_summary(
        self,
        content: str,
        threat_categories: List[str],
        attack_patterns: List[Dict],
        technique_chain: List[Dict],
        confidence_score: float,
    ) -> str:
        categories_str = "、".join(threat_categories) if threat_categories else "未分类"
        patterns_str = "、".join(
            p.get("name", str(p)) for p in attack_patterns
        ) if attack_patterns else "未识别"
        chain_str = " → ".join(
            s.get("stage", str(s)) for s in technique_chain
        ) if technique_chain else "未提取"

        system_prompt = (
            "你是一个黑灰产情报分析摘要撰写专家。根据分析结果，"
            "生成一段简洁的情报分析摘要（200字以内）。\n\n"
            "要求：\n"
            "- 突出关键威胁信息\n"
            "- 包含威胁类别和攻击手法\n"
            "- 说明技术链路\n"
            "- 给出置信度评估\n"
            "- 只返回摘要文本，不要其他内容"
        )
        prompt = (
            f"威胁类别：{categories_str}\n"
            f"攻击手法：{patterns_str}\n"
            f"技术链路：{chain_str}\n"
            f"置信度：{confidence_score:.2f}\n"
            f"原始内容摘要：{_sanitize_input(content[:500])}\n\n"
            f"请生成情报分析摘要。"
        )

        try:
            summary = await self.llm.generate(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=settings.LLM_TEMPERATURE_CREATIVE,
                max_tokens=settings.LLM_MAX_TOKENS_SHORT,
            )
            return summary.strip()
        except Exception as exc:
            self.logger.warning(f"Summary generation failed: {exc}")

        import re
        entity_count = len(re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|1[3-9]\d{9}|[a-zA-Z0-9-]+\.[a-z]{2,}', content))
        blacktalk_count = len(attack_patterns) if attack_patterns else 0
        return f"基于{entity_count}个实体和{blacktalk_count}个黑话的情报分析"

    def _determine_final_threat(
        self,
        initial_threat: str,
        threat_categories: List[str],
        confidence_score: float,
    ) -> str:
        high_risk_categories = {"fraud", "hacking", "money_laundering", "ransomware"}
        critical_categories = {"drug"}

        if any(c in critical_categories for c in threat_categories):
            if confidence_score >= 0.5:
                return "critical"
            return "high"

        if any(c in high_risk_categories for c in threat_categories):
            if confidence_score >= 0.7:
                return "high"
            if confidence_score >= 0.4:
                return "medium"
            return "low"

        if threat_categories:
            if confidence_score >= 0.6:
                return "medium"
            return "low"

        try:
            threat_enum = ThreatLevel(initial_threat)
            return threat_enum.value
        except ValueError:
            return "info"
