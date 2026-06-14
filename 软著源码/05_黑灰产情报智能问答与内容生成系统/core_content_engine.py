import asyncio
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from loguru import logger


@dataclass
class GeneratedDocument:
    doc_id: str
    title: str
    content_type: str
    content: str
    source_refs: List[str]
    model_id: str
    template_id: Optional[str] = None
    word_count: int = 0
    generation_time_ms: float = 0
    tokens_used: int = 0
    created_at: Optional[datetime] = None

    def to_dict(self) -> Dict:
        return {
            "doc_id": self.doc_id,
            "title": self.title,
            "content_type": self.content_type,
            "content": self.content[:500],
            "source_refs": self.source_refs,
            "model_id": self.model_id,
            "template_id": self.template_id,
            "word_count": self.word_count,
            "generation_time_ms": round(self.generation_time_ms, 2),
            "tokens_used": self.tokens_used,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


@dataclass
class ReviewOpinion:
    opinion_id: str
    doc_id: str
    reviewer: str
    reviewer_role: str
    action: str
    comment: str
    version: int
    created_at: Optional[datetime] = None

    def to_dict(self) -> Dict:
        return {
            "opinion_id": self.opinion_id,
            "doc_id": self.doc_id,
            "reviewer": self.reviewer,
            "reviewer_role": self.reviewer_role,
            "action": self.action,
            "comment": self.comment,
            "version": self.version,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


@dataclass
class DocumentVersion:
    version_id: str
    doc_id: str
    version: int
    content: str
    change_summary: str
    created_at: Optional[datetime] = None

    def to_dict(self) -> Dict:
        return {
            "version_id": self.version_id,
            "doc_id": self.doc_id,
            "version": self.version,
            "content": self.content[:500],
            "change_summary": self.change_summary,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


@dataclass
class TemplateVersion:
    template_id: str
    version: int
    content: str
    description: str
    created_at: Optional[datetime] = None

    def to_dict(self) -> Dict:
        return {
            "template_id": self.template_id,
            "version": self.version,
            "content": self.content[:500],
            "description": self.description,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


@dataclass
class QualityAssessment:
    content_type: str
    overall_score: float
    completeness_score: float
    accuracy_score: float
    readability_score: float
    issues: List[str]
    needs_revision: bool
    assessed_at: Optional[datetime] = None

    def to_dict(self) -> Dict:
        return {
            "content_type": self.content_type,
            "overall_score": round(self.overall_score, 2),
            "completeness_score": round(self.completeness_score, 2),
            "accuracy_score": round(self.accuracy_score, 2),
            "readability_score": round(self.readability_score, 2),
            "issues": self.issues,
            "needs_revision": self.needs_revision,
            "assessed_at": self.assessed_at.isoformat() if self.assessed_at else None,
        }


class ReviewStatus(str, Enum):
    PENDING = "pending"
    FIRST_REVIEW = "first_review"
    SECOND_REVIEW = "second_review"
    APPROVED = "approved"
    REJECTED = "rejected"


class ContentGenerator:
    CONTENT_TEMPLATES = {
        "report_summary": {
            "system_prompt": "你是威胁情报分析专家，请根据提供的情报数据生成结构化的报告摘要。",
            "structure": [
                "## 概述",
                "## 关键发现",
                "## 威胁评估",
                "## 建议措施",
            ],
        },
        "intel_brief": {
            "system_prompt": "你是威胁情报简报撰写专家，请生成简洁、专业的情报简报。",
            "structure": [
                "## 情报概要",
                "## 威胁指标",
                "## 影响分析",
                "## 处置建议",
            ],
        },
        "security_advice": {
            "system_prompt": "你是网络安全防护专家，请基于威胁分析结果生成防护建议。",
            "structure": [
                "## 威胁背景",
                "## 风险评估",
                "## 防护措施",
                "## 监控建议",
            ],
        },
        "trend_analysis": {
            "system_prompt": "你是威胁趋势分析专家，请基于历史数据和当前情报生成趋势分析报告。",
            "structure": [
                "## 趋势概述",
                "## 数据分析",
                "## 预测判断",
                "## 应对策略",
            ],
        },
        "threat_assessment": {
            "system_prompt": "你是黑灰产威胁研判专家，请对威胁情报进行等级研判和风险评估，输出结构化研判报告。",
            "structure": [
                "## 威胁等级研判",
                "## 风险评估",
                "## 攻击向量分析",
                "## 处置建议",
            ],
        },
        "attack_chain_analysis": {
            "system_prompt": "你是黑灰产攻击链路分析专家，请还原攻击手法链路，分析各环节关联关系。",
            "structure": [
                "## 攻击链路还原",
                "## 各环节分析",
                "## 关联实体",
                "## 防御建议",
            ],
        },
        "threat_situation_brief": {
            "system_prompt": "你是黑灰产态势分析专家，请生成周期性威胁态势简报，涵盖近期黑灰产活动态势。",
            "structure": [
                "## 态势概述",
                "## 威胁趋势",
                "## 重点事件",
                "## 防护建议",
            ],
        },
        "high_risk_alert": {
            "system_prompt": "你是黑灰产高危预警专家，请生成高危威胁预警通报，明确预警等级和紧急处置措施。",
            "structure": [
                "## 预警等级",
                "## 威胁描述",
                "## 影响范围",
                "## 紧急处置",
            ],
        },
        "ioc_report": {
            "system_prompt": "你是IoC指标分析专家，请提取失陷指标并生成关联分析报告。",
            "structure": [
                "## IoC指标清单",
                "## 关联分析",
                "## 溯源信息",
                "## 防御建议",
            ],
        },
        "crime_pattern_analysis": {
            "system_prompt": "你是黑灰产犯罪模式分析专家，请识别犯罪模式、还原犯罪链路，输出结构化分析报告。",
            "structure": [
                "## 犯罪模式识别",
                "## 链路还原",
                "## 组织架构分析",
                "## 打击建议",
            ],
        },
    }

    def __init__(self, llm_service=None, prompt_engine=None):
        self._llm = llm_service
        self._prompt_engine = prompt_engine
        self._industry_config: Dict[str, Any] = {}

    def set_industry_config(self, config: Dict[str, Any]):
        self._industry_config = config
        content_types = config.get("content_types", {})
        for ctype, ctype_config in content_types.items():
            if isinstance(ctype_config, dict):
                existing = self.CONTENT_TEMPLATES.get(ctype, {})
                merged = {**existing, **ctype_config}
                self.CONTENT_TEMPLATES[ctype] = merged
        threat_categories = config.get("threat_categories", [])
        if threat_categories:
            for ctype, tmpl in self.CONTENT_TEMPLATES.items():
                if "threat_categories" not in tmpl:
                    tmpl["threat_categories"] = threat_categories
        return True

    async def generate(
        self,
        content_type: str,
        title: str,
        source_data: Optional[str] = None,
        source_refs: Optional[List[str]] = None,
        template_id: Optional[str] = None,
        model_id: Optional[str] = None,
        custom_instructions: Optional[str] = None,
        max_tokens: int = 4096,
        timeout: float = 60.0,
    ) -> GeneratedDocument:
        start = time.time()

        template_config = self.CONTENT_TEMPLATES.get(content_type, self.CONTENT_TEMPLATES["report_summary"])

        system_prompt = template_config["system_prompt"]
        if custom_instructions:
            system_prompt += f"\n\n额外要求: {custom_instructions}"

        structure = "\n".join(template_config["structure"])

        prompt = f"请生成以下类型的文档:\n\n标题: {title}\n类型: {content_type}\n\n"
        prompt += f"建议结构:\n{structure}\n\n"

        if source_data:
            prompt += f"参考数据:\n{source_data[:3000]}\n\n"

        prompt += "请直接输出文档内容，使用Markdown格式。"

        content = ""
        tokens_used = 0

        if self._llm:
            try:
                response = await asyncio.wait_for(
                    self._llm.chat(prompt),
                    timeout=timeout,
                )
                if isinstance(response, dict):
                    content = response.get("content", "")
                    tokens_used = response.get("usage", {}).get("total_tokens", 0)
                elif isinstance(response, str):
                    content = response
                    tokens_used = len(content) // 4
            except asyncio.TimeoutError:
                logger.warning(f"内容生成超时: {title}")
                content = self._generate_fallback(content_type, title, source_data)
            except Exception as exc:
                logger.error(f"内容生成失败: {exc}")
                content = self._generate_fallback(content_type, title, source_data)
        else:
            content = self._generate_fallback(content_type, title, source_data)

        content = self._content_safety_filter(content)

        return GeneratedDocument(
            doc_id=uuid.uuid4().hex,
            title=title,
            content_type=content_type,
            content=content,
            source_refs=source_refs or [],
            model_id=model_id or "system",
            template_id=template_id,
            word_count=len(content),
            generation_time_ms=(time.time() - start) * 1000,
            tokens_used=tokens_used,
            created_at=datetime.now(timezone.utc),
        )

    async def generate_report_summary(self, title: str, context: str, data: Dict = None) -> Dict:
        if not self._llm:
            return self._fallback_report_summary(title, context)

        system_prompt = (
            "你是威胁情报分析专家。请根据提供的情报数据和上下文，"
            "生成结构化的威胁情报报告摘要。输出必须为严格的JSON格式，"
            '包含以下字段：title（报告标题）、summary（摘要概述）、'
            'key_findings（关键发现列表）、threat_assessment（威胁评估）、'
            'recommendations（建议措施列表）、confidence（置信度，0-1之间的数值）。'
        )

        user_prompt = f"报告标题: {title}\n上下文信息: {context}\n"
        if data:
            user_prompt += f"附加数据: {json.dumps(data, ensure_ascii=False)[:2000]}\n"
        user_prompt += "\n请生成结构化的报告摘要，以JSON格式输出。"

        try:
            result = await self._llm.generate_json(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
            )
            if isinstance(result, dict):
                return {
                    "title": result.get("title", title),
                    "summary": result.get("summary", ""),
                    "key_findings": result.get("key_findings", []),
                    "threat_assessment": result.get("threat_assessment", ""),
                    "recommendations": result.get("recommendations", []),
                    "confidence": result.get("confidence", 0.0),
                }
            return self._fallback_report_summary(title, context)
        except Exception as exc:
            logger.error(f"报告摘要生成失败: {exc}")
            return self._fallback_report_summary(title, context)

    def _fallback_report_summary(self, title: str, context: str) -> Dict:
        return {
            "title": title,
            "summary": context[:500] if context else "",
            "key_findings": [],
            "threat_assessment": "待评估（LLM服务不可用）",
            "recommendations": [],
            "confidence": 0.0,
        }

    async def generate_intelligence_briefing(self, topics: List[str], time_range: str = "最近7天") -> Dict:
        if not self._llm:
            return self._fallback_intelligence_briefing(topics, time_range)

        system_prompt = (
            "你是威胁情报简报撰写专家。请根据提供的主题和时间范围，"
            "生成专业、简洁的情报简报。输出必须为严格的JSON格式，"
            '包含以下字段：briefing（简报正文）、highlights（要点列表）、'
            'emerging_threats（新兴威胁列表）、watch_items（关注事项列表）。'
        )

        topics_str = "、".join(topics)
        user_prompt = (
            f"关注主题: {topics_str}\n时间范围: {time_range}\n\n"
            "请生成情报简报，以JSON格式输出。"
        )

        try:
            result = await self._llm.generate_json(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
            )
            if isinstance(result, dict):
                return {
                    "briefing": result.get("briefing", ""),
                    "highlights": result.get("highlights", []),
                    "emerging_threats": result.get("emerging_threats", []),
                    "watch_items": result.get("watch_items", []),
                }
            return self._fallback_intelligence_briefing(topics, time_range)
        except Exception as exc:
            logger.error(f"情报简报生成失败: {exc}")
            return self._fallback_intelligence_briefing(topics, time_range)

    def _fallback_intelligence_briefing(self, topics: List[str], time_range: str) -> Dict:
        topics_str = "、".join(topics)
        return {
            "briefing": f"{time_range}内关于{topics_str}的情报简报（LLM服务不可用，待补充）",
            "highlights": [],
            "emerging_threats": [],
            "watch_items": [],
        }

    async def generate_security_advice(self, threat_type: str, context: str) -> Dict:
        if not self._llm:
            return self._fallback_security_advice(threat_type, context)

        system_prompt = (
            "你是网络安全防护专家。请根据威胁类型和相关上下文，"
            "生成专业的安全防护建议。输出必须为严格的JSON格式，"
            '包含以下字段：threat_analysis（威胁分析）、'
            'immediate_actions（即时行动列表）、'
            'long_term_measures（长期措施列表）、'
            'monitoring_suggestions（监控建议列表）、'
            'priority_level（优先级：critical/high/medium/low）。'
        )

        user_prompt = (
            f"威胁类型: {threat_type}\n上下文信息: {context}\n\n"
            "请生成安全防护建议，以JSON格式输出。"
        )

        try:
            result = await self._llm.generate_json(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
            )
            if isinstance(result, dict):
                return {
                    "threat_analysis": result.get("threat_analysis", ""),
                    "immediate_actions": result.get("immediate_actions", []),
                    "long_term_measures": result.get("long_term_measures", []),
                    "monitoring_suggestions": result.get("monitoring_suggestions", []),
                    "priority_level": result.get("priority_level", "medium"),
                }
            return self._fallback_security_advice(threat_type, context)
        except Exception as exc:
            logger.error(f"安全建议生成失败: {exc}")
            return self._fallback_security_advice(threat_type, context)

    def _fallback_security_advice(self, threat_type: str, context: str) -> Dict:
        return {
            "threat_analysis": f"威胁类型: {threat_type}，上下文: {context[:300]}（LLM服务不可用，待分析）",
            "immediate_actions": [],
            "long_term_measures": [],
            "monitoring_suggestions": [],
            "priority_level": "medium",
        }

    async def generate_trend_analysis(self, data_points: List[Dict], metric: str = "威胁指数") -> Dict:
        if not self._llm:
            return self._fallback_trend_analysis(data_points, metric)

        system_prompt = (
            "你是威胁趋势分析专家。请根据提供的数据点，"
            "分析威胁趋势并生成预测。输出必须为严格的JSON格式，"
            '包含以下字段：trend_direction（趋势方向：上升/下降/平稳）、'
            'trend_description（趋势描述）、'
            'key_observations（关键观察列表）、'
            'forecast（预测判断）、'
            'risk_level（风险等级：critical/high/medium/low）。'
        )

        data_str = json.dumps(data_points, ensure_ascii=False)[:3000]
        user_prompt = (
            f"分析指标: {metric}\n数据点: {data_str}\n\n"
            "请分析趋势并生成预测，以JSON格式输出。"
        )

        try:
            result = await self._llm.generate_json(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
            )
            if isinstance(result, dict):
                return {
                    "trend_direction": result.get("trend_direction", "平稳"),
                    "trend_description": result.get("trend_description", ""),
                    "key_observations": result.get("key_observations", []),
                    "forecast": result.get("forecast", ""),
                    "risk_level": result.get("risk_level", "medium"),
                }
            return self._fallback_trend_analysis(data_points, metric)
        except Exception as exc:
            logger.error(f"趋势分析生成失败: {exc}")
            return self._fallback_trend_analysis(data_points, metric)

    def _fallback_trend_analysis(self, data_points: List[Dict], metric: str) -> Dict:
        return {
            "trend_direction": "平稳",
            "trend_description": f"基于{len(data_points)}个数据点的{metric}趋势分析（LLM服务不可用，待补充）",
            "key_observations": [],
            "forecast": "",
            "risk_level": "medium",
        }

    def _generate_fallback(
        self, content_type: str, title: str, source_data: Optional[str]
    ) -> str:
        template_config = self.CONTENT_TEMPLATES.get(content_type, self.CONTENT_TEMPLATES["report_summary"])
        sections = []
        for section in template_config["structure"]:
            section_key = section.replace("## ", "").strip()
            sections.append(f"{section}\n\n")
            if source_data:
                relevant = self._extract_relevant_section(source_data, section_key)
                if relevant:
                    sections.append(f"{relevant}\n\n")
            sections.append(f"（该章节待进一步分析补充）\n\n")
        metadata = f"\n---\n*文档类型: {content_type} | 生成时间: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}*\n"
        return f"# {title}\n\n" + "".join(sections) + metadata

    def _extract_relevant_section(self, source_data: str, section_key: str) -> Optional[str]:
        keywords_map = {
            "概述": ["概述", "概要", "总体", "整体"],
            "关键发现": ["发现", "关键", "重要", "核心"],
            "威胁评估": ["威胁", "风险", "等级", "评估"],
            "建议措施": ["建议", "措施", "防护", "应对"],
            "情报概要": ["情报", "概要", "摘要"],
            "威胁指标": ["指标", "IoC", "特征", "标识"],
            "影响分析": ["影响", "范围", "损失"],
            "处置建议": ["处置", "建议", "应对", "响应"],
            "威胁背景": ["背景", "起源", "来源"],
            "风险评估": ["风险", "评估", "等级"],
            "防护措施": ["防护", "措施", "防御", "加固"],
            "监控建议": ["监控", "检测", "告警"],
            "趋势概述": ["趋势", "变化", "走向"],
            "数据分析": ["数据", "统计", "分析"],
            "预测判断": ["预测", "预判", "展望"],
            "应对策略": ["策略", "应对", "方案"],
        }
        keywords = keywords_map.get(section_key, [section_key])
        sentences = source_data.split("。")
        relevant = []
        for s in sentences:
            s_stripped = s.strip()
            if not s_stripped:
                continue
            if any(kw in s_stripped for kw in keywords):
                relevant.append(s_stripped)
        return "。".join(relevant[:3]) + "。" if relevant else None

    def _content_safety_filter(self, content: str) -> str:
        if not content:
            return content

        sensitive_patterns = [
            (r'密码[是为：:]\s*\S+', '密码[已脱敏]'),
            (r'api[_-]?key[=:]\s*["\']?\s*[A-Za-z0-9_\-]{20,}', 'api_key=[已脱敏]'),
            (r'secret[=:]\s*["\']?\s*[A-Za-z0-9_\-]{20,}', 'secret=[已脱敏]'),
            (r'token[=:]\s*["\']?\s*[A-Za-z0-9_\-\.]{20,}', 'token=[已脱敏]'),
            (r'authorization[=:]\s*["\']?\s*Bearer\s+\S+', 'authorization=[已脱敏]'),
            (r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}\b', '[IP:PORT已脱敏]'),
            (r'身份证号[是为：:]\s*\d{17}[\dXx]', '身份证号[已脱敏]'),
            (r'\b1[3-9]\d{9}\b', '[手机号已脱敏]'),
            (r'银行卡号[是为：:]\s*\d{16,19}', '银行卡号[已脱敏]'),
        ]

        for pattern, replacement in sensitive_patterns:
            content = re.sub(pattern, replacement, content, flags=re.IGNORECASE)

        return content

    def assess_content_quality(self, content: str, content_type: str) -> QualityAssessment:
        issues = []
        completeness_score = self._assess_completeness(content, content_type, issues)
        accuracy_score = self._assess_accuracy(content, content_type, issues)
        readability_score = self._assess_readability(content, content_type, issues)

        overall_score = (
            completeness_score * 0.4
            + accuracy_score * 0.35
            + readability_score * 0.25
        )

        needs_revision = overall_score < 0.6 or len(issues) > 3

        return QualityAssessment(
            content_type=content_type,
            overall_score=overall_score,
            completeness_score=completeness_score,
            accuracy_score=accuracy_score,
            readability_score=readability_score,
            issues=issues,
            needs_revision=needs_revision,
            assessed_at=datetime.now(timezone.utc),
        )

    def _assess_completeness(self, content: str, content_type: str, issues: List[str]) -> float:
        template_config = self.CONTENT_TEMPLATES.get(content_type, self.CONTENT_TEMPLATES["report_summary"])
        required_sections = template_config.get("structure", [])
        found = 0
        for section in required_sections:
            section_name = section.replace("## ", "").strip()
            if section_name in content:
                found += 1
            else:
                issues.append(f"缺少必要章节: {section_name}")

        if not required_sections:
            return 0.5

        section_ratio = found / len(required_sections)

        word_count = len(content)
        word_score = 1.0
        if word_count < 100:
            word_score = word_count / 100
            issues.append(f"内容过短: {word_count}字")
        elif word_count > 50000:
            word_score = 0.7
            issues.append(f"内容过长: {word_count}字")

        placeholder_count = content.count("待进一步分析补充") + content.count("待补充") + content.count("待分析")
        placeholder_score = max(0.0, 1.0 - placeholder_count * 0.15)
        if placeholder_count > 0:
            issues.append(f"存在{placeholder_count}处占位符内容")

        return section_ratio * 0.5 + word_score * 0.3 + placeholder_score * 0.2

    def _assess_accuracy(self, content: str, content_type: str, issues: List[str]) -> float:
        score = 0.7

        threat_level_patterns = [r"高危|严重|紧急|critical|high", r"中危|medium", r"低危|low"]
        has_level = any(re.search(p, content, re.IGNORECASE) for p in threat_level_patterns)
        if has_level:
            score += 0.1
        else:
            issues.append("缺少威胁等级描述")

        ioc_patterns = [r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", r"[a-f0-9]{32,64}", r"[a-f0-9]{40,64}"]
        has_ioc = any(re.search(p, content, re.IGNORECASE) for p in ioc_patterns)
        if has_ioc:
            score += 0.1

        time_patterns = [r"\d{4}[-/年]\d{1,2}[-/月]\d{1,2}[日]?", r"\d{1,2}:\d{2}"]
        has_time = any(re.search(p, content) for p in time_patterns)
        if has_time:
            score += 0.05
        else:
            issues.append("缺少时间信息引用")

        source_patterns = [r"来源[：:]", r"参考", r"引用", r"情报源"]
        has_source = any(re.search(p, content) for p in source_patterns)
        if has_source:
            score += 0.05
        else:
            issues.append("缺少情报来源引用")

        return min(score, 1.0)

    def _assess_readability(self, content: str, content_type: str, issues: List[str]) -> float:
        score = 0.7

        heading_count = len(re.findall(r"^#{1,4}\s+", content, re.MULTILINE))
        if heading_count >= 3:
            score += 0.1
        elif heading_count == 0:
            score -= 0.2
            issues.append("缺少标题层级结构")

        list_count = len(re.findall(r"^[\-\*]\s+|^\d+\.\s+", content, re.MULTILINE))
        if list_count >= 2:
            score += 0.1
        elif list_count == 0:
            score -= 0.05
            issues.append("缺少列表结构，可读性不足")

        paragraphs = [p.strip() for p in content.split("\n\n") if p.strip()]
        if paragraphs:
            avg_len = sum(len(p) for p in paragraphs) / len(paragraphs)
            if avg_len > 500:
                score -= 0.1
                issues.append("段落过长，建议拆分")
            elif avg_len > 30:
                score += 0.1

        return max(0.0, min(score, 1.0))


class LLMContentGenerator:
    def __init__(self, llm_service=None):
        self._llm = llm_service

    async def generate_report_summary(self, intelligence_ids: List[str], context: str) -> Dict:
        if not self._llm:
            return self._fallback_report_summary(intelligence_ids, context)

        system_prompt = (
            "你是威胁情报分析专家。请根据提供的情报ID列表和上下文信息，"
            "生成结构化的情报报告摘要。输出必须为严格的JSON格式，"
            '包含以下字段：title（报告标题）、summary（摘要概述）、'
            'key_findings（关键发现列表）、threat_assessment（威胁评估）、'
            'recommendations（建议措施列表）、confidence（置信度，0-1之间）、'
            'source_intel_ids（来源情报ID列表）。'
        )

        ids_str = "、".join(intelligence_ids)
        user_prompt = f"情报ID列表: {ids_str}\n上下文信息: {context}\n\n请生成结构化的报告摘要，以JSON格式输出。"

        try:
            result = await self._llm.generate_json(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
            )
            if isinstance(result, dict):
                return {
                    "title": result.get("title", "情报报告摘要"),
                    "summary": result.get("summary", ""),
                    "key_findings": result.get("key_findings", []),
                    "threat_assessment": result.get("threat_assessment", ""),
                    "recommendations": result.get("recommendations", []),
                    "confidence": result.get("confidence", 0.0),
                    "source_intel_ids": intelligence_ids,
                }
            return self._fallback_report_summary(intelligence_ids, context)
        except Exception as exc:
            logger.error(f"LLM报告摘要生成失败: {exc}")
            return self._fallback_report_summary(intelligence_ids, context)

    def _fallback_report_summary(self, intelligence_ids: List[str], context: str) -> Dict:
        return {
            "title": "情报报告摘要",
            "summary": context[:500] if context else "",
            "key_findings": [],
            "threat_assessment": "待评估（LLM服务不可用）",
            "recommendations": [],
            "confidence": 0.0,
            "source_intel_ids": intelligence_ids,
        }

    async def generate_intel_brief(self, intelligence_ids: List[str], time_range: str = "最近7天") -> Dict:
        if not self._llm:
            return self._fallback_intel_brief(intelligence_ids, time_range)

        system_prompt = (
            "你是威胁情报简报撰写专家。请根据提供的情报ID列表和时间范围，"
            "生成专业、简洁的情报简报。输出必须为严格的JSON格式，"
            '包含以下字段：briefing（简报正文）、highlights（要点列表）、'
            'emerging_threats（新兴威胁列表）、watch_items（关注事项列表）、'
            'time_range（时间范围）、source_intel_ids（来源情报ID列表）。'
        )

        ids_str = "、".join(intelligence_ids)
        user_prompt = (
            f"情报ID列表: {ids_str}\n时间范围: {time_range}\n\n"
            "请生成情报简报，以JSON格式输出。"
        )

        try:
            result = await self._llm.generate_json(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
            )
            if isinstance(result, dict):
                return {
                    "briefing": result.get("briefing", ""),
                    "highlights": result.get("highlights", []),
                    "emerging_threats": result.get("emerging_threats", []),
                    "watch_items": result.get("watch_items", []),
                    "time_range": time_range,
                    "source_intel_ids": intelligence_ids,
                }
            return self._fallback_intel_brief(intelligence_ids, time_range)
        except Exception as exc:
            logger.error(f"LLM情报简报生成失败: {exc}")
            return self._fallback_intel_brief(intelligence_ids, time_range)

    def _fallback_intel_brief(self, intelligence_ids: List[str], time_range: str) -> Dict:
        ids_str = "、".join(intelligence_ids[:5])
        return {
            "briefing": f"{time_range}内情报简报，涉及情报: {ids_str}（LLM服务不可用，待补充）",
            "highlights": [],
            "emerging_threats": [],
            "watch_items": [],
            "time_range": time_range,
            "source_intel_ids": intelligence_ids,
        }

    async def generate_security_advice(self, threat_analysis: Dict) -> Dict:
        if not self._llm:
            return self._fallback_security_advice(threat_analysis)

        system_prompt = (
            "你是网络安全防护专家。请根据提供的威胁分析结果，"
            "生成专业的安全防护建议。输出必须为严格的JSON格式，"
            '包含以下字段：threat_analysis（威胁分析）、'
            'immediate_actions（即时行动列表）、'
            'long_term_measures（长期措施列表）、'
            'monitoring_suggestions（监控建议列表）、'
            'priority_level（优先级：critical/high/medium/low）。'
        )

        analysis_str = json.dumps(threat_analysis, ensure_ascii=False)[:3000]
        user_prompt = f"威胁分析结果: {analysis_str}\n\n请生成安全防护建议，以JSON格式输出。"

        try:
            result = await self._llm.generate_json(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
            )
            if isinstance(result, dict):
                return {
                    "threat_analysis": result.get("threat_analysis", ""),
                    "immediate_actions": result.get("immediate_actions", []),
                    "long_term_measures": result.get("long_term_measures", []),
                    "monitoring_suggestions": result.get("monitoring_suggestions", []),
                    "priority_level": result.get("priority_level", "medium"),
                }
            return self._fallback_security_advice(threat_analysis)
        except Exception as exc:
            logger.error(f"LLM安全建议生成失败: {exc}")
            return self._fallback_security_advice(threat_analysis)

    def _fallback_security_advice(self, threat_analysis: Dict) -> Dict:
        threat_type = threat_analysis.get("threat_type", "未知威胁")
        return {
            "threat_analysis": f"威胁类型: {threat_type}（LLM服务不可用，待分析）",
            "immediate_actions": [],
            "long_term_measures": [],
            "monitoring_suggestions": [],
            "priority_level": "medium",
        }

    async def generate_trend_analysis(self, time_series_data: List[Dict]) -> Dict:
        if not self._llm:
            return self._fallback_trend_analysis(time_series_data)

        system_prompt = (
            "你是威胁趋势分析专家。请根据提供的时间序列数据，"
            "分析威胁趋势并生成预测。输出必须为严格的JSON格式，"
            '包含以下字段：trend_direction（趋势方向：上升/下降/平稳）、'
            'trend_description（趋势描述）、'
            'key_observations（关键观察列表）、'
            'forecast（预测判断）、'
            'risk_level（风险等级：critical/high/medium/low）、'
            'data_points_analyzed（分析的数据点数量）。'
        )

        data_str = json.dumps(time_series_data, ensure_ascii=False)[:3000]
        user_prompt = f"时间序列数据: {data_str}\n\n请分析趋势并生成预测，以JSON格式输出。"

        try:
            result = await self._llm.generate_json(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
            )
            if isinstance(result, dict):
                return {
                    "trend_direction": result.get("trend_direction", "平稳"),
                    "trend_description": result.get("trend_description", ""),
                    "key_observations": result.get("key_observations", []),
                    "forecast": result.get("forecast", ""),
                    "risk_level": result.get("risk_level", "medium"),
                    "data_points_analyzed": len(time_series_data),
                }
            return self._fallback_trend_analysis(time_series_data)
        except Exception as exc:
            logger.error(f"LLM趋势分析生成失败: {exc}")
            return self._fallback_trend_analysis(time_series_data)

    def _fallback_trend_analysis(self, time_series_data: List[Dict]) -> Dict:
        return {
            "trend_direction": "平稳",
            "trend_description": f"基于{len(time_series_data)}个数据点的趋势分析（LLM服务不可用，待补充）",
            "key_observations": [],
            "forecast": "",
            "risk_level": "medium",
            "data_points_analyzed": len(time_series_data),
        }


class ReviewWorkflow:
    REVIEW_TIMEOUT_HOURS = 48

    TRANSITIONS = {
        ReviewStatus.PENDING: [ReviewStatus.FIRST_REVIEW, ReviewStatus.REJECTED],
        ReviewStatus.FIRST_REVIEW: [ReviewStatus.SECOND_REVIEW, ReviewStatus.REJECTED],
        ReviewStatus.SECOND_REVIEW: [ReviewStatus.APPROVED, ReviewStatus.REJECTED],
        ReviewStatus.APPROVED: [],
        ReviewStatus.REJECTED: [ReviewStatus.PENDING],
    }

    ROLE_PERMISSIONS = {
        ReviewStatus.PENDING: {"reviewer", "expert", "supervisor", "admin"},
        ReviewStatus.FIRST_REVIEW: {"expert", "supervisor", "admin"},
        ReviewStatus.SECOND_REVIEW: {"supervisor", "admin"},
        ReviewStatus.APPROVED: {"admin"},
        ReviewStatus.REJECTED: {"reviewer", "expert", "supervisor", "admin"},
    }

    def __init__(self):
        self._review_levels = {
            "report_summary": ["auto_check", "expert_review"],
            "intel_brief": ["auto_check", "expert_review", "supervisor_approve"],
            "security_advice": ["auto_check", "expert_review", "supervisor_approve"],
            "trend_analysis": ["auto_check", "expert_review"],
            "threat_assessment": ["auto_check", "expert_review", "supervisor_approve"],
            "attack_chain_analysis": ["auto_check", "expert_review", "supervisor_approve"],
            "threat_situation_brief": ["auto_check", "expert_review"],
            "high_risk_alert": ["auto_check", "expert_review", "supervisor_approve"],
            "ioc_report": ["auto_check", "expert_review"],
            "crime_pattern_analysis": ["auto_check", "expert_review", "supervisor_approve"],
        }
        self._auto_check_rules = {
            "min_word_count": 100,
            "max_word_count": 50000,
            "required_sections": {
                "report_summary": ["概述", "关键发现"],
                "intel_brief": ["情报概要", "处置建议"],
                "security_advice": ["防护措施"],
                "trend_analysis": ["趋势概述", "预测判断"],
                "threat_assessment": ["威胁等级", "风险评估", "处置建议"],
                "attack_chain_analysis": ["攻击链路", "关联分析"],
                "threat_situation_brief": ["态势概述", "威胁趋势"],
                "high_risk_alert": ["预警等级", "影响范围", "紧急处置"],
                "ioc_report": ["IoC指标", "关联分析"],
                "crime_pattern_analysis": ["犯罪模式", "链路还原"],
            },
            "sensitive_patterns": [
                r"密码[是为：:]\s*\S+",
                r"api[_-]?key[=:]\s*\S+",
                r"secret[=:]\s*\S+",
            ],
        }
        self._opinions: Dict[str, List[ReviewOpinion]] = {}
        self._versions: Dict[str, List[DocumentVersion]] = {}
        self._review_timestamps: Dict[str, Dict[str, datetime]] = {}
        self._doc_status: Dict[str, ReviewStatus] = {}
        self._doc_content_type: Dict[str, str] = {}
        self._max_documents = 500

    def auto_check(self, content_type: str, content: str) -> Dict[str, Any]:
        issues = []
        warnings = []

        word_count = len(content)
        min_wc = self._auto_check_rules["min_word_count"]
        max_wc = self._auto_check_rules["max_word_count"]

        if word_count < min_wc:
            issues.append(f"内容过短: {word_count}字 (最少{min_wc}字)")
        if word_count > max_wc:
            issues.append(f"内容过长: {word_count}字 (最多{max_wc}字)")

        required = self._auto_check_rules["required_sections"].get(content_type, [])
        for section in required:
            if section not in content:
                warnings.append(f"缺少建议章节: {section}")

        for pattern in self._auto_check_rules["sensitive_patterns"]:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                issues.append(f"检测到敏感信息模式: {pattern} (匹配{len(matches)}处)")

        passed = len(issues) == 0

        return {
            "passed": passed,
            "issues": issues,
            "warnings": warnings,
            "word_count": word_count,
            "content_type": content_type,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

    def get_review_levels(self, content_type: str) -> List[str]:
        return self._review_levels.get(content_type, ["auto_check", "expert_review"])

    def get_review_chain(self, content_type: str) -> List[Dict]:
        levels = self.get_review_levels(content_type)
        role_map = {
            "auto_check": {
                "role": "system",
                "description": "自动化审核",
                "standards": [
                    f"内容字数在{self._auto_check_rules['min_word_count']}-{self._auto_check_rules['max_word_count']}之间",
                    "包含必要章节结构",
                    "不含敏感信息模式",
                ],
            },
            "expert_review": {
                "role": "expert",
                "description": "专家审核",
                "standards": [
                    "内容专业准确性",
                    "情报来源可靠性",
                    "分析逻辑严密性",
                    "术语使用规范性",
                ],
            },
            "supervisor_approve": {
                "role": "supervisor",
                "description": "主管审批",
                "standards": [
                    "内容合规性",
                    "发布风险评估",
                    "信息脱敏完整性",
                ],
            },
        }
        chain = []
        for level in levels:
            info = role_map.get(level, {"role": level, "description": level, "standards": []})
            chain.append({
                "level": level,
                "role": info["role"],
                "description": info["description"],
                "standards": info["standards"],
            })
        return chain

    def can_approve(
        self,
        content_type: str,
        current_status: str,
        reviewer_role: str,
    ) -> bool:
        levels = self.get_review_levels(content_type)

        if current_status == "pending":
            return "auto_check" in levels or reviewer_role in ("admin", "expert")
        elif current_status == "auto_checked":
            return reviewer_role in ("admin", "expert", "supervisor")
        elif current_status == "expert_reviewed":
            return reviewer_role in ("admin", "supervisor")

        return reviewer_role == "admin"

    def next_status(self, content_type: str, current_status: str, action: str) -> str:
        if action == "reject":
            return "rejected"

        levels = self.get_review_levels(content_type)
        status_flow = ["pending"]

        if "auto_check" in levels:
            status_flow.append("auto_checked")
        if "expert_review" in levels:
            status_flow.append("expert_reviewed")
        if "supervisor_approve" in levels:
            status_flow.append("supervisor_approved")

        status_flow.append("approved")

        try:
            current_idx = status_flow.index(current_status)
            if current_idx < len(status_flow) - 1:
                return status_flow[current_idx + 1]
        except ValueError:
            pass

        return "approved"

    def submit_for_review(self, doc_id: str, content_type: str, content: str) -> Dict:
        self._doc_status[doc_id] = ReviewStatus.PENDING
        self._doc_content_type[doc_id] = content_type
        self._review_timestamps[doc_id] = {
            "submitted_at": datetime.now(timezone.utc),
        }
        version = self._create_version(doc_id, content, "初始提交")
        self._opinions[doc_id] = []
        if len(self._doc_status) > self._max_documents:
            oldest_doc = next(iter(self._doc_status))
            self._opinions.pop(oldest_doc, None)
            self._versions.pop(oldest_doc, None)
            self._review_timestamps.pop(oldest_doc, None)
            self._doc_content_type.pop(oldest_doc, None)
            del self._doc_status[oldest_doc]

        return {
            "doc_id": doc_id,
            "status": ReviewStatus.PENDING.value,
            "content_type": content_type,
            "version": version.version,
            "submitted_at": self._review_timestamps[doc_id]["submitted_at"].isoformat(),
        }

    def review(
        self,
        doc_id: str,
        reviewer: str,
        reviewer_role: str,
        action: str,
        comment: str,
        content: Optional[str] = None,
    ) -> Dict:
        current_status = self._doc_status.get(doc_id)
        if current_status is None:
            logger.error(f"文档未提交审核: {doc_id}")
            return {"error": "文档未提交审核", "doc_id": doc_id}

        if action not in ("approve", "reject"):
            return {"error": f"无效操作: {action}", "doc_id": doc_id}

        if reviewer_role not in self.ROLE_PERMISSIONS.get(current_status, set()):
            return {"error": f"角色{reviewer_role}无权在当前状态{current_status.value}下审核", "doc_id": doc_id}

        next_status = self._transition(current_status, action)
        if next_status is None:
            return {"error": f"不允许从{current_status.value}状态执行{action}操作", "doc_id": doc_id}

        self._doc_status[doc_id] = next_status

        opinions = self._opinions.get(doc_id, [])
        version_num = len(self._versions.get(doc_id, []))
        opinion = ReviewOpinion(
            opinion_id=uuid.uuid4().hex,
            doc_id=doc_id,
            reviewer=reviewer,
            reviewer_role=reviewer_role,
            action=action,
            comment=comment,
            version=version_num,
            created_at=datetime.now(timezone.utc),
        )
        opinions.append(opinion)
        self._opinions[doc_id] = opinions

        timestamp_key = f"{next_status.value}_at"
        self._review_timestamps.setdefault(doc_id, {})[timestamp_key] = datetime.now(timezone.utc)

        new_version = None
        if content and action == "approve":
            new_version = self._create_version(doc_id, content, f"{reviewer_role}审核通过后的修订")

        result = {
            "doc_id": doc_id,
            "previous_status": current_status.value,
            "current_status": next_status.value,
            "reviewer": reviewer,
            "reviewer_role": reviewer_role,
            "action": action,
            "comment": comment,
            "version": version_num,
        }

        if new_version:
            result["new_version"] = new_version.version

        return result

    def get_review_status(self, doc_id: str) -> Optional[Dict]:
        status = self._doc_status.get(doc_id)
        if status is None:
            return None

        opinions = self._opinions.get(doc_id, [])
        versions = self._versions.get(doc_id, [])
        timestamps = self._review_timestamps.get(doc_id, {})

        return {
            "doc_id": doc_id,
            "status": status.value,
            "content_type": self._doc_content_type.get(doc_id, ""),
            "opinions_count": len(opinions),
            "current_version": versions[-1].version if versions else 0,
            "timestamps": {k: v.isoformat() for k, v in timestamps.items()},
            "timeout_info": self._check_timeout(doc_id),
        }

    def get_review_opinions(self, doc_id: str) -> List[Dict]:
        opinions = self._opinions.get(doc_id, [])
        return [op.to_dict() for op in opinions]

    def get_document_versions(self, doc_id: str) -> List[Dict]:
        versions = self._versions.get(doc_id, [])
        return [v.to_dict() for v in versions]

    def get_version_content(self, doc_id: str, version: int) -> Optional[str]:
        versions = self._versions.get(doc_id, [])
        for v in versions:
            if v.version == version:
                return v.content
        return None

    def check_timeouts(self) -> List[Dict]:
        timed_out = []
        for doc_id, status in self._doc_status.items():
            if status in (ReviewStatus.APPROVED, ReviewStatus.REJECTED):
                continue
            timeout_info = self._check_timeout(doc_id)
            if timeout_info.get("is_timeout"):
                timed_out.append({
                    "doc_id": doc_id,
                    "status": status.value,
                    "timeout_info": timeout_info,
                })
        return timed_out

    def _transition(self, current: ReviewStatus, action: str) -> Optional[ReviewStatus]:
        allowed = self.TRANSITIONS.get(current, [])
        if action == "approve":
            if current == ReviewStatus.PENDING:
                return ReviewStatus.FIRST_REVIEW
            elif current == ReviewStatus.FIRST_REVIEW:
                return ReviewStatus.SECOND_REVIEW
            elif current == ReviewStatus.SECOND_REVIEW:
                return ReviewStatus.APPROVED
            return None
        elif action == "reject":
            if ReviewStatus.REJECTED in allowed:
                return ReviewStatus.REJECTED
            return None
        return None

    def _create_version(self, doc_id: str, content: str, change_summary: str) -> DocumentVersion:
        versions = self._versions.get(doc_id, [])
        version_num = len(versions) + 1
        version = DocumentVersion(
            version_id=uuid.uuid4().hex,
            doc_id=doc_id,
            version=version_num,
            content=content,
            change_summary=change_summary,
            created_at=datetime.now(timezone.utc),
        )
        versions.append(version)
        self._versions[doc_id] = versions
        return version

    def _check_timeout(self, doc_id: str) -> Dict:
        timestamps = self._review_timestamps.get(doc_id, {})
        submitted_at = timestamps.get("submitted_at")
        if not submitted_at:
            return {"is_timeout": False}

        now = datetime.now(timezone.utc)
        elapsed_hours = (now - submitted_at).total_seconds() / 3600
        timeout_hours = self.REVIEW_TIMEOUT_HOURS

        status = self._doc_status.get(doc_id)
        last_action_time = submitted_at
        for key in ["first_review_at", "second_review_at"]:
            t = timestamps.get(key)
            if t:
                last_action_time = t

        elapsed_from_last = (now - last_action_time).total_seconds() / 3600

        is_timeout = elapsed_from_last > timeout_hours
        is_warning = not is_timeout and elapsed_from_last > timeout_hours * 0.75

        return {
            "is_timeout": is_timeout,
            "is_warning": is_warning,
            "elapsed_hours": round(elapsed_hours, 1),
            "elapsed_from_last_action_hours": round(elapsed_from_last, 1),
            "timeout_threshold_hours": timeout_hours,
            "current_status": status.value if status else None,
        }


class TemplateRenderer:
    def __init__(self, llm_service=None):
        self._llm = llm_service
        self._template_versions: Dict[str, List[TemplateVersion]] = {}
        self._active_versions: Dict[str, int] = {}
        self._max_templates = 200

    async def render(
        self,
        template_content: str,
        variables: Dict[str, Any],
        data: Optional[str] = None,
    ) -> str:
        try:
            result = template_content

            result = self._process_conditionals(result, variables)
            result = self._process_loops(result, variables)
            result = self._process_defaults(result, variables)

            for key, value in variables.items():
                result = result.replace(f"{{{{{key}}}}}", str(value))

            if data:
                data_placeholder = "{{source_data}}"
                if data_placeholder in result:
                    result = result.replace(data_placeholder, data[:3000])
                else:
                    result += f"\n\n## 数据\n{data[:3000]}"

            remaining = re.findall(r"\{\{(\w+)\}\}", result)
            for var in remaining:
                result = result.replace(f"{{{{{var}}}}}", f"[{var}未填充]")

            return result
        except Exception as exc:
            logger.error(f"模板渲染失败: {exc}")
            return await self._fallback_llm_render(template_content, variables, data)

    async def _fallback_llm_render(
        self,
        template_content: str,
        variables: Dict[str, Any],
        data: Optional[str],
    ) -> str:
        if not self._llm:
            logger.warning("模板渲染失败且LLM不可用，返回原始模板")
            return template_content

        try:
            vars_str = json.dumps(variables, ensure_ascii=False)[:2000]
            prompt = (
                f"以下模板渲染失败，请根据变量信息生成最终内容:\n\n"
                f"模板:\n{template_content[:2000]}\n\n"
                f"变量:\n{vars_str}\n"
            )
            if data:
                prompt += f"数据:\n{data[:1000]}\n"
            prompt += "\n请直接输出渲染后的内容，使用Markdown格式。"

            response = await asyncio.wait_for(
                self._llm.chat(prompt),
                timeout=30.0,
            )
            if isinstance(response, dict):
                return response.get("content", template_content)
            elif isinstance(response, str):
                return response
            return template_content
        except Exception as exc:
            logger.error(f"LLM回退渲染失败: {exc}")
            return template_content

    def register_template(self, template_id: str, content: str, description: str = "") -> TemplateVersion:
        versions = self._template_versions.get(template_id, [])
        version_num = len(versions) + 1
        tv = TemplateVersion(
            template_id=template_id,
            version=version_num,
            content=content,
            description=description,
            created_at=datetime.now(timezone.utc),
        )
        versions.append(tv)
        self._template_versions[template_id] = versions
        self._active_versions[template_id] = version_num
        if len(self._active_versions) > self._max_templates:
            oldest_template = next(iter(self._active_versions))
            self._template_versions.pop(oldest_template, None)
            del self._active_versions[oldest_template]
        return tv

    def get_template(self, template_id: str, version: Optional[int] = None) -> Optional[TemplateVersion]:
        versions = self._template_versions.get(template_id, [])
        if not versions:
            return None
        if version is not None:
            for v in versions:
                if v.version == version:
                    return v
            return None
        active_ver = self._active_versions.get(template_id, versions[-1].version)
        for v in versions:
            if v.version == active_ver:
                return v
        return versions[-1]

    def list_template_versions(self, template_id: str) -> List[Dict]:
        versions = self._template_versions.get(template_id, [])
        return [v.to_dict() for v in versions]

    def set_active_version(self, template_id: str, version: int) -> bool:
        versions = self._template_versions.get(template_id, [])
        for v in versions:
            if v.version == version:
                self._active_versions[template_id] = version
                return True
        return False

    async def render_by_id(
        self,
        template_id: str,
        variables: Dict[str, Any],
        data: Optional[str] = None,
        version: Optional[int] = None,
    ) -> Optional[str]:
        tv = self.get_template(template_id, version)
        if tv is None:
            logger.error(f"模板不存在: {template_id}")
            return None
        return await self.render(tv.content, variables, data)

    def _process_conditionals(self, template: str, variables: Dict[str, Any]) -> str:
        pattern = r'\{%\s*if\s+(\w+)\s*%\}(.*?)\{%\s*endif\s*%\}'

        def _replace(match):
            var_name = match.group(1)
            body = match.group(2)
            if variables.get(var_name):
                return body
            return ""

        return re.sub(pattern, _replace, template, flags=re.DOTALL)

    def _process_loops(self, template: str, variables: Dict[str, Any]) -> str:
        pattern = r'\{%\s*for\s+(\w+)\s+in\s+(\w+)\s*%\}(.*?)\{%\s*endfor\s*%\}'

        def _replace(match):
            item_name = match.group(1)
            list_name = match.group(2)
            body = match.group(3)
            items = variables.get(list_name, [])
            if not isinstance(items, (list, tuple)):
                return ""
            parts = []
            for item in items:
                if isinstance(item, dict):
                    rendered = body
                    for k, v in item.items():
                        rendered = rendered.replace(f"{{{{{item_name}.{k}}}}}", str(v))
                    rendered = rendered.replace(f"{{{{{item_name}}}}}", str(item))
                    parts.append(rendered)
                else:
                    parts.append(body.replace(f"{{{{{item_name}}}}}", str(item)))
            return "".join(parts)

        return re.sub(pattern, _replace, template, flags=re.DOTALL)

    def _process_defaults(self, template: str, variables: Dict[str, Any]) -> str:
        pattern = r'\{\{\s*(\w+)\s*\|\s*default\(["\'](.+?)["\']\)\s*\}\}'

        def _replace(match):
            var_name = match.group(1)
            default_val = match.group(2)
            val = variables.get(var_name, default_val)
            return str(val)

        return re.sub(pattern, _replace, template)
