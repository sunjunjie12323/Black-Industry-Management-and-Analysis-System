import json
import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from loguru import logger

from app.core.llm import LLMService
from app.core.vector_store import VectorStore

try:
    import jieba
    _JIEBA_AVAILABLE = True
except ImportError:
    _JIEBA_AVAILABLE = False


class ConfirmationStatus(str, Enum):
    UNCONFIRMED = "unconfirmed"
    AI_CONFIRMED = "ai_confirmed"
    HUMAN_CONFIRMED = "human_confirmed"
    DISPUTED = "disputed"


class Evidence:
    def __init__(
        self,
        id: str,
        source_id: str,
        source_type: str,
        content: str,
        confidence: float,
        timestamp: Optional[datetime] = None,
        confirmation_status: ConfirmationStatus = ConfirmationStatus.UNCONFIRMED,
        collection_time: Optional[datetime] = None,
    ):
        self.id = id
        self.source_id = source_id
        self.source_type = source_type
        self.content = content
        self.confidence = confidence
        self.timestamp = timestamp or datetime.now(timezone.utc)
        self.confirmation_status = confirmation_status
        self.collection_time = collection_time or self.timestamp

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "source_id": self.source_id,
            "source_type": self.source_type,
            "content": self.content,
            "confidence": self.confidence,
            "timestamp": self.timestamp.isoformat(),
            "confirmation_status": self.confirmation_status.value,
            "collection_time": self.collection_time.isoformat(),
        }


class HallucinationReport:
    def __init__(
        self,
        is_likely_hallucination: bool,
        flagged_claims: List[Dict],
        evidence_gaps: List[str],
        hallucination_score: float = 0.0,
    ):
        self.is_likely_hallucination = is_likely_hallucination
        self.flagged_claims = flagged_claims
        self.evidence_gaps = evidence_gaps
        self.hallucination_score = hallucination_score

    def to_dict(self) -> dict:
        return {
            "is_likely_hallucination": self.is_likely_hallucination,
            "flagged_claims": self.flagged_claims,
            "evidence_gaps": self.evidence_gaps,
            "hallucination_score": self.hallucination_score,
        }


class CrossValidator:
    MIN_SOURCES_FOR_HIGH_CONFIDENCE = 3
    MIN_SOURCES_FOR_MEDIUM_CONFIDENCE = 2

    def __init__(self, credibility_tracker: Optional["SourceCredibilityTracker"] = None):
        self._credibility_tracker = credibility_tracker

    def cross_validate(self, evidence_list: List[Evidence]) -> Dict:
        if not evidence_list:
            return {
                "confidence_level": "low",
                "independent_source_count": 0,
                "corroborating_sources": [],
                "conflicting_sources": [],
            }

        independent_sources = self._identify_independent_sources(evidence_list)
        ioc_groups = self._group_by_ioc(evidence_list)

        corroborating = []
        conflicting = []

        for ioc, evidences in ioc_groups.items():
            if len(evidences) >= 2:
                corroborating.append({
                    "ioc": ioc,
                    "source_count": len(evidences),
                    "source_types": list({e.source_type for e in evidences}),
                })
            else:
                conflicting.append({
                    "ioc": ioc,
                    "source_count": 1,
                    "note": "single_source_no_corroboration",
                })

        source_count = len(independent_sources)

        if source_count >= self.MIN_SOURCES_FOR_HIGH_CONFIDENCE:
            confidence_level = "high"
        elif source_count >= self.MIN_SOURCES_FOR_MEDIUM_CONFIDENCE:
            confidence_level = "medium"
        else:
            confidence_level = "low"

        if self._credibility_tracker:
            weighted_score = sum(
                self._credibility_tracker.get_credibility(e.source_id) for e in evidence_list
            ) / len(evidence_list)
            if weighted_score < 0.3 and confidence_level == "high":
                confidence_level = "medium"
                logger.debug(f"Downgraded confidence due to low source credibility: {weighted_score:.2f}")

        return {
            "confidence_level": confidence_level,
            "independent_source_count": source_count,
            "corroborating_sources": corroborating,
            "conflicting_sources": conflicting,
        }

    def _identify_independent_sources(self, evidence_list: List[Evidence]) -> List[str]:
        source_groups: Dict[str, List[Evidence]] = {}
        for e in evidence_list:
            key = f"{e.source_type}:{e.source_id}"
            if key not in source_groups:
                source_groups[key] = []
            source_groups[key].append(e)

        independent_ids = []
        seen_types_times: Dict[str, datetime] = {}

        for key, evidences in source_groups.items():
            e = evidences[0]
            is_independent = True
            for existing_type, existing_time in seen_types_times.items():
                if existing_type == e.source_type:
                    time_diff = abs((e.collection_time - existing_time).total_seconds())
                    if time_diff < 3600:
                        is_independent = False
                        break
            if is_independent:
                independent_ids.append(e.source_id)
                seen_types_times[e.source_type] = e.collection_time

        return independent_ids

    def _group_by_ioc(self, evidence_list: List[Evidence]) -> Dict[str, List[Evidence]]:
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        domain_pattern = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
        url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
        email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        sha256_pattern = re.compile(r'\b[a-fA-F0-9]{64}\b')

        ioc_groups: Dict[str, List[Evidence]] = {}

        for e in evidence_list:
            iocs = set()
            for pat in [ip_pattern, domain_pattern, url_pattern, email_pattern, sha256_pattern]:
                iocs.update(pat.findall(e.content))
            for ioc in iocs:
                if ioc not in ioc_groups:
                    ioc_groups[ioc] = []
                ioc_groups[ioc].append(e)

        return ioc_groups


class SourceCredibilityTracker:
    def __init__(self):
        self._max_hypotheses = 100
        self._alpha: Dict[str, float] = {}
        self._beta: Dict[str, float] = {}
        self._prior_alpha = 5.0
        self._prior_beta = 5.0

    def update_credibility(self, source: str, was_accurate: bool) -> None:
        if source not in self._alpha:
            self._alpha[source] = self._prior_alpha
            self._beta[source] = self._prior_beta
        if was_accurate:
            self._alpha[source] += 1.0
        else:
            self._beta[source] += 1.0
        if len(self._alpha) > self._max_hypotheses:
            oldest_key = next(iter(self._alpha))
            self._beta.pop(oldest_key, None)
            del self._alpha[oldest_key]
        logger.debug(f"Source credibility updated: {source} accurate={was_accurate} alpha={self._alpha[source]} beta={self._beta[source]}")

    def get_credibility(self, source: str) -> float:
        if source not in self._alpha:
            self._alpha[source] = self._prior_alpha
            self._beta[source] = self._prior_beta
        alpha = self._alpha[source]
        beta = self._beta[source]
        return alpha / (alpha + beta)

    def get_credibility_details(self, source: str) -> Dict:
        if source not in self._alpha:
            self._alpha[source] = self._prior_alpha
            self._beta[source] = self._prior_beta
        alpha = self._alpha[source]
        beta = self._beta[source]
        total = alpha + beta - self._prior_alpha - self._prior_beta
        return {
            "source": source,
            "credibility": alpha / (alpha + beta),
            "accurate_count": alpha - self._prior_alpha,
            "inaccurate_count": beta - self._prior_beta,
            "total_verifications": int(total),
        }

    def to_dict(self) -> Dict:
        result = {}
        for source in self._alpha:
            result[source] = self.get_credibility_details(source)
        return result


class HallucinationDetector:
    def __init__(self, llm_service: Optional[LLMService] = None):
        self._llm = llm_service

    async def detect_hallucination(self, original_content: str, llm_analysis: str) -> HallucinationReport:
        flagged_claims = []
        evidence_gaps = []

        rule_result = self._rule_based_detection(original_content, llm_analysis)
        flagged_claims.extend(rule_result["flagged_claims"])
        evidence_gaps.extend(rule_result["evidence_gaps"])

        if self._llm:
            try:
                llm_result = await self._llm_based_detection(original_content, llm_analysis)
                flagged_claims.extend(llm_result["flagged_claims"])
                evidence_gaps.extend(llm_result["evidence_gaps"])
            except Exception as exc:
                logger.warning(f"LLM hallucination detection failed: {exc}")

        hallucination_score = self._compute_hallucination_score(flagged_claims, evidence_gaps)
        is_likely = hallucination_score > 0.5 or len(flagged_claims) >= 3

        return HallucinationReport(
            is_likely_hallucination=is_likely,
            flagged_claims=flagged_claims,
            evidence_gaps=evidence_gaps,
            hallucination_score=hallucination_score,
        )

    def _rule_based_detection(self, original_content: str, llm_analysis: str) -> Dict:
        flagged_claims = []
        evidence_gaps = []

        specific_number_pattern = re.compile(r'\b\d+(?:\.\d+)?%?\b')
        original_numbers = set(specific_number_pattern.findall(original_content))
        analysis_numbers = set(specific_number_pattern.findall(llm_analysis))
        fabricated_numbers = analysis_numbers - original_numbers
        if fabricated_numbers:
            flagged_claims.append({
                "type": "fabricated_numbers",
                "detail": f"LLM添加了原始内容中未提及的具体数字: {', '.join(list(fabricated_numbers)[:10])}",
                "severity": "high",
            })
            evidence_gaps.append(f"数字 {', '.join(list(fabricated_numbers)[:5])} 无原始来源支持")

        name_pattern = re.compile(r'[\u4e00-\u9fff]{2,4}(?:集团|公司|组织|团伙|团队|平台)')
        original_names = set(name_pattern.findall(original_content))
        analysis_names = set(name_pattern.findall(llm_analysis))
        fabricated_names = analysis_names - original_names
        if fabricated_names:
            flagged_claims.append({
                "type": "fabricated_names",
                "detail": f"LLM添加了原始内容中未提及的名称: {', '.join(list(fabricated_names)[:5])}",
                "severity": "high",
            })
            evidence_gaps.append(f"名称 {', '.join(list(fabricated_names)[:3])} 无原始来源支持")

        date_pattern = re.compile(r'\d{4}[-/年]\d{1,2}[-/月]\d{1,2}[日]?')
        original_dates = set(date_pattern.findall(original_content))
        analysis_dates = set(date_pattern.findall(llm_analysis))
        fabricated_dates = analysis_dates - original_dates
        if fabricated_dates:
            flagged_claims.append({
                "type": "fabricated_dates",
                "detail": f"LLM添加了原始内容中未提及的日期: {', '.join(list(fabricated_dates)[:5])}",
                "severity": "medium",
            })
            evidence_gaps.append(f"日期 {', '.join(list(fabricated_dates)[:3])} 无原始来源支持")

        confidence_pattern = re.compile(r'(?:置信度|confidence|可信度)[^\d]*(\d+(?:\.\d+)?)%?')
        confidence_matches = confidence_pattern.findall(llm_analysis)
        if confidence_matches:
            for conf_str in confidence_matches:
                conf_val = float(conf_str)
                if conf_val > 90 or (conf_val > 0.9 and conf_val <= 1.0):
                    if len(original_content) < 100:
                        flagged_claims.append({
                            "type": "confidence_mismatch",
                            "detail": f"LLM输出高置信度({conf_val})但原始证据不足",
                            "severity": "medium",
                        })
                        evidence_gaps.append("高置信度声明与证据数量不匹配")

        return {
            "flagged_claims": flagged_claims,
            "evidence_gaps": evidence_gaps,
        }

    async def _llm_based_detection(self, original_content: str, llm_analysis: str) -> Dict:
        system_prompt = (
            "你是一个AI幻觉检测专家。比较LLM分析和原始内容，找出LLM添加的、原始内容中未提及的具体声明。\n"
            "请以JSON格式返回：\n"
            '{"flagged_claims": [{"type": "hallucinated_claim", "detail": "描述", "severity": "high/medium/low"}], "evidence_gaps": ["缺失的证据1", "缺失的证据2"]}\n\n'
            "只返回JSON，不要其他内容。"
        )
        prompt = f"原始内容：\n{original_content[:2000]}\n\nLLM分析：\n{llm_analysis[:2000]}"

        response = await self._llm.generate(
            prompt=prompt,
            system_prompt=system_prompt,
            temperature=0.1,
            max_tokens=500,
        )

        try:
            result = json.loads(response.strip())
            return {
                "flagged_claims": result.get("flagged_claims", []),
                "evidence_gaps": result.get("evidence_gaps", []),
            }
        except json.JSONDecodeError:
            logger.warning("Failed to parse LLM hallucination detection response as JSON")
            return {"flagged_claims": [], "evidence_gaps": []}

    def _compute_hallucination_score(self, flagged_claims: List[Dict], evidence_gaps: List[str]) -> float:
        if not flagged_claims and not evidence_gaps:
            return 0.0

        severity_weights = {"high": 0.4, "medium": 0.2, "low": 0.1}
        claim_score = sum(severity_weights.get(c.get("severity", "low"), 0.1) for c in flagged_claims)
        gap_score = len(evidence_gaps) * 0.1

        total = claim_score + gap_score
        return min(1.0, total)


class VerificationResult:
    def __init__(
        self,
        conclusion: str,
        confidence: float,
        evidence_count: int,
        source_count: int,
        cross_validated: bool,
        evidence_list: List[Evidence],
        verification_details: str,
        confirmation_level: str = "unconfirmed",
    ):
        self.conclusion = conclusion
        self.confidence = confidence
        self.evidence_count = evidence_count
        self.source_count = source_count
        self.cross_validated = cross_validated
        self.evidence_list = evidence_list
        self.verification_details = verification_details
        self.confirmation_level = confirmation_level

    def to_dict(self) -> dict:
        return {
            "conclusion": self.conclusion,
            "confidence": self.confidence,
            "evidence_count": self.evidence_count,
            "source_count": self.source_count,
            "cross_validated": self.cross_validated,
            "evidence_list": [e.to_dict() for e in self.evidence_list],
            "verification_details": self.verification_details,
            "confirmation_level": self.confirmation_level,
        }


class EvidenceChain:
    MIN_SOURCES_FOR_CROSS_VALIDATION = 2
    SOURCE_TYPE_WEIGHTS = {
        "intelligence": 1.0,
        "entity": 0.8,
        "external": 0.9,
    }
    CONSISTENCY_WEIGHT = 0.4
    SOURCE_COUNT_WEIGHT = 0.3
    DIVERSITY_WEIGHT = 0.2
    CROSS_VALIDATION_WEIGHT = 0.1

    def __init__(self, llm: LLMService, vector_store: VectorStore):
        self.llm = llm
        self.vector_store = vector_store
        self._credibility_tracker = SourceCredibilityTracker()
        self._cross_validator = CrossValidator(self._credibility_tracker)
        self._hallucination_detector = HallucinationDetector(llm_service=llm)

    @property
    def credibility_tracker(self) -> SourceCredibilityTracker:
        return self._credibility_tracker

    @property
    def cross_validator(self) -> CrossValidator:
        return self._cross_validator

    @property
    def hallucination_detector(self) -> HallucinationDetector:
        return self._hallucination_detector

    async def verify(
        self, conclusion: str, sources: List[Evidence]
    ) -> VerificationResult:
        if not sources:
            return VerificationResult(
                conclusion=conclusion,
                confidence=0.0,
                evidence_count=0,
                source_count=0,
                cross_validated=False,
                evidence_list=[],
                verification_details="无证据来源，无法验证",
                confirmation_level="unconfirmed",
            )

        unique_sources = {e.source_id for e in sources}
        source_types = {e.source_type for e in sources}

        try:
            consistency_score = await self._assess_consistency(conclusion, sources)
        except Exception as exc:
            logger.warning(f"LLM consistency assessment failed, using rule-based fallback: {exc}")
            consistency_score = self._rule_based_consistency_check(conclusion, sources)

        source_count_score = min(len(unique_sources) / 5.0, 1.0)

        diversity_score = min(len(source_types) / 3.0, 1.0)

        cross_validated = len(unique_sources) >= self.MIN_SOURCES_FOR_CROSS_VALIDATION
        cross_validation_score = 1.0 if cross_validated else 0.0

        avg_evidence_confidence = sum(e.confidence for e in sources) / len(sources)

        cross_result = self._cross_validator.cross_validate(sources)

        final_confidence = (
            consistency_score * self.CONSISTENCY_WEIGHT
            + source_count_score * self.SOURCE_COUNT_WEIGHT
            + diversity_score * self.DIVERSITY_WEIGHT
            + cross_validation_score * self.CROSS_VALIDATION_WEIGHT
        ) * avg_evidence_confidence

        final_confidence = max(0.0, min(1.0, final_confidence))

        confirmation_level = self._determine_confirmation_level(sources, cross_result)

        details = self._build_verification_details(
            conclusion=conclusion,
            sources=sources,
            consistency_score=consistency_score,
            source_count_score=source_count_score,
            diversity_score=diversity_score,
            cross_validated=cross_validated,
            avg_evidence_confidence=avg_evidence_confidence,
            final_confidence=final_confidence,
            cross_result=cross_result,
            confirmation_level=confirmation_level,
        )

        return VerificationResult(
            conclusion=conclusion,
            confidence=final_confidence,
            evidence_count=len(sources),
            source_count=len(unique_sources),
            cross_validated=cross_validated,
            evidence_list=sources,
            verification_details=details,
            confirmation_level=confirmation_level,
        )

    def _determine_confirmation_level(self, sources: List[Evidence], cross_result: Dict) -> str:
        has_human = any(e.confirmation_status == ConfirmationStatus.HUMAN_CONFIRMED for e in sources)
        has_disputed = any(e.confirmation_status == ConfirmationStatus.DISPUTED for e in sources)
        has_ai = any(e.confirmation_status == ConfirmationStatus.AI_CONFIRMED for e in sources)

        if has_disputed:
            return "disputed"
        if has_human and cross_result["confidence_level"] in ("high", "medium"):
            return "human_confirmed"
        if has_ai and cross_result["confidence_level"] == "high":
            return "ai_confirmed"
        if cross_result["confidence_level"] == "high":
            return "ai_confirmed"
        if cross_result["confidence_level"] == "medium":
            return "ai_confirmed"
        return "unconfirmed"

    async def _assess_consistency(
        self, conclusion: str, sources: List[Evidence]
    ) -> float:
        if len(sources) == 0:
            return 0.0
        if len(sources) == 1:
            return sources[0].confidence * 0.8

        evidence_text = "\n".join(
            f"[来源{i+1}] (类型: {e.source_type}, 置信度: {e.confidence:.2f}): {e.content[:300]}"
            for i, e in enumerate(sources)
        )

        system_prompt = (
            "你是一个情报分析验证专家。你需要评估以下结论是否被提供的证据所支持。\n"
            "请给出0到1之间的一致性分数：\n"
            "- 1.0: 所有证据完全支持结论\n"
            "- 0.7-0.9: 大部分证据支持结论\n"
            "- 0.4-0.6: 部分证据支持，部分矛盾\n"
            "- 0.1-0.3: 大部分证据与结论矛盾\n"
            "- 0.0: 证据完全不支持结论\n\n"
            "只返回一个0到1之间的数字，不要其他内容。"
        )
        prompt = f"结论：{conclusion}\n\n证据：\n{evidence_text}"

        try:
            response = await self.llm.generate(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=0.1,
                max_tokens=10,
            )
            score = float(response.strip())
            return max(0.0, min(1.0, score))
        except (ValueError, TypeError) as exc:
            logger.warning(f"Failed to parse consistency score from LLM: {exc}")
            return self._rule_based_consistency_check(conclusion, sources)
        except Exception as exc:
            logger.error(f"Consistency assessment failed: {exc}")
            return self._rule_based_consistency_check(conclusion, sources)

    def _rule_based_consistency_check(self, conclusion: str, sources: List[Evidence]) -> float:
        if not sources:
            return 0.0

        score = 0.8

        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        domain_pattern = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
        url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
        email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        sha256_pattern = re.compile(r'\b[a-fA-F0-9]{64}\b')

        iocs_in_conclusion = set()
        for pat in [ip_pattern, domain_pattern, url_pattern, email_pattern, sha256_pattern]:
            iocs_in_conclusion.update(pat.findall(conclusion))

        iocs_in_sources = set()
        for s in sources:
            for pat in [ip_pattern, domain_pattern, url_pattern, email_pattern, sha256_pattern]:
                iocs_in_sources.update(pat.findall(s.content))

        if iocs_in_conclusion:
            overlap = iocs_in_conclusion & iocs_in_sources
            ratio = len(overlap) / len(iocs_in_conclusion)
            if ratio < 0.3:
                score -= 0.2
                logger.debug(f"Rule check: IoC overlap low ({ratio:.2f}), penalizing")

        severe_keywords = ["严重", "critical", "极高", "紧急", "重大"]
        low_keywords = ["low", "低", "轻微", "一般"]
        conclusion_lower = conclusion.lower()
        has_severe = any(kw in conclusion_lower for kw in severe_keywords)
        if has_severe:
            all_low = all(
                any(kw in s.content.lower() for kw in low_keywords)
                for s in sources
            )
            if all_low and sources:
                score -= 0.3
                logger.debug("Rule check: severe conclusion but all sources low, penalizing")

        unique_source_types = {s.source_type for s in sources}
        if len(unique_source_types) == 1 and len(sources) > 2:
            score -= 0.1
            logger.debug("Rule check: single source type, penalizing")

        return max(0.0, min(1.0, score))

    def _build_verification_details(
        self,
        conclusion: str,
        sources: List[Evidence],
        consistency_score: float,
        source_count_score: float,
        diversity_score: float,
        cross_validated: bool,
        avg_evidence_confidence: float,
        final_confidence: float,
        cross_result: Optional[Dict] = None,
        confirmation_level: str = "unconfirmed",
    ) -> str:
        unique_sources = {e.source_id for e in sources}
        source_types = {e.source_type for e in sources}
        lines = [
            f"结论验证报告：{conclusion[:100]}",
            f"最终置信度：{final_confidence:.2f}",
            f"确认等级：{confirmation_level}",
            f"证据数量：{len(sources)}",
            f"独立来源数：{len(unique_sources)}",
            f"来源类型：{', '.join(source_types)}",
            f"是否交叉验证：{'是' if cross_validated else '否'}",
            f"一致性分数：{consistency_score:.2f}",
            f"来源数量分数：{source_count_score:.2f}",
            f"多样性分数：{diversity_score:.2f}",
            f"证据平均置信度：{avg_evidence_confidence:.2f}",
        ]
        if cross_result:
            lines.append(f"交叉验证置信等级：{cross_result.get('confidence_level', 'unknown')}")
            lines.append(f"独立来源确认数：{cross_result.get('independent_source_count', 0)}")
            corroborating = cross_result.get("corroborating_sources", [])
            if corroborating:
                lines.append(f"互相印证的IoC数：{len(corroborating)}")
        if final_confidence >= 0.8:
            lines.append("验证结论：高度可信，结论被充分证据支持")
        elif final_confidence >= 0.6:
            lines.append("验证结论：较为可信，但建议补充更多来源验证")
        elif final_confidence >= 0.4:
            lines.append("验证结论：可信度一般，需要更多证据支持")
        else:
            lines.append("验证结论：可信度较低，结论可能不被证据支持")
        return "\n".join(lines)

    async def create_evidence_chain(
        self, conclusion: str, analysis_result: dict
    ) -> List[Evidence]:
        evidence_list: List[Evidence] = []

        raw_ids = analysis_result.get("raw_intelligence_ids", [])
        for raw_id in raw_ids:
            evidence = Evidence(
                id=uuid4().hex,
                source_id=raw_id,
                source_type="intelligence",
                content=analysis_result.get("analysis_summary", ""),
                confidence=analysis_result.get("confidence_score", 0.5),
            )
            evidence_list.append(evidence)

        entity_ids = analysis_result.get("entity_ids", [])
        for entity_id in entity_ids:
            evidence = Evidence(
                id=uuid4().hex,
                source_id=entity_id,
                source_type="entity",
                content=f"关联实体: {entity_id}",
                confidence=0.6,
            )
            evidence_list.append(evidence)

        external_refs = analysis_result.get("external_references", [])
        for ref in external_refs:
            if isinstance(ref, dict):
                evidence = Evidence(
                    id=uuid4().hex,
                    source_id=ref.get("id", uuid4().hex),
                    source_type="external",
                    content=ref.get("content", ""),
                    confidence=ref.get("confidence", 0.5),
                )
            else:
                evidence = Evidence(
                    id=uuid4().hex,
                    source_id=str(ref),
                    source_type="external",
                    content=str(ref),
                    confidence=0.5,
                )
            evidence_list.append(evidence)

        logger.info(
            f"Created evidence chain for conclusion '{conclusion[:50]}...': "
            f"{len(evidence_list)} evidence items"
        )
        return evidence_list

    async def detect_hallucination(self, claim: str, context: str) -> float:
        report = await self._hallucination_detector.detect_hallucination(context, claim)
        return report.hallucination_score
