"""
动态风险评分引擎
基于 CVSS 标准的多维度风险评估算法，支持行业差异化评分、时间衰减、级联风险分析
"""
import math
import asyncio
from collections import defaultdict
from typing import Any, Optional

from loguru import logger


# ---------------------------------------------------------------------------
# CVSS v3.1 标准常量
# ---------------------------------------------------------------------------
# Attack Vector 评分
_ATTACK_VECTOR = {
    "network": 0.85,
    "adjacent": 0.62,
    "adjacent_network": 0.62,
    "local": 0.55,
    "physical": 0.20,
}

# Attack Complexity
_ATTACK_COMPLEXITY = {
    "low": 0.77,
    "high": 0.44,
}

# Privileges Required (depends on scope, use unscoped as default)
_PRIVILEGES_REQUIRED = {
    "none": 0.85,
    "low": 0.62,
    "high": 0.27,
}

# User Interaction
_USER_INTERACTION = {
    "none": 0.85,
    "required": 0.62,
}

# ---------------------------------------------------------------------------
# 威胁类型基础严重度 (0.0 – 1.0)
# ---------------------------------------------------------------------------
_THREAT_TYPE_BASE_SEVERITY = {
    "apt": 0.95,
    "zero_day": 0.90,
    "ransomware": 0.88,
    "data_breach": 0.82,
    "supply_chain": 0.85,
    "malware": 0.70,
    "phishing": 0.55,
    "ddos": 0.50,
    "botnet": 0.65,
    "c2": 0.75,
    "credential_theft": 0.72,
    "insider_threat": 0.78,
    "cryptojacking": 0.45,
    "spam": 0.20,
    "scam": 0.40,
    "fraud": 0.60,
    "default": 0.50,
}

# ---------------------------------------------------------------------------
# 行业影响乘数
# ---------------------------------------------------------------------------
_INDUSTRY_IMPACT_MULTIPLIER = {
    "general": 1.0,
    "finance": 1.3,
    "healthcare": 1.4,
    "manufacturing": 1.1,
    "education": 1.0,
    "government": 1.3,
    "energy": 1.3,
    "telecom": 1.2,
    "retail": 1.1,
    "technology": 1.0,
}

# ---------------------------------------------------------------------------
# 行业风险矩阵权重
# ---------------------------------------------------------------------------
_INDUSTRY_RISK_WEIGHTS = {
    "general": {
        "severity": 0.25,
        "exploitability": 0.20,
        "impact": 0.25,
        "velocity": 0.15,
        "determinism": 0.15,
    },
    "finance": {
        "severity": 0.20,
        "exploitability": 0.15,
        "impact": 0.35,
        "velocity": 0.15,
        "determinism": 0.15,
    },
    "healthcare": {
        "severity": 0.25,
        "exploitability": 0.15,
        "impact": 0.30,
        "velocity": 0.15,
        "determinism": 0.15,
    },
    "manufacturing": {
        "severity": 0.25,
        "exploitability": 0.20,
        "impact": 0.25,
        "velocity": 0.20,
        "determinism": 0.10,
    },
    "education": {
        "severity": 0.20,
        "exploitability": 0.25,
        "impact": 0.20,
        "velocity": 0.20,
        "determinism": 0.15,
    },
}

# ---------------------------------------------------------------------------
# 行业风险等级阈值
# ---------------------------------------------------------------------------
_INDUSTRY_THRESHOLDS = {
    "general": {"critical": 80, "high": 60, "medium": 40, "low": 20},
    "finance": {"critical": 70, "high": 50, "medium": 35, "low": 15},
    "healthcare": {"critical": 65, "high": 45, "medium": 30, "low": 15},
    "manufacturing": {"critical": 75, "high": 55, "medium": 40, "low": 20},
    "education": {"critical": 80, "high": 60, "medium": 40, "low": 20},
}


def _clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    """Clamp a float to [lo, hi]."""
    return max(lo, min(hi, value))


def _safe_float(value: Any, default: float = 0.0) -> float:
    """Safely convert a value to float, returning *default* on failure."""
    if value is None:
        return default
    try:
        return float(value)
    except (ValueError, TypeError):
        return default


# ---------------------------------------------------------------------------
# RiskMatrix
# ---------------------------------------------------------------------------
class RiskMatrix:
    """Predefined risk matrices for different industries."""

    SUPPORTED_INDUSTRIES = ("general", "finance", "healthcare", "manufacturing", "education")

    def get_matrix(self, industry: str) -> dict:
        """Return industry-specific dimension weights (sum ≈ 1.0)."""
        industry = industry.lower().strip()
        if industry not in _INDUSTRY_RISK_WEIGHTS:
            logger.debug(f"Unknown industry '{industry}', falling back to 'general'")
            industry = "general"
        return dict(_INDUSTRY_RISK_WEIGHTS[industry])

    def get_thresholds(self, industry: str) -> dict:
        """Return risk-level thresholds for the given industry."""
        industry = industry.lower().strip()
        if industry not in _INDUSTRY_THRESHOLDS:
            industry = "general"
        return dict(_INDUSTRY_THRESHOLDS[industry])

    def get_industry_multiplier(self, industry: str) -> float:
        """Return the impact multiplier for the given industry."""
        industry = industry.lower().strip()
        return _INDUSTRY_IMPACT_MULTIPLIER.get(industry, 1.0)


# ---------------------------------------------------------------------------
# DynamicRiskScorer
# ---------------------------------------------------------------------------
class DynamicRiskScorer:
    """
    动态风险评分引擎

    综合 CVSS v3.1 可利用性公式、指数时间衰减、级联风险分析等算法，
    对威胁事件进行多维度量化评估。
    """

    # CVSS v3.1 exploitability coefficient constant
    _CVSS_EXPLOIT_COEFFICIENT = 8.22

    def __init__(self, risk_matrix: Optional[RiskMatrix] = None):
        self._risk_matrix = risk_matrix or RiskMatrix()
        logger.info("DynamicRiskScorer initialised")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def calculate_risk_score(
        self,
        threat_event: dict,
        context: dict | None = None,
    ) -> dict:
        """
        Calculate a comprehensive risk score for *threat_event*.

        Returns a dict with:
          - risk_score (0–100)
          - risk_level (critical / high / medium / low / info)
          - breakdown of each dimension
        """
        context = context or {}
        industry = context.get("industry", "general")

        severity = self.calculate_severity_score(threat_event)
        exploitability = self.calculate_exploitability_score(threat_event)
        impact = self.calculate_impact_score(threat_event, industry=industry)
        velocity = self.calculate_velocity_score(threat_event)
        determinism = self.calculate_determinism_score(threat_event)

        weights = self._risk_matrix.get_matrix(industry)

        raw_score = (
            weights["severity"] * severity
            + weights["exploitability"] * exploitability
            + weights["impact"] * impact
            + weights["velocity"] * velocity
            + weights["determinism"] * determinism
        )

        # Scale to 0-100
        risk_score_100 = _clamp(raw_score, 0.0, 1.0) * 100.0

        # Optional time-decay
        age_hours = _safe_float(context.get("age_hours"), -1.0)
        half_life = _safe_float(context.get("half_life_hours"), 168.0)
        if age_hours >= 0:
            risk_score_100 = self.apply_time_decay(risk_score_100, age_hours, half_life)

        risk_level = self.get_risk_level(risk_score_100)

        breakdown = {
            "severity": round(severity, 4),
            "exploitability": round(exploitability, 4),
            "impact": round(impact, 4),
            "velocity": round(velocity, 4),
            "determinism": round(determinism, 4),
            "weights": weights,
            "industry": industry,
        }

        logger.debug(
            f"Risk score calculated: {risk_score_100:.2f} ({risk_level}) | "
            f"severity={severity:.3f} exploit={exploitability:.3f} "
            f"impact={impact:.3f} velocity={velocity:.3f} "
            f"determinism={determinism:.3f}"
        )

        return {
            "risk_score": round(risk_score_100, 2),
            "risk_level": risk_level,
            "breakdown": breakdown,
        }

    # ------------------------------------------------------------------
    # Dimension scorers (each returns 0.0 – 1.0)
    # ------------------------------------------------------------------

    def calculate_severity_score(self, event: dict) -> float:
        """
        Base severity from threat type and CVSS-like scoring.

        Weighted factors:
          data_sensitivity (0.30) + scope (0.25) +
          reversibility (0.20) + regulatory_impact (0.25)
        """
        # Threat-type base
        threat_type = str(event.get("threat_type", "default")).lower().strip()
        type_base = _THREAT_TYPE_BASE_SEVERITY.get(
            threat_type,
            _THREAT_TYPE_BASE_SEVERITY["default"],
        )

        # Optional CVSS base-score override (0-10 → 0-1)
        cvss_score = _safe_float(event.get("cvss_score"), -1.0)
        if 0.0 <= cvss_score <= 10.0:
            type_base = max(type_base, cvss_score / 10.0)

        # Factor 1 – data_sensitivity (0-1)
        data_sensitivity = _clamp(_safe_float(event.get("data_sensitivity"), 0.5))

        # Factor 2 – scope: ratio of affected assets / total assets
        affected = _safe_float(event.get("affected_count", 0))
        total = _safe_float(event.get("total_assets", 0))
        if total > 0:
            scope = _clamp(affected / total)
        else:
            scope = _clamp(_safe_float(event.get("scope"), 0.5))

        # Factor 3 – reversibility (0 = fully reversible, 1 = irreversible)
        reversibility = 1.0 - _clamp(_safe_float(event.get("reversibility"), 0.5))

        # Factor 4 – regulatory_impact (0-1)
        regulatory_impact = _clamp(_safe_float(event.get("regulatory_impact"), 0.5))

        severity = (
            0.30 * data_sensitivity
            + 0.25 * scope
            + 0.20 * reversibility
            + 0.25 * regulatory_impact
        )

        # Blend with threat-type base (70 % factor-driven, 30 % type-driven)
        severity = 0.70 * severity + 0.30 * type_base

        return _clamp(severity)

    def calculate_exploitability_score(self, event: dict) -> float:
        """
        How easy is this threat to exploit?

        CVSS-inspired formula:
          exploitability = 8.22 × AttackVector × AttackComplexity
                                    × PrivilegesRequired × UserInteraction
        Normalised to 0.0 – 1.0 (max theoretical ≈ 8.22).
        """
        av_key = str(event.get("attack_vector", "network")).lower().strip()
        ac_key = str(event.get("attack_complexity", "low")).lower().strip()
        pr_key = str(event.get("required_privileges", event.get("privileges_required", "none"))).lower().strip()
        ui_key = str(event.get("user_interaction", "none")).lower().strip()

        av = _ATTACK_VECTOR.get(av_key, 0.85)
        ac = _ATTACK_COMPLEXITY.get(ac_key, 0.77)
        pr = _PRIVILEGES_REQUIRED.get(pr_key, 0.85)
        ui = _USER_INTERACTION.get(ui_key, 0.85)

        raw = self._CVSS_EXPLOIT_COEFFICIENT * av * ac * pr * ui

        # Normalise: theoretical max = 8.22 * 0.85 * 0.77 * 0.85 * 0.85 ≈ 4.48
        # Use the theoretical max for normalisation so the result maps to 0-1.
        theoretical_max = (
            self._CVSS_EXPLOIT_COEFFICIENT
            * max(_ATTACK_VECTOR.values())
            * max(_ATTACK_COMPLEXITY.values())
            * max(_PRIVILEGES_REQUIRED.values())
            * max(_USER_INTERACTION.values())
        )
        score = raw / theoretical_max if theoretical_max > 0 else 0.0

        # Boost if public exploit is available
        exploit_available = event.get("availability_of_exploit", event.get("exploit_available"))
        if exploit_available is not None:
            if isinstance(exploit_available, bool):
                if exploit_available:
                    score = min(1.0, score * 1.15)
            elif str(exploit_available).lower() in ("true", "yes", "1", "public"):
                score = min(1.0, score * 1.15)

        return _clamp(score)

    def calculate_impact_score(self, event: dict, industry: str = "general") -> float:
        """
        Business impact based on industry context.

        Factors: financial_loss, reputation_damage, operational_disruption,
                 legal_liability  (each 0-1, equally weighted).
        An industry-specific multiplier is applied and the result capped at 1.0.
        """
        financial_loss = _clamp(_safe_float(event.get("financial_loss"), 0.5))
        reputation_damage = _clamp(_safe_float(event.get("reputation_damage"), 0.5))
        operational_disruption = _clamp(_safe_float(event.get("operational_disruption"), 0.5))
        legal_liability = _clamp(_safe_float(event.get("legal_liability"), 0.5))

        base_impact = (
            0.25 * financial_loss
            + 0.25 * reputation_damage
            + 0.25 * operational_disruption
            + 0.25 * legal_liability
        )

        multiplier = self._risk_matrix.get_industry_multiplier(industry)
        return _clamp(base_impact * multiplier)

    def calculate_velocity_score(self, event: dict) -> float:
        """
        How fast is this threat spreading?

        Velocity = affected_count / time_hours  (normalised).
        Uses a sigmoid-like mapping so that very high rates saturate at 1.0.
        """
        affected_count = _safe_float(event.get("affected_count", 0))
        time_hours = _safe_float(event.get("time_since_discovery", 0))
        propagation_rate = _safe_float(event.get("propagation_rate"), -1.0)

        if propagation_rate >= 0:
            # If an explicit propagation_rate (0-1) is supplied, use it directly.
            velocity = _clamp(propagation_rate)
        elif time_hours > 0 and affected_count > 0:
            raw_velocity = affected_count / time_hours  # hosts per hour
            # Sigmoid normalisation: v / (v + k), k=10 means 10 hosts/h → 0.5
            velocity = raw_velocity / (raw_velocity + 10.0)
        else:
            # Fall back to affected_count_growth if available
            growth = _safe_float(event.get("affected_count_growth"), 0)
            velocity = _clamp(growth / (growth + 50.0))  # logistic with k=50

        return _clamp(velocity)

    def calculate_determinism_score(self, event: dict) -> float:
        """
        How certain are we about this threat?

        Based on: source_count, verification_status, confidence_level,
                  evidence_quality.
        """
        # source_count → more sources = higher certainty
        source_count = int(_safe_float(event.get("source_count"), 1))
        source_score = min(1.0, math.log2(max(source_count, 1) + 1) / 4.0)

        # verification_status
        verification_map = {
            "verified": 1.0,
            "confirmed": 1.0,
            "partially_verified": 0.7,
            "unverified": 0.4,
            "rumor": 0.2,
            "unknown": 0.3,
        }
        v_status = str(event.get("verification_status", "unknown")).lower().strip()
        verification_score = verification_map.get(v_status, 0.3)

        # confidence_level (0-1)
        confidence_level = _clamp(_safe_float(event.get("confidence_level"), 0.5))

        # evidence_quality (0-1)
        evidence_quality = _clamp(_safe_float(event.get("evidence_quality"), 0.5))

        determinism = (
            0.20 * source_score
            + 0.25 * verification_score
            + 0.30 * confidence_level
            + 0.25 * evidence_quality
        )

        return _clamp(determinism)

    # ------------------------------------------------------------------
    # Time decay
    # ------------------------------------------------------------------

    def apply_time_decay(
        self,
        risk_score: float,
        age_hours: float,
        half_life_hours: float = 168.0,
    ) -> float:
        """
        Exponential decay:
            decayed = score × exp(−0.693 × age / half_life)

        Default half-life = 7 days (168 hours).
        """
        if half_life_hours <= 0:
            return risk_score
        decay_factor = math.exp(-0.693 * age_hours / half_life_hours)
        return _clamp(risk_score * decay_factor, 0.0, 100.0)

    # ------------------------------------------------------------------
    # Cascade risk
    # ------------------------------------------------------------------

    def calculate_cascade_risk(
        self,
        primary_risk: float,
        dependent_systems: list[dict],
    ) -> float:
        """
        Calculate cascading risk to dependent systems.

        For each dependent system:
            cascade_factor = coupling_strength × dependency_criticality
        Total cascade = primary_risk × Σ(cascade_factors), capped at 1.0.
        """
        if not dependent_systems:
            return 0.0

        total_cascade = 0.0
        for system in dependent_systems:
            coupling = _clamp(_safe_float(system.get("coupling_strength"), 0.5))
            criticality = _clamp(_safe_float(system.get("dependency_criticality"), 0.5))
            total_cascade += coupling * criticality

        cascade_risk = primary_risk * total_cascade
        return _clamp(cascade_risk)

    # ------------------------------------------------------------------
    # Risk level mapping
    # ------------------------------------------------------------------

    def get_risk_level(self, score: float) -> str:
        """
        Map a 0-100 score to a risk level string.

        0-20  → info
        20-40 → low
        40-60 → medium
        60-80 → high
        80-100 → critical
        """
        if score >= 80:
            return "critical"
        if score >= 60:
            return "high"
        if score >= 40:
            return "medium"
        if score >= 20:
            return "low"
        return "info"

    # ------------------------------------------------------------------
    # Batch scoring
    # ------------------------------------------------------------------

    async def batch_score(
        self,
        events: list[dict],
        context: dict | None = None,
    ) -> list[dict]:
        """
        Score multiple events, applying cross-event adjustments.

        If multiple events share entities (by ``entity_value`` or ``id``),
        risk is increased by 10 % per additional overlapping event.
        """
        context = context or {}

        # Score each event independently first
        results: list[dict] = []
        for event in events:
            result = await self.calculate_risk_score(event, context)
            result["event_id"] = event.get("id", event.get("event_id", ""))
            results.append(result)

        if len(results) <= 1:
            return results

        # Build entity → event-index mapping for cross-event amplification
        entity_map: dict[str, list[int]] = defaultdict(list)
        for idx, event in enumerate(events):
            entities = event.get("entities", [])
            if isinstance(entities, str):
                entities = [e.strip() for e in entities.split(",") if e.strip()]
            # Also consider entity_value as a shared key
            ev = event.get("entity_value", "")
            if ev:
                entities.append(ev)
            eid = event.get("id", event.get("event_id", ""))
            if eid:
                entities.append(eid)

            for entity in entities:
                entity_map[str(entity).lower().strip()].append(idx)

        # Count how many *other* events each event shares entities with
        overlap_count: dict[int, int] = defaultdict(int)
        for _entity, indices in entity_map.items():
            unique_indices = set(indices)
            if len(unique_indices) <= 1:
                continue
            for idx in unique_indices:
                overlap_count[idx] += len(unique_indices) - 1

        # Apply 10 % boost per additional overlapping event
        for idx, result in enumerate(results):
            extra = overlap_count.get(idx, 0)
            if extra > 0:
                boost = 1.0 + 0.10 * extra
                new_score = min(100.0, result["risk_score"] * boost)
                result["risk_score"] = round(new_score, 2)
                result["risk_level"] = self.get_risk_level(new_score)
                result["cross_event_boost"] = round(boost, 4)

        return results


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------
dynamic_risk_scorer = DynamicRiskScorer()
