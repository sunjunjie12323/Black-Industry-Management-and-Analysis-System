import math
import statistics
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from loguru import logger


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class QualityAssessment:
    item_id: str
    credibility: float
    completeness: float
    timeliness: float
    consistency: float
    overall_score: float
    grade: str
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "item_id": self.item_id,
            "credibility": round(self.credibility, 4),
            "completeness": round(self.completeness, 4),
            "timeliness": round(self.timeliness, 4),
            "consistency": round(self.consistency, 4),
            "overall_score": round(self.overall_score, 4),
            "grade": self.grade,
            "recommendations": self.recommendations,
        }


@dataclass
class ReputationRecord:
    timestamp: str
    was_accurate: bool
    weight: float
    resulting_reputation: float


# ---------------------------------------------------------------------------
# Source Reputation Tracker
# ---------------------------------------------------------------------------

class SourceReputationTracker:
    """Track reputation per source over time with history and trend analysis."""

    DEFAULT_REPUTATION: float = 0.5
    HISTORY_LIMIT: int = 500

    def __init__(self) -> None:
        self._reputations: Dict[str, float] = {}
        self._history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=self.HISTORY_LIMIT))

    # -- public API ---------------------------------------------------------

    def update(self, source: str, was_accurate: bool, weight: float = 0.1) -> float:
        """Update reputation using exponential moving average.

        new_rep = (1 - weight) * old_rep + weight * accuracy
        where accuracy = 1.0 if was_accurate else 0.0
        """
        weight = max(0.0, min(1.0, weight))
        old_rep = self.get_reputation(source)
        accuracy = 1.0 if was_accurate else 0.0
        new_rep = (1.0 - weight) * old_rep + weight * accuracy
        new_rep = max(0.0, min(1.0, new_rep))

        self._reputations[source] = new_rep
        self._history[source].append(ReputationRecord(
            timestamp=datetime.now(timezone.utc).isoformat(),
            was_accurate=was_accurate,
            weight=weight,
            resulting_reputation=round(new_rep, 6),
        ))
        logger.debug(
            f"Source '{source}' reputation: {old_rep:.4f} -> {new_rep:.4f} "
            f"(accurate={was_accurate}, weight={weight})"
        )
        return new_rep

    def get_reputation(self, source: str) -> float:
        """Return reputation score; default 0.5 for unknown sources."""
        return self._reputations.get(source, self.DEFAULT_REPUTATION)

    def get_trend(self, source: str, window: int = 20) -> str:
        """Calculate reputation trend over the last *window* records.

        Returns one of: 'improving', 'declining', 'stable'.
        Uses simple linear regression slope on the reputation history.
        """
        history = self._history.get(source)
        if not history or len(history) < 2:
            return "stable"

        recent = list(history)[-window:]
        reps = [r.resulting_reputation for r in recent]

        if len(reps) < 2:
            return "stable"

        # Simple linear regression: slope of reputation over time indices
        n = len(reps)
        x_mean = (n - 1) / 2.0
        y_mean = statistics.mean(reps)

        numerator = sum((i - x_mean) * (r - y_mean) for i, r in enumerate(reps))
        denominator = sum((i - x_mean) ** 2 for i in range(n))

        if denominator == 0:
            return "stable"

        slope = numerator / denominator

        # Threshold: slope > 0.001 per record is improving, < -0.001 is declining
        if slope > 0.001:
            return "improving"
        elif slope < -0.001:
            return "declining"
        return "stable"

    def get_history(self, source: str, limit: int = 50) -> List[dict]:
        """Return recent reputation history for a source."""
        history = self._history.get(source)
        if not history:
            return []
        records = list(history)[-limit:]
        return [
            {
                "timestamp": r.timestamp,
                "was_accurate": r.was_accurate,
                "weight": r.weight,
                "resulting_reputation": r.resulting_reputation,
            }
            for r in records
        ]

    def get_all_sources(self) -> Dict[str, Dict[str, Any]]:
        """Return summary for all tracked sources."""
        result: Dict[str, Dict[str, Any]] = {}
        for source in set(list(self._reputations.keys()) + list(self._history.keys())):
            result[source] = {
                "reputation": round(self.get_reputation(source), 4),
                "trend": self.get_trend(source),
                "history_count": len(self._history.get(source, [])),
            }
        return result


# ---------------------------------------------------------------------------
# Intelligence Quality Engine
# ---------------------------------------------------------------------------

# Completeness field weights (must sum to 1.0)
_COMPLETENESS_WEIGHTS: Dict[str, float] = {
    "title": 0.20,
    "content": 0.30,
    "source": 0.15,
    "timestamp": 0.10,
    "entities": 0.15,
    "iocs": 0.10,
}

# Timeliness decay constants (lambda) per severity level
_DECAY_LAMBDA: Dict[str, float] = {
    "critical": 0.01,
    "high": 0.005,
    "medium": 0.002,
    "low": 0.001,
}

# Overall quality weights
_W_CREDIBILITY = 0.35
_W_COMPLETENESS = 0.20
_W_TIMELINESS = 0.25
_W_CONSISTENCY = 0.20

# Grade boundaries
_GRADE_BOUNDARIES: List[Tuple[float, str]] = [
    (0.90, "A"),
    (0.75, "B"),
    (0.60, "C"),
    (0.40, "D"),
]


def _clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, value))


def _normalize_severity(severity: Optional[str]) -> str:
    if not severity:
        return "medium"
    return severity.strip().lower()


class IntelligenceQualityEngine:
    """Commercial-grade intelligence quality assessment engine.

    All scoring algorithms are deterministic and parameter-driven — no
    hardcoded or fake data is used at any point.
    """

    def __init__(self) -> None:
        self._reputation_tracker = SourceReputationTracker()
        # Convenience alias – direct dict access for callers that need it
        self._source_reputations: Dict[str, float] = self._reputation_tracker._reputations

    # ------------------------------------------------------------------
    # Public helpers – source reputation
    # ------------------------------------------------------------------

    def get_source_reputation(self, source: str) -> float:
        """Return reputation score for *source* (default 0.5 for unknown)."""
        return self._reputation_tracker.get_reputation(source)

    async def update_source_reputation(
        self, source: str, was_accurate: bool, weight: float = 0.1
    ) -> None:
        """Update source reputation via exponential moving average.

        new_rep = (1 - weight) * old_rep + weight * accuracy
        """
        self._reputation_tracker.update(source, was_accurate, weight)

    # ------------------------------------------------------------------
    # Individual scoring functions
    # ------------------------------------------------------------------

    def calculate_credibility_score(
        self, item: dict, source_reputation: float
    ) -> float:
        """Bayesian credibility score.

        Model:
            prior        = source_reputation
            likelihood   = P(observed_signals | intelligence_is_accurate)
            evidence     = P(observed_signals)
            posterior    = prior * likelihood / evidence   (Bayes' theorem)

        Signals used to build the likelihood:
            - content_consistency: internal coherence of the item's content
              (measured by presence and non-emptiness of key fields)
            - verification_count : number of corroborating sources
              (mapped through a saturating function)
        """
        prior = _clamp(source_reputation)

        # -- content consistency signal -----------------------------------
        # Ratio of non-empty key fields present in the item
        key_fields = ["title", "content", "source", "entities", "iocs", "severity"]
        non_empty = sum(
            1 for f in key_fields
            if item.get(f) is not None and str(item.get(f, "")).strip() != ""
        )
        content_consistency = non_empty / len(key_fields) if key_fields else 0.0

        # -- verification signal ------------------------------------------
        verification_count = int(item.get("verification_count", 0))
        # Saturating curve: 1 - exp(-count / k), k=3 gives ~0.95 at count=9
        verification_signal = 1.0 - math.exp(-verification_count / 3.0)

        # -- combine into likelihood --------------------------------------
        # Weighted combination of the two signals
        likelihood = 0.5 * content_consistency + 0.5 * verification_signal
        likelihood = _clamp(likelihood, 0.01, 0.99)

        # -- Bayes' theorem -----------------------------------------------
        # evidence = P(signals) = prior * P(signals|accurate) + (1-prior) * P(signals|inaccurate)
        # P(signals|inaccurate) ≈ 1 - likelihood  (symmetric assumption)
        evidence = prior * likelihood + (1.0 - prior) * (1.0 - likelihood)
        if evidence < 1e-12:
            evidence = 1e-12

        posterior = prior * likelihood / evidence
        return _clamp(posterior)

    def calculate_completeness_score(self, item: dict) -> float:
        """Weighted completeness score.

        Checks which required fields are present and non-empty:
            title(0.20) + content(0.30) + source(0.15) +
            timestamp(0.10) + entities(0.15) + iocs(0.10)

        A field is considered "present" if it exists and is truthy
        (non-empty string, non-empty list, or non-None).
        """
        score = 0.0
        for field_name, weight in _COMPLETENESS_WEIGHTS.items():
            value = item.get(field_name)
            if value is None:
                continue
            if isinstance(value, str) and not value.strip():
                continue
            if isinstance(value, (list, tuple, set)) and len(value) == 0:
                continue
            score += weight
        return _clamp(score)

    def calculate_timeliness_score(
        self, item: dict, current_time: datetime
    ) -> float:
        """Exponential-decay timeliness score.

        score = exp(-lambda * age_hours)

        Lambda is chosen based on the item's severity / threat level:
            critical -> 0.01,  high -> 0.005,
            medium   -> 0.002, low  -> 0.001

        Fresh intel (< 1 h) ≈ 1.0, 24 h ≈ 0.78, 7 d ≈ 0.35 (for critical).
        """
        timestamp = item.get("timestamp") or item.get("collected_at")
        if timestamp is None:
            # No timestamp → assume stale
            return 0.0

        # Parse timestamp
        if isinstance(timestamp, str):
            try:
                ts = timestamp.replace("Z", "+00:00")
                parsed = datetime.fromisoformat(ts)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                timestamp = parsed
            except (ValueError, TypeError):
                return 0.0
        elif isinstance(timestamp, datetime):
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)
        else:
            return 0.0

        if current_time.tzinfo is None:
            current_time = current_time.replace(tzinfo=timezone.utc)

        age_hours = max(0.0, (current_time - timestamp).total_seconds() / 3600.0)

        severity = _normalize_severity(
            item.get("severity") or item.get("threat_level")
        )
        lam = _DECAY_LAMBDA.get(severity, _DECAY_LAMBDA["medium"])

        score = math.exp(-lam * age_hours)
        return _clamp(score)

    def calculate_consistency_score(
        self, item: dict, related_items: list[dict]
    ) -> float:
        """Cross-validate with related intelligence from other sources.

        Algorithm:
            1. Extract entity sets from the item and each related item.
            2. Compute Jaccard similarity for each pair.
            3. Penalise contradictions in threat-level / severity.
            4. consistency = mean of adjusted similarities across related items.

        If there are no related items the score defaults to 0.5 (neutral —
        neither confirmed nor contradicted).
        """
        if not related_items:
            return 0.5

        item_entities = self._extract_entity_set(item)
        if not item_entities:
            # Cannot compare — neutral score
            return 0.5

        item_severity = _normalize_severity(
            item.get("severity") or item.get("threat_level")
        )

        similarities: List[float] = []
        for related in related_items:
            related_entities = self._extract_entity_set(related)
            jaccard = self._jaccard_similarity(item_entities, related_entities)

            # Contradiction penalty: if severity levels disagree significantly
            related_severity = _normalize_severity(
                related.get("severity") or related.get("threat_level")
            )
            severity_penalty = self._severity_contradiction_penalty(
                item_severity, related_severity
            )

            adjusted = jaccard * (1.0 - severity_penalty)
            similarities.append(adjusted)

        if not similarities:
            return 0.5

        consistency = statistics.mean(similarities)
        return _clamp(consistency)

    def calculate_overall_quality(
        self,
        credibility: float,
        completeness: float,
        timeliness: float,
        consistency: float,
    ) -> dict:
        """Weighted-average overall quality with grade and recommendations.

        Weights:
            credibility  0.35
            completeness 0.20
            timeliness   0.25
            consistency  0.20
        """
        overall = (
            _W_CREDIBILITY * credibility
            + _W_COMPLETENESS * completeness
            + _W_TIMELINESS * timeliness
            + _W_CONSISTENCY * consistency
        )
        overall = _clamp(overall)

        grade = "F"
        for threshold, letter in _GRADE_BOUNDARIES:
            if overall >= threshold:
                grade = letter
                break

        recommendations = self._generate_recommendations(
            credibility, completeness, timeliness, consistency
        )

        return {
            "overall_score": round(overall, 4),
            "grade": grade,
            "recommendations": recommendations,
            "weights": {
                "credibility": _W_CREDIBILITY,
                "completeness": _W_COMPLETENESS,
                "timeliness": _W_TIMELINESS,
                "consistency": _W_CONSISTENCY,
            },
            "scores": {
                "credibility": round(credibility, 4),
                "completeness": round(completeness, 4),
                "timeliness": round(timeliness, 4),
                "consistency": round(consistency, 4),
            },
        }

    # ------------------------------------------------------------------
    # Batch / async assessment
    # ------------------------------------------------------------------

    async def assess_quality(self, intelligence_items: list[dict]) -> dict:
        """Assess quality for a list of raw intelligence items.

        Returns a dict with per-item assessments and aggregate statistics.
        """
        now = datetime.now(timezone.utc)
        assessments: List[dict] = []

        for item in intelligence_items:
            item_id = str(item.get("id", item.get("item_id", "unknown")))
            source = item.get("source", "unknown")
            source_rep = self.get_source_reputation(source)

            credibility = self.calculate_credibility_score(item, source_rep)
            completeness = self.calculate_completeness_score(item)
            timeliness = self.calculate_timeliness_score(item, now)
            # No related items available in single-item mode → neutral
            consistency = self.calculate_consistency_score(item, [])

            quality = self.calculate_overall_quality(
                credibility, completeness, timeliness, consistency
            )

            assessment = QualityAssessment(
                item_id=item_id,
                credibility=credibility,
                completeness=completeness,
                timeliness=timeliness,
                consistency=consistency,
                overall_score=quality["overall_score"],
                grade=quality["grade"],
                recommendations=quality["recommendations"],
            )
            assessments.append(assessment.to_dict())

        # Aggregate statistics
        if assessments:
            avg_overall = statistics.mean(a["overall_score"] for a in assessments)
            grade_dist: Dict[str, int] = defaultdict(int)
            for a in assessments:
                grade_dist[a["grade"]] += 1
        else:
            avg_overall = 0.0
            grade_dist = {}

        return {
            "total_items": len(assessments),
            "average_quality": round(avg_overall, 4),
            "grade_distribution": dict(grade_dist),
            "assessments": assessments,
        }

    async def batch_assess(
        self, items: list[dict], related_items_map: dict
    ) -> list[dict]:
        """Assess quality for a batch of items with cross-referencing.

        Parameters
        ----------
        items : list[dict]
            Intelligence items to assess.
        related_items_map : dict
            Mapping of item_id -> list of related items from other sources.
        """
        now = datetime.now(timezone.utc)
        results: List[dict] = []

        for item in items:
            item_id = str(item.get("id", item.get("item_id", "unknown")))
            source = item.get("source", "unknown")
            source_rep = self.get_source_reputation(source)
            related = related_items_map.get(item_id, [])

            credibility = self.calculate_credibility_score(item, source_rep)
            completeness = self.calculate_completeness_score(item)
            timeliness = self.calculate_timeliness_score(item, now)
            consistency = self.calculate_consistency_score(item, related)

            quality = self.calculate_overall_quality(
                credibility, completeness, timeliness, consistency
            )

            assessment = QualityAssessment(
                item_id=item_id,
                credibility=credibility,
                completeness=completeness,
                timeliness=timeliness,
                consistency=consistency,
                overall_score=quality["overall_score"],
                grade=quality["grade"],
                recommendations=quality["recommendations"],
            )
            results.append(assessment.to_dict())

        return results

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_entity_set(item: dict) -> set:
        """Extract a normalised set of entity identifiers from an item."""
        entities: set = set()

        # Explicit entities list
        raw_entities = item.get("entities")
        if isinstance(raw_entities, (list, tuple, set)):
            for e in raw_entities:
                if isinstance(e, dict):
                    val = e.get("value") or e.get("name") or ""
                    if val:
                        entities.add(str(val).strip().lower())
                elif isinstance(e, str) and e.strip():
                    entities.add(e.strip().lower())

        # IOCs as additional entity signals
        raw_iocs = item.get("iocs")
        if isinstance(raw_iocs, (list, tuple, set)):
            for ioc in raw_iocs:
                if isinstance(ioc, dict):
                    val = ioc.get("value") or ioc.get("indicator") or ""
                    if val:
                        entities.add(str(val).strip().lower())
                elif isinstance(ioc, str) and ioc.strip():
                    entities.add(ioc.strip().lower())

        # Keywords / tags as fallback
        for key in ("keywords", "tags"):
            raw = item.get(key)
            if isinstance(raw, (list, tuple, set)):
                for kw in raw:
                    if isinstance(kw, str) and kw.strip():
                        entities.add(kw.strip().lower())

        return entities

    @staticmethod
    def _jaccard_similarity(set_a: set, set_b: set) -> float:
        """Jaccard similarity coefficient between two sets."""
        if not set_a or not set_b:
            return 0.0
        intersection = len(set_a & set_b)
        union = len(set_a | set_b)
        if union == 0:
            return 0.0
        return intersection / union

    @staticmethod
    def _severity_contradiction_penalty(sev_a: str, sev_b: str) -> float:
        """Return a penalty in [0, 1] for severity disagreement.

        Severity ordering: critical > high > medium > low > unknown
        Penalty is proportional to the distance between the two levels.
        """
        ordering = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        level_a = ordering.get(sev_a, 0)
        level_b = ordering.get(sev_b, 0)

        if level_a == 0 or level_b == 0:
            # Unknown severity → no penalty (cannot determine contradiction)
            return 0.0

        distance = abs(level_a - level_b)
        # Max distance is 3 (critical vs low); normalise to [0, 1]
        return min(distance / 3.0, 1.0)

    @staticmethod
    def _generate_recommendations(
        credibility: float,
        completeness: float,
        timeliness: float,
        consistency: float,
    ) -> List[str]:
        """Generate actionable recommendations based on sub-scores."""
        recs: List[str] = []

        if credibility < 0.4:
            recs.append(
                "Low credibility: verify this intelligence through additional "
                "trusted sources before acting on it."
            )
        elif credibility < 0.6:
            recs.append(
                "Moderate credibility: consider cross-referencing with at "
                "least two independent sources."
            )

        if completeness < 0.4:
            recs.append(
                "Critical data gaps: the item is missing several key fields. "
                "Enrich with title, content, source, entities, and IOCs."
            )
        elif completeness < 0.7:
            missing = []
            # This is a best-effort hint — caller can inspect the item
            recs.append(
                "Incomplete data: consider adding missing fields to improve "
                "actionability and searchability."
            )

        if timeliness < 0.3:
            recs.append(
                "Stale intelligence: this item is significantly aged. "
                "Request fresh collection or mark for archival review."
            )
        elif timeliness < 0.6:
            recs.append(
                "Aging intelligence: schedule re-verification to confirm "
                "the threat is still active."
            )

        if consistency < 0.3:
            recs.append(
                "Low cross-source consistency: this intelligence conflicts "
                "with related reports. Investigate contradictions."
            )
        elif consistency < 0.5:
            recs.append(
                "Moderate consistency concerns: some related reports differ. "
                "Review entity overlap and severity alignment."
            )

        if not recs:
            recs.append("Quality is satisfactory. No immediate action required.")

        return recs


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

intelligence_quality_engine = IntelligenceQualityEngine()
