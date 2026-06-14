import asyncio
import json
import math
import os
import random
from collections import Counter, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional
from uuid import uuid4

import numpy as np
from loguru import logger

from app.config import settings
from app.core.knowledge_graph import KnowledgeGraph
from app.core.vector_store import VectorStore


# Reference defaults - override via ORGANISM_HALF_LIFE_JSON / ORGANISM_VITALITY_RANGE_JSON / ORGANISM_EXPECTED_MENTIONS_JSON env vars
SPECIES_HALF_LIFE_HOURS = {
    "ip": 72,
    "phone": 168,
    "bankcard": 336,
    "domain": 720,
    "ttp": 2160,
    "organization": 4320,
    "slang": 8760,
    "campaign": 720,
}

DEFAULT_HALF_LIFE = 720

DEATH_THRESHOLD = 0.1

REBORN_VITALITY_BOOST = 0.3

GENE_INHERITANCE_VITALITY_BOOST = 0.2

EXPECTED_MENTIONS_PER_HOUR = {
    "ip": 0.5,
    "phone": 0.2,
    "bankcard": 0.1,
    "domain": 0.05,
    "ttp": 0.02,
    "organization": 0.01,
    "slang": 0.005,
    "campaign": 0.05,
}

SIGNIFICANT_CHANGE_THRESHOLD = 0.3

SPECIES_INITIAL_VITALITY_RANGE = {
    "ip": (0.6, 0.95),
    "domain": (0.6, 0.95),
    "phone": (0.5, 0.85),
    "bankcard": (0.5, 0.85),
    "organization": (0.3, 0.7),
    "ttp": (0.3, 0.7),
    "slang": (0.5, 0.85),
    "campaign": (0.4, 0.75),
}

DEFAULT_INITIAL_VITALITY_RANGE = (0.4, 0.85)


def _load_organism_config():
    global SPECIES_HALF_LIFE_HOURS, SPECIES_INITIAL_VITALITY_RANGE, EXPECTED_MENTIONS_PER_HOUR
    from app.config import settings
    if settings.ORGANISM_HALF_LIFE_JSON:
        try:
            SPECIES_HALF_LIFE_HOURS = json.loads(settings.ORGANISM_HALF_LIFE_JSON)
        except (json.JSONDecodeError, TypeError):
            pass
    if settings.ORGANISM_VITALITY_RANGE_JSON:
        try:
            loaded = json.loads(settings.ORGANISM_VITALITY_RANGE_JSON)
            SPECIES_INITIAL_VITALITY_RANGE = {k: tuple(v) for k, v in loaded.items()}
        except (json.JSONDecodeError, TypeError):
            pass
    if settings.ORGANISM_EXPECTED_MENTIONS_JSON:
        try:
            EXPECTED_MENTIONS_PER_HOUR = json.loads(settings.ORGANISM_EXPECTED_MENTIONS_JSON)
        except (json.JSONDecodeError, TypeError):
            pass


_load_organism_config()

ACTIVITY_EMA_ALPHA = 0.3

HALF_LIFE_ADJUSTMENT_FACTOR = 0.5

MIN_HALF_LIFE_MULTIPLIER = 0.25

MAX_HALF_LIFE_MULTIPLIER = 3.0


@dataclass
class EvolutionEvent:
    timestamp: str
    event_type: str
    description: str
    trigger: str
    before_state: Dict
    after_state: Dict
    related_intelligence_ids: List[str]

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class IntelligenceOrganism:
    intelligence_id: str
    species: str
    born_at: str
    current_age_hours: float
    generation: int
    vitality: float
    evolution_log: List[EvolutionEvent]
    mutations: List[Dict]
    offspring: List[str]
    parent_ids: List[str]
    current_state: Dict
    half_life: float
    is_alive: bool
    next_check_at: str
    mention_count: int = 0
    confirmed_use_count: int = 0
    total_use_count: int = 0

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class VitalityReport:
    organism_id: str
    vitality: float
    freshness: float
    activity: float
    relevance: float
    is_alive: bool
    age_hours: float
    half_life_hours: float
    recommended_action: str
    generation: int

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class ValidationResult:
    step_index: int
    predicted_action: str
    predicted_probability: float
    actual_occurred: bool
    evidence: List[str]
    validated_at: str
    time_to_occurrence: Optional[float]

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class PredictionTracker:
    prediction_id: str
    entity_id: str
    predicted_steps: List[Dict]
    made_at: str
    validation_window: str
    validation_deadline: str
    validations: List[ValidationResult]
    accuracy_score: float
    model_calibration: Dict

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class OrganismTree:
    root_id: str
    nodes: List[Dict]
    edges: List[Dict]

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class IntelligenceGene:
    gene_id: str
    species: str
    patterns: List[str]
    associations: List[str]
    attack_chains: List[str]
    confidence_history: List[float]
    total_lifetime_hours: float
    cause_of_death: str
    preserved_at: str

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class GenealogyTree:
    organism_id: str
    current_generation: int
    ancestors: List[Dict]
    total_ancestors: int
    inherited_patterns: List[str]
    inherited_associations: List[str]

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class AccuracyReport:
    total_predictions: int
    correct_predictions: int
    accuracy: float
    calibration_data: Dict
    brier_score: float

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class CalibrationResult:
    bias_direction: str
    calibration_factors: Dict
    sample_size: int

    def to_dict(self) -> Dict:
        return asdict(self)


class AdaptiveHalfLifeCalculator:
    def __init__(self):
        self._max_sources = 200
        self._activity_history: Dict[str, deque] = {}
        self._ema_values: Dict[str, float] = {}
        self._half_life_multipliers: Dict[str, float] = {}

    def update_activity(self, organism_id: str, mention_count: int, hours_elapsed: float):
        if hours_elapsed <= 0:
            return
        current_rate = mention_count / hours_elapsed
        if organism_id not in self._activity_history:
            self._activity_history[organism_id] = deque(maxlen=50)
            self._ema_values[organism_id] = current_rate
        self._activity_history[organism_id].append(current_rate)
        prev_ema = self._ema_values[organism_id]
        self._ema_values[organism_id] = ACTIVITY_EMA_ALPHA * current_rate + (1 - ACTIVITY_EMA_ALPHA) * prev_ema
        if len(self._ema_values) > self._max_sources:
            oldest_source = next(iter(self._ema_values))
            self._activity_history.pop(oldest_source, None)
            self._half_life_multipliers.pop(oldest_source, None)
            del self._ema_values[oldest_source]

    def compute_adaptive_half_life(self, organism_id: str, species: str, base_half_life: float) -> float:
        if organism_id not in self._ema_values:
            return base_half_life
        ema = self._ema_values[organism_id]
        expected_rate = EXPECTED_MENTIONS_PER_HOUR.get(species, 0.01)
        if expected_rate <= 0:
            return base_half_life
        ratio = ema / expected_rate
        if ratio > 1.0:
            multiplier = 1.0 + HALF_LIFE_ADJUSTMENT_FACTOR * math.log2(ratio)
        else:
            multiplier = 1.0 - HALF_LIFE_ADJUSTMENT_FACTOR * (1.0 - ratio)
        multiplier = max(MIN_HALF_LIFE_MULTIPLIER, min(MAX_HALF_LIFE_MULTIPLIER, multiplier))
        self._half_life_multipliers[organism_id] = multiplier
        return base_half_life * multiplier

    def get_multiplier(self, organism_id: str) -> float:
        return self._half_life_multipliers.get(organism_id, 1.0)

    def remove_organism(self, organism_id: str):
        self._activity_history.pop(organism_id, None)
        self._ema_values.pop(organism_id, None)
        self._half_life_multipliers.pop(organism_id, None)

    def to_persist_dict(self) -> Dict:
        return {
            "ema_values": self._ema_values,
            "half_life_multipliers": self._half_life_multipliers,
        }

    def from_persist_dict(self, data: Dict):
        if "ema_values" in data:
            self._ema_values = data["ema_values"]
        if "half_life_multipliers" in data:
            self._half_life_multipliers = data["half_life_multipliers"]


class SemanticChangeDetector:
    def __init__(self, vector_store: VectorStore = None):
        self._vector_store = vector_store
        self._max_cache_size = 1000
        self._embedding_cache: Dict[str, np.ndarray] = {}

    async def compute_semantic_similarity(self, text_a: str, text_b: str) -> float:
        if self._vector_store is None:
            return self._improved_jaccard_similarity(text_a, text_b)
        try:
            emb_a = await self._get_embedding(text_a)
            emb_b = await self._get_embedding(text_b)
            if emb_a is not None and emb_b is not None:
                vec_a = np.array(emb_a, dtype=np.float64)
                vec_b = np.array(emb_b, dtype=np.float64)
                norm_a = np.linalg.norm(vec_a)
                norm_b = np.linalg.norm(vec_b)
                if norm_a > 0 and norm_b > 0:
                    return float(np.dot(vec_a, vec_b) / (norm_a * norm_b))
        except Exception as exc:
            logger.debug(f"Semantic embedding failed, falling back to Jaccard: {exc}")
        return self._improved_jaccard_similarity(text_a, text_b)

    async def detect_significant_change(
        self, before: Dict, after: Dict, threshold: float = SIGNIFICANT_CHANGE_THRESHOLD
    ) -> bool:
        for key in after:
            if key not in before:
                return True
        combined_before = self._state_to_text(before)
        combined_after = self._state_to_text(after)
        if not combined_before and not combined_after:
            return False
        if not combined_before or not combined_after:
            return True
        similarity = await self.compute_semantic_similarity(combined_before, combined_after)
        return (1.0 - similarity) > threshold

    async def _get_embedding(self, text: str) -> Optional[List[float]]:
        cache_key = text[:200]
        if cache_key in self._embedding_cache:
            return self._embedding_cache[cache_key].tolist()
        try:
            embedding = await self._vector_store.get_embedding(text)
            if embedding:
                self._embedding_cache[cache_key] = np.array(embedding, dtype=np.float64)
                if len(self._embedding_cache) > self._max_cache_size:
                    oldest_key = next(iter(self._embedding_cache))
                    del self._embedding_cache[oldest_key]
            return embedding
        except Exception:
            return None

    def _state_to_text(self, state: Dict) -> str:
        parts = []
        for key, val in state.items():
            if isinstance(val, (str, int, float)):
                parts.append(f"{key}:{val}")
            elif isinstance(val, list):
                parts.append(f"{key}:{' '.join(str(v) for v in val)}")
            elif isinstance(val, dict):
                parts.append(f"{key}:{json.dumps(val, ensure_ascii=False)}")
        return " ".join(parts)

    def _improved_jaccard_similarity(self, text_a: str, text_b: str) -> float:
        import re
        tokens_a = set(re.findall(r'[a-zA-Z_]{2,}|[\u4e00-\u9fff]{2,}', text_a.lower()))
        tokens_b = set(re.findall(r'[a-zA-Z_]{2,}|[\u4e00-\u9fff]{2,}', text_b.lower()))
        if not tokens_a and not tokens_b:
            return 1.0
        if not tokens_a or not tokens_b:
            return 0.0
        intersection = tokens_a & tokens_b
        union = tokens_a | tokens_b
        return len(intersection) / len(union)


class LLMEnhancedEvolution:
    async def llm_analyze_significance(
        self, llm_service, before_state: Dict, after_state: Dict
    ) -> Optional[bool]:
        if llm_service is None:
            return None
        try:
            before_summary = json.dumps(before_state, ensure_ascii=False, default=str)[:800]
            after_summary = json.dumps(after_state, ensure_ascii=False, default=str)[:800]
            json_format_significance = '{"significant": true/false, "reason": "简短原因"}'
            prompt = (
                "你是黑灰产威胁情报分析专家。请判断以下情报实体的状态变化是否具有实质性意义。\n\n"
                f"变化前状态：{before_summary}\n\n"
                f"变化后状态：{after_summary}\n\n"
                f"请仅回答JSON格式：{json_format_significance}\n"
                "判断标准：是否出现了新的威胁指标、攻击手法、关联实体、置信度重大变化等。"
                "格式变化、时间戳更新等非实质性变化不算。"
            )
            result = await llm_service.generate_json(
                prompt=prompt,
                system_prompt="你是黑灰产威胁情报分析专家，仅输出JSON格式。",
                temperature=settings.LLM_TEMPERATURE_DEFAULT,
            )
            if isinstance(result, dict):
                return result.get("significant", None)
        except Exception as exc:
            logger.debug(f"LLM significance analysis failed: {exc}")
        return None

    async def llm_infer_initial_vitality(
        self, llm_service, species: str, initial_data: Dict
    ) -> Optional[float]:
        if llm_service is None:
            return None
        try:
            data_summary = json.dumps(initial_data, ensure_ascii=False, default=str)[:800]
            json_format_vitality = '{"vitality": 0.75, "reason": "简短原因"}'
            prompt = (
                "你是黑灰产威胁情报分析专家。请根据以下情报内容推断该实体的初始活力值(0.0-1.0)。\n\n"
                f"实体类型：{species}\n"
                f"情报内容：{data_summary}\n\n"
                "判断标准：\n"
                "- 高活力(0.8-1.0)：明确的攻击指标、活跃的威胁源、高置信度情报\n"
                "- 中活力(0.5-0.8)：疑似威胁、中等置信度、有部分佐证\n"
                "- 低活力(0.2-0.5)：模糊情报、低置信度、缺乏佐证\n\n"
                f"请仅回答JSON格式：{json_format_vitality}"
            )
            result = await llm_service.generate_json(
                prompt=prompt,
                system_prompt="你是黑灰产威胁情报分析专家，仅输出JSON格式。",
                temperature=settings.LLM_TEMPERATURE_DEFAULT,
            )
            if isinstance(result, dict) and "vitality" in result:
                vitality = float(result["vitality"])
                return max(0.1, min(1.0, vitality))
        except Exception as exc:
            logger.debug(f"LLM vitality inference failed: {exc}")
        return None

    async def llm_recommend_action(
        self, llm_service, organism, vitality_report
    ) -> Optional[str]:
        if llm_service is None:
            return None
        try:
            state_summary = json.dumps(organism.current_state, ensure_ascii=False, default=str)[:500]
            json_format_action = '{"action": "行动建议", "priority": "high/medium/low"}'
            alive_status = "存活" if vitality_report.is_alive else "已死亡"
            prompt = (
                "你是黑灰产威胁情报分析专家。请根据以下情报有机体的状态给出行动建议。\n\n"
                f"实体ID：{organism.intelligence_id}\n"
                f"类型：{organism.species}\n"
                f"活力值：{vitality_report.vitality:.4f}\n"
                f"新鲜度：{vitality_report.freshness:.4f}\n"
                f"活跃度：{vitality_report.activity:.4f}\n"
                f"相关性：{vitality_report.relevance:.4f}\n"
                f"存活状态：{alive_status}\n"
                f"年龄：{vitality_report.age_hours:.1f}小时\n"
                f"代际：{vitality_report.generation}\n"
                f"当前状态摘要：{state_summary}\n\n"
                "请给出一个简短的行动建议(20字以内)，例如：'紧急更新情报源'、'归档并保留基因'、'继续监控'等。\n"
                f"请仅回答JSON格式：{json_format_action}"
            )
            result = await llm_service.generate_json(
                prompt=prompt,
                system_prompt="你是黑灰产威胁情报分析专家，仅输出JSON格式。",
                temperature=settings.LLM_TEMPERATURE_CREATIVE,
            )
            if isinstance(result, dict) and "action" in result:
                return result["action"]
        except Exception as exc:
            logger.debug(f"LLM action recommendation failed: {exc}")
        return None

    async def llm_validate_prediction(
        self, llm_service, predicted_action: str, evidence: List[str], entity_context: str = ""
    ) -> Optional[bool]:
        if llm_service is None:
            return None
        try:
            evidence_text = "\n".join(f"- {e[:200]}" for e in evidence[:5])
            json_format_validate = '{"occurred": true/false, "confidence": 0.0-1.0, "reason": "简短原因"}'
            prompt = (
                "你是黑灰产威胁情报分析专家。请判断以下预测是否已经在证据中得到验证。\n\n"
                f"预测行为：{predicted_action}\n"
                f"实体上下文：{entity_context[:300]}\n"
                f"相关证据：\n{evidence_text}\n\n"
                f"请仅回答JSON格式：{json_format_validate}"
            )
            result = await llm_service.generate_json(
                prompt=prompt,
                system_prompt="你是黑灰产威胁情报分析专家，仅输出JSON格式。",
                temperature=settings.LLM_TEMPERATURE_DEFAULT,
            )
            if isinstance(result, dict) and "occurred" in result:
                return result["occurred"]
        except Exception as exc:
            logger.debug(f"LLM prediction validation failed: {exc}")
        return None


class IntelligenceOrganismEngine(LLMEnhancedEvolution):
    PERSIST_DIR = "./organism_data"
    PERSIST_FILE = "organism_state.json"
    AUTO_SAVE_INTERVAL_SECONDS = 60

    def __init__(
        self,
        vector_store: VectorStore,
        knowledge_graph: KnowledgeGraph,
        persist_dir: str = None,
        llm_service=None,
    ):
        self.vector_store = vector_store
        self.knowledge_graph = knowledge_graph
        self.persist_dir = persist_dir or self.PERSIST_DIR
        self.llm_service = llm_service
        self.organisms: Dict[str, IntelligenceOrganism] = {}
        self.prediction_trackers: Dict[str, PredictionTracker] = {}
        self.genes: Dict[str, IntelligenceGene] = {}
        self._persist_lock = asyncio.Lock()
        self._adaptive_half_life = AdaptiveHalfLifeCalculator()
        self._semantic_detector = SemanticChangeDetector(vector_store)
        self._load_from_disk()

    def _load_from_disk(self):
        persist_path = Path(self.persist_dir) / self.PERSIST_FILE
        if not persist_path.exists():
            logger.info("No persisted organism data found, starting fresh")
            return
        try:
            with open(persist_path, "r", encoding="utf-8") as f:
                raw = json.load(f)

            for oid, odata in raw.get("organisms", {}).items():
                odata["evolution_log"] = [EvolutionEvent(**ev) for ev in odata.get("evolution_log", [])]
                self.organisms[oid] = IntelligenceOrganism(**odata)

            for pid, pdata in raw.get("prediction_trackers", {}).items():
                pdata["validations"] = [ValidationResult(**v) for v in pdata.get("validations", [])]
                self.prediction_trackers[pid] = PredictionTracker(**pdata)

            for gid, gdata in raw.get("genes", {}).items():
                self.genes[gid] = IntelligenceGene(**gdata)

            adaptive_data = raw.get("adaptive_half_life", {})
            if adaptive_data:
                self._adaptive_half_life.from_persist_dict(adaptive_data)

            logger.info(
                f"Loaded organism data from disk: {len(self.organisms)} organisms, "
                f"{len(self.prediction_trackers)} trackers, {len(self.genes)} genes"
            )
        except Exception as exc:
            logger.warning(f"Failed to load organism data from disk: {exc}, starting fresh")

    async def save_to_disk(self):
        async with self._persist_lock:
            persist_dir = Path(self.persist_dir)
            persist_dir.mkdir(parents=True, exist_ok=True)
            persist_path = persist_dir / self.PERSIST_FILE

            try:
                data = {
                    "organisms": {oid: o.to_dict() for oid, o in self.organisms.items()},
                    "prediction_trackers": {pid: p.to_dict() for pid, p in self.prediction_trackers.items()},
                    "genes": {gid: g.to_dict() for gid, g in self.genes.items()},
                    "adaptive_half_life": self._adaptive_half_life.to_persist_dict(),
                    "saved_at": datetime.now(timezone.utc).isoformat(),
                }
                tmp_path = persist_path.with_suffix(".tmp")
                with open(tmp_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, ensure_ascii=False, default=str)
                tmp_path.replace(persist_path)
                logger.debug(f"Organism data saved to disk ({len(self.organisms)} organisms, {len(self.genes)} genes)")
            except Exception as exc:
                logger.error(f"Failed to save organism data to disk: {exc}")

    async def spawn_organism(
        self, intelligence_id: str, species: str, initial_data: Dict, skip_save: bool = False
    ) -> IntelligenceOrganism:
        now = datetime.now(timezone.utc)
        born_at = now.isoformat()
        base_half_life = SPECIES_HALF_LIFE_HOURS.get(species, DEFAULT_HALF_LIFE)
        half_life = base_half_life
        next_check = (now + timedelta(hours=max(half_life * 0.1, 1))).isoformat()

        gene_matches = await self.find_gene_matches(initial_data)
        inherited_vitality = None
        inherited_generation = 1
        parent_ids: List[str] = []
        inherited_patterns: List[str] = []
        inherited_associations: List[str] = []

        if gene_matches:
            best_gene = gene_matches[0]
            inherited_props = await self.inherit_genes(intelligence_id, [best_gene.gene_id])
            inherited_vitality = inherited_props.get("initial_vitality")
            inherited_generation = inherited_props.get("generation", 1)
            parent_ids = inherited_props.get("parent_ids", [])
            inherited_patterns = inherited_props.get("patterns", [])
            inherited_associations = inherited_props.get("associations", [])

        if inherited_vitality is not None:
            initial_vitality = inherited_vitality
        else:
            llm_vitality = await self.llm_infer_initial_vitality(
                self.llm_service, species, initial_data
            )
            if llm_vitality is not None:
                initial_vitality = llm_vitality
            else:
                vitality_range = SPECIES_INITIAL_VITALITY_RANGE.get(species, DEFAULT_INITIAL_VITALITY_RANGE)
                initial_vitality = random.uniform(vitality_range[0], vitality_range[1])

        organism = IntelligenceOrganism(
            intelligence_id=intelligence_id,
            species=species,
            born_at=born_at,
            current_age_hours=0.0,
            generation=inherited_generation,
            vitality=initial_vitality,
            evolution_log=[],
            mutations=[],
            offspring=[],
            parent_ids=parent_ids,
            current_state=initial_data,
            half_life=half_life,
            is_alive=True,
            next_check_at=next_check,
            mention_count=1,
            confirmed_use_count=0,
            total_use_count=0,
        )

        born_event = EvolutionEvent(
            timestamp=born_at,
            event_type="born",
            description=f"Organism spawned as species '{species}'"
            + (f" with inherited genes from {len(gene_matches)} ancestor(s)" if gene_matches else ""),
            trigger="spawn",
            before_state={},
            after_state=initial_data,
            related_intelligence_ids=parent_ids,
        )
        organism.evolution_log.append(born_event)

        if inherited_patterns:
            organism.current_state["inherited_patterns"] = inherited_patterns
        if inherited_associations:
            organism.current_state["inherited_associations"] = inherited_associations

        self.organisms[intelligence_id] = organism
        self._adaptive_half_life.update_activity(intelligence_id, 1, 1.0)
        logger.info(
            f"Spawned organism {intelligence_id} (species={species}, "
            f"generation={organism.generation}, vitality={organism.vitality:.2f})"
        )
        if not skip_save:
            await self.save_to_disk()
        return organism

    async def simulate_time_passage(self, hours: float):
        now = datetime.now(timezone.utc)
        for organism in self.organisms.values():
            age_hours = (now - datetime.fromisoformat(organism.born_at)).total_seconds() / 3600 if organism.born_at else 0
            organism.current_age_hours = age_hours + hours

            real_mentions = await self._count_real_mentions(organism, hours)
            if real_mentions is not None:
                organism.mention_count = real_mentions
                organism.total_use_count = max(1, int(real_mentions * 0.6))
                organism.confirmed_use_count = max(0, int(organism.total_use_count * 0.5))
            else:
                expected = EXPECTED_MENTIONS_PER_HOUR.get(organism.species, 0.01) * hours
                organism.mention_count = max(0, int(expected))
                organism.total_use_count = max(0, int(expected * 0.6))
                organism.confirmed_use_count = max(0, int(organism.total_use_count * 0.5))

            self._adaptive_half_life.update_activity(
                organism.intelligence_id, organism.mention_count, hours
            )
            adaptive_half_life = self._adaptive_half_life.compute_adaptive_half_life(
                organism.intelligence_id, organism.species, organism.half_life
            )

            freshness = 0.5 ** (organism.current_age_hours / adaptive_half_life) if adaptive_half_life > 0 else 0.0
            expected_mentions = EXPECTED_MENTIONS_PER_HOUR.get(organism.species, 0.01) * hours
            activity = min(organism.mention_count / max(expected_mentions, 1), 1.0) if expected_mentions > 0 else 0.1
            relevance = await self._compute_real_relevance(organism)
            organism.vitality = freshness * activity * relevance
            organism.is_alive = organism.vitality >= DEATH_THRESHOLD

            next_check_delta = max(adaptive_half_life * 0.1, 1)
            organism.next_check_at = (now + timedelta(hours=next_check_delta)).isoformat()

        logger.info(f"Simulated {hours:.1f} hours of time passage for all organisms")
        await self.save_to_disk()

    async def _count_real_mentions(self, organism: IntelligenceOrganism, hours: float) -> Optional[int]:
        try:
            if hasattr(self, 'vector_store') and self.vector_store:
                cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
                results = await self.vector_store.search_intelligence(
                    organism.intelligence_id, n_results=100
                )
                return len(results) if results else 0
        except Exception:
            pass
        return None

    async def _compute_real_relevance(self, organism: IntelligenceOrganism) -> float:
        if organism.total_use_count > 0:
            return min(organism.confirmed_use_count / organism.total_use_count, 1.0)
        try:
            if hasattr(self, 'vector_store') and self.vector_store:
                results = await self.vector_store.search_intelligence(
                    organism.intelligence_id, n_results=5
                )
                return min(1.0, len(results) * 0.2) if results else 0.1
        except Exception:
            pass
        return 0.1

    async def evolve(
        self, organism_id: str, new_data: Dict, trigger: str = "auto_monitor", skip_save: bool = False
    ) -> IntelligenceOrganism:
        organism = self.organisms.get(organism_id)
        if not organism:
            logger.warning(f"Organism {organism_id} not found for evolution")
            return None

        now = datetime.now(timezone.utc)
        before_state = organism.current_state.copy()

        has_significant_change = await self._detect_significant_change_enhanced(before_state, new_data)

        if has_significant_change:
            mutation = {
                "timestamp": now.isoformat(),
                "changed_fields": list(
                    set(new_data.keys()) - set(before_state.keys())
                    | {
                        k
                        for k in new_data
                        if k in before_state
                        and self._field_change_magnitude(before_state.get(k), new_data.get(k))
                        > SIGNIFICANT_CHANGE_THRESHOLD
                    }
                ),
                "trigger": trigger,
            }
            organism.mutations.append(mutation)

            event = EvolutionEvent(
                timestamp=now.isoformat(),
                event_type="mutated",
                description=f"Significant changes detected via {trigger}",
                trigger=trigger,
                before_state=before_state,
                after_state=new_data,
                related_intelligence_ids=[],
            )
            organism.evolution_log.append(event)

        organism.current_state.update(new_data)
        organism.mention_count += 1

        if "confirmed" in new_data and new_data.get("confirmed"):
            organism.confirmed_use_count += 1
        organism.total_use_count += 1

        born_at = datetime.fromisoformat(organism.born_at)
        age_hours = max((now - born_at).total_seconds() / 3600, 0)
        organism.current_age_hours = age_hours

        self._adaptive_half_life.update_activity(organism_id, 1, max(age_hours, 0.1))

        vitality_report = await self.check_vitality(organism_id)
        organism.vitality = vitality_report.vitality
        organism.is_alive = vitality_report.is_alive

        adaptive_half_life = self._adaptive_half_life.compute_adaptive_half_life(
            organism_id, organism.species, organism.half_life
        )
        next_check_delta = max(adaptive_half_life * 0.1, 1)
        organism.next_check_at = (now + timedelta(hours=next_check_delta)).isoformat()

        logger.info(
            f"Evolved organism {organism_id}: vitality={organism.vitality:.3f}, "
            f"mutated={has_significant_change}, trigger={trigger}"
        )
        if not skip_save:
            await self.save_to_disk()
        return organism

    async def _detect_significant_change_enhanced(self, before: Dict, after: Dict) -> bool:
        llm_result = await self.llm_analyze_significance(self.llm_service, before, after)
        if llm_result is not None:
            return llm_result
        semantic_result = await self._semantic_detector.detect_significant_change(before, after)
        if semantic_result:
            return True
        return self._detect_significant_change(before, after)

    async def check_vitality(self, organism_id: str) -> VitalityReport:
        organism = self.organisms.get(organism_id)
        if not organism:
            return VitalityReport(
                organism_id=organism_id,
                vitality=0.0,
                freshness=0.0,
                activity=0.0,
                relevance=0.0,
                is_alive=False,
                age_hours=0.0,
                half_life_hours=0.0,
                recommended_action="organism_not_found",
                generation=0,
            )

        now = datetime.now(timezone.utc)
        born_at = datetime.fromisoformat(organism.born_at)
        age_hours = max((now - born_at).total_seconds() / 3600, 0)
        organism.current_age_hours = age_hours

        adaptive_half_life = self._adaptive_half_life.compute_adaptive_half_life(
            organism_id, organism.species, organism.half_life
        )

        freshness = 0.5 ** (age_hours / adaptive_half_life) if adaptive_half_life > 0 else 0.0

        if age_hours < 1.0:
            activity = 1.0
        else:
            expected_mentions = EXPECTED_MENTIONS_PER_HOUR.get(organism.species, 0.01) * age_hours
            activity = min(organism.mention_count / max(expected_mentions, 1), 1.0) if expected_mentions > 0 else 0.5

        relevance = 0.5
        if organism.total_use_count > 0:
            relevance = min(organism.confirmed_use_count / organism.total_use_count, 1.0)

        vitality = freshness * activity * relevance

        was_alive = organism.is_alive
        is_alive = vitality >= DEATH_THRESHOLD

        if was_alive and not is_alive:
            event = EvolutionEvent(
                timestamp=now.isoformat(),
                event_type="died",
                description=f"Vitality dropped below threshold ({vitality:.4f} < {DEATH_THRESHOLD})",
                trigger="vitality_check",
                before_state={"vitality": organism.vitality, "is_alive": True},
                after_state={"vitality": vitality, "is_alive": False},
                related_intelligence_ids=[],
            )
            organism.evolution_log.append(event)
            organism.is_alive = False
            logger.info(f"Organism {organism_id} has died (vitality={vitality:.4f})")

        elif not was_alive and is_alive:
            organism.generation += 1
            event = EvolutionEvent(
                timestamp=now.isoformat(),
                event_type="reborn",
                description=f"Organism reborn as generation {organism.generation} (vitality={vitality:.4f})",
                trigger="vitality_check",
                before_state={"vitality": organism.vitality, "is_alive": False, "generation": organism.generation - 1},
                after_state={"vitality": vitality, "is_alive": True, "generation": organism.generation},
                related_intelligence_ids=[],
            )
            organism.evolution_log.append(event)
            organism.is_alive = True
            logger.info(f"Organism {organism_id} reborn as generation {organism.generation}")

        organism.vitality = vitality

        recommended_action = await self._determine_recommended_action_enhanced(
            organism, vitality, is_alive, organism.species
        )

        return VitalityReport(
            organism_id=organism_id,
            vitality=round(vitality, 6),
            freshness=round(freshness, 6),
            activity=round(activity, 6),
            relevance=round(relevance, 6),
            is_alive=is_alive,
            age_hours=round(age_hours, 2),
            half_life_hours=adaptive_half_life,
            recommended_action=recommended_action,
            generation=organism.generation,
        )

    async def _determine_recommended_action_enhanced(
        self, organism, vitality: float, is_alive: bool, species: str
    ) -> str:
        base_action = self._determine_recommended_action(vitality, is_alive, species)
        if self.llm_service is None:
            return base_action
        temp_report = VitalityReport(
            organism_id=organism.intelligence_id,
            vitality=vitality,
            freshness=0.0,
            activity=0.0,
            relevance=0.0,
            is_alive=is_alive,
            age_hours=organism.current_age_hours,
            half_life_hours=organism.half_life,
            recommended_action=base_action,
            generation=organism.generation,
        )
        llm_action = await self.llm_recommend_action(self.llm_service, organism, temp_report)
        return llm_action if llm_action else base_action

    async def get_evolution_timeline(self, organism_id: str) -> List[EvolutionEvent]:
        organism = self.organisms.get(organism_id)
        if not organism:
            return []
        return organism.evolution_log

    async def find_offspring(self, organism_id: str, depth: int = 3) -> OrganismTree:
        nodes: List[Dict] = []
        edges: List[Dict] = []

        root = self.organisms.get(organism_id)
        if not root:
            return OrganismTree(root_id=organism_id, nodes=nodes, edges=edges)

        nodes.append({
            "id": root.intelligence_id,
            "generation": root.generation,
            "vitality": root.vitality,
            "species": root.species,
        })

        visited = {organism_id}
        queue = deque([(organism_id, 0)])

        while queue:
            current_id, current_depth = queue.popleft()
            if current_depth >= depth:
                continue

            current = self.organisms.get(current_id)
            if not current:
                continue

            for child_id in current.offspring:
                if child_id in visited:
                    continue
                visited.add(child_id)

                child = self.organisms.get(child_id)
                if child:
                    nodes.append({
                        "id": child.intelligence_id,
                        "generation": child.generation,
                        "vitality": child.vitality,
                        "species": child.species,
                    })
                    edges.append({
                        "from": current_id,
                        "to": child_id,
                        "relationship": "spawned",
                    })
                    queue.append((child_id, current_depth + 1))

        for oid, organism in self.organisms.items():
            if oid in visited:
                continue
            if organism_id in organism.parent_ids:
                visited.add(oid)
                nodes.append({
                    "id": organism.intelligence_id,
                    "generation": organism.generation,
                    "vitality": organism.vitality,
                    "species": organism.species,
                })
                edges.append({
                    "from": organism_id,
                    "to": oid,
                    "relationship": "spawned",
                })
                queue.append((oid, 1))

        return OrganismTree(root_id=organism_id, nodes=nodes, edges=edges)

    async def register_prediction(
        self,
        entity_id: str,
        predicted_steps: List[Dict],
        validation_window_hours: float = 168,
    ) -> PredictionTracker:
        now = datetime.now(timezone.utc)
        prediction_id = uuid4().hex
        deadline = now + timedelta(hours=validation_window_hours)

        tracker = PredictionTracker(
            prediction_id=prediction_id,
            entity_id=entity_id,
            predicted_steps=predicted_steps,
            made_at=now.isoformat(),
            validation_window=f"{validation_window_hours}h",
            validation_deadline=deadline.isoformat(),
            validations=[],
            accuracy_score=0.0,
            model_calibration={},
        )

        self.prediction_trackers[prediction_id] = tracker
        logger.info(
            f"Registered prediction {prediction_id} for entity {entity_id} "
            f"with {len(predicted_steps)} steps, window={validation_window_hours}h"
        )
        return tracker

    async def validate_predictions(self) -> List[ValidationResult]:
        now = datetime.now(timezone.utc)
        results: List[ValidationResult] = []

        for tracker_id, tracker in list(self.prediction_trackers.items()):
            deadline = datetime.fromisoformat(tracker.validation_deadline)
            if now < deadline and not self._has_new_evidence(tracker):
                continue

            entity_context = await self._get_entity_context_for_validation(tracker.entity_id)

            for step_index, step in enumerate(tracker.predicted_steps):
                already_validated = any(
                    v.step_index == step_index for v in tracker.validations
                )
                if already_validated:
                    continue

                predicted_action = step.get("action", "")
                predicted_probability = step.get("probability", 0.5)

                evidence: List[str] = []
                actual_occurred = False
                time_to_occurrence: Optional[float] = None

                try:
                    evidence, actual_occurred, time_to_occurrence = await self._search_evidence(
                        predicted_action, tracker.entity_id, tracker.made_at
                    )
                except Exception as exc:
                    logger.warning(f"Evidence search failed for prediction {tracker_id}: {exc}")
                    try:
                        evidence, actual_occurred, time_to_occurrence = (
                            await self._heuristic_evidence_search(predicted_action, tracker.entity_id)
                        )
                    except Exception as exc2:
                        logger.warning(f"Heuristic evidence search also failed: {exc2}")

                if evidence and self.llm_service is not None:
                    llm_occurred = await self.llm_validate_prediction(
                        self.llm_service, predicted_action, evidence, entity_context
                    )
                    if llm_occurred is not None:
                        actual_occurred = llm_occurred

                if evidence and not actual_occurred and self.llm_service is None:
                    kg_occurred = await self._validate_via_knowledge_graph(
                        predicted_action, tracker.entity_id, tracker.made_at
                    )
                    if kg_occurred is not None:
                        actual_occurred = kg_occurred

                validation = ValidationResult(
                    step_index=step_index,
                    predicted_action=predicted_action,
                    predicted_probability=predicted_probability,
                    actual_occurred=actual_occurred,
                    evidence=evidence,
                    validated_at=now.isoformat(),
                    time_to_occurrence=time_to_occurrence,
                )

                tracker.validations.append(validation)
                results.append(validation)

            if tracker.validations:
                correct = sum(1 for v in tracker.validations if v.actual_occurred)
                tracker.accuracy_score = correct / len(tracker.validations)
                tracker.model_calibration = self._update_calibration(tracker)

        logger.info(f"Validated {len(results)} prediction steps")
        return results

    async def _get_entity_context_for_validation(self, entity_id: str) -> str:
        organism = self.organisms.get(entity_id)
        if organism:
            return json.dumps(organism.current_state, ensure_ascii=False, default=str)[:300]
        try:
            entity = await self.knowledge_graph.get_entity(entity_id)
            if entity:
                return str(entity.context)[:300] if hasattr(entity, 'context') and entity.context else ""
        except Exception:
            pass
        return ""

    async def _validate_via_knowledge_graph(
        self, predicted_action: str, entity_id: str, prediction_made_at: str
    ) -> Optional[bool]:
        try:
            entity = await self.knowledge_graph.get_entity(entity_id)
            if not entity:
                return None
            if hasattr(entity, 'last_seen') and entity.last_seen:
                try:
                    made_time = datetime.fromisoformat(prediction_made_at)
                    if entity.last_seen > made_time:
                        return True
                except (ValueError, TypeError):
                    pass
            if hasattr(entity, 'relations'):
                for rel in entity.relations:
                    rel_type = str(rel.get("type", "") if isinstance(rel, dict) else rel).lower()
                    action_terms = self._extract_key_terms(predicted_action)
                    for term in action_terms:
                        if term in rel_type:
                            return True
        except Exception as exc:
            logger.debug(f"Knowledge graph validation failed: {exc}")
        return None

    async def get_prediction_accuracy(self, entity_id: str = None) -> AccuracyReport:
        trackers = list(self.prediction_trackers.values())

        if entity_id:
            trackers = [t for t in trackers if t.entity_id == entity_id]

        total_predictions = 0
        correct_predictions = 0
        calibration_buckets: Dict[str, Dict] = {}

        for tracker in trackers:
            for validation in tracker.validations:
                total_predictions += 1
                if validation.actual_occurred:
                    correct_predictions += 1

                bucket = self._probability_bucket(validation.predicted_probability)
                if bucket not in calibration_buckets:
                    calibration_buckets[bucket] = {"total": 0, "occurred": 0}
                calibration_buckets[bucket]["total"] += 1
                if validation.actual_occurred:
                    calibration_buckets[bucket]["occurred"] += 1

        calibration_data = {}
        for bucket, data in sorted(calibration_buckets.items()):
            rate = data["occurred"] / data["total"] if data["total"] > 0 else 0.0
            calibration_data[bucket] = {
                "predicted_range": bucket,
                "actual_rate": round(rate, 4),
                "sample_size": data["total"],
            }

        accuracy = correct_predictions / total_predictions if total_predictions > 0 else 0.0

        brier_score = self._compute_brier_score(trackers)

        return AccuracyReport(
            total_predictions=total_predictions,
            correct_predictions=correct_predictions,
            accuracy=round(accuracy, 6),
            calibration_data=calibration_data,
            brier_score=round(brier_score, 6),
        )

    async def calibrate_model(self) -> CalibrationResult:
        trackers = list(self.prediction_trackers.values())
        all_validations = []
        for tracker in trackers:
            all_validations.extend(tracker.validations)

        if not all_validations:
            return CalibrationResult(
                bias_direction="unknown",
                calibration_factors={},
                sample_size=0,
            )

        occurred_probabilities = []
        not_occurred_probabilities = []
        for v in all_validations:
            if v.actual_occurred:
                occurred_probabilities.append(v.predicted_probability)
            else:
                not_occurred_probabilities.append(v.predicted_probability)

        avg_occurred = (
            sum(occurred_probabilities) / len(occurred_probabilities)
            if occurred_probabilities
            else 0.0
        )
        avg_not_occurred = (
            sum(not_occurred_probabilities) / len(not_occurred_probabilities)
            if not_occurred_probabilities
            else 0.0
        )

        actual_rate = len(occurred_probabilities) / len(all_validations)
        avg_predicted = sum(v.predicted_probability for v in all_validations) / len(all_validations)

        if avg_predicted > actual_rate + 0.1:
            bias_direction = "over_confident"
        elif avg_predicted < actual_rate - 0.1:
            bias_direction = "under_confident"
        else:
            bias_direction = "well_calibrated"

        calibration_factors = {}
        buckets: Dict[str, List[ValidationResult]] = {}
        for v in all_validations:
            bucket = self._probability_bucket(v.predicted_probability)
            if bucket not in buckets:
                buckets[bucket] = []
            buckets[bucket].append(v)

        for bucket, validations in buckets.items():
            occurred = sum(1 for v in validations if v.actual_occurred)
            actual_rate_bucket = occurred / len(validations) if validations else 0.0
            avg_predicted_bucket = sum(v.predicted_probability for v in validations) / len(validations)
            if avg_predicted_bucket > 0:
                calibration_factors[bucket] = round(actual_rate_bucket / avg_predicted_bucket, 4)
            else:
                calibration_factors[bucket] = 1.0

        return CalibrationResult(
            bias_direction=bias_direction,
            calibration_factors=calibration_factors,
            sample_size=len(all_validations),
        )

    async def archive_organism(
        self, organism_id: str, cause: str = "expired", skip_save: bool = False
    ) -> IntelligenceGene:
        organism = self.organisms.get(organism_id)
        if not organism:
            raise ValueError(f"Organism {organism_id} not found")

        now = datetime.now(timezone.utc)
        patterns = self._extract_patterns(organism)
        associations = self._extract_associations(organism)
        attack_chains = self._extract_attack_chains(organism)
        confidence_history = [
            e.after_state.get("vitality", 0.0)
            for e in organism.evolution_log
            if "vitality" in e.after_state
        ]
        if not confidence_history:
            confidence_history = [organism.vitality]

        gene = IntelligenceGene(
            gene_id=uuid4().hex,
            species=organism.species,
            patterns=patterns,
            associations=associations,
            attack_chains=attack_chains,
            confidence_history=confidence_history,
            total_lifetime_hours=organism.current_age_hours,
            cause_of_death=cause,
            preserved_at=now.isoformat(),
        )

        organism.is_alive = False

        event = EvolutionEvent(
            timestamp=now.isoformat(),
            event_type="died",
            description=f"Organism archived (cause: {cause}), gene {gene.gene_id} preserved",
            trigger="archive",
            before_state={"is_alive": True, "vitality": organism.vitality},
            after_state={"is_alive": False, "gene_id": gene.gene_id},
            related_intelligence_ids=[],
        )
        organism.evolution_log.append(event)

        self.genes[gene.gene_id] = gene
        self._adaptive_half_life.remove_organism(organism_id)
        logger.info(
            f"Archived organism {organism_id}, preserved gene {gene.gene_id} "
            f"({len(patterns)} patterns, {len(associations)} associations)"
        )
        if not skip_save:
            await self.save_to_disk()
        return gene

    async def inherit_genes(self, new_organism_id: str, parent_genes: List[str]) -> Dict:
        inherited_patterns: List[str] = []
        inherited_associations: List[str] = []
        inherited_attack_chains: List[str] = []
        max_generation = 0
        parent_ids: List[str] = []

        for gene_id in parent_genes:
            gene = self.genes.get(gene_id)
            if not gene:
                continue

            inherited_patterns.extend(gene.patterns)
            inherited_associations.extend(gene.associations)
            inherited_attack_chains.extend(gene.attack_chains)

            for oid, organism in self.organisms.items():
                for ev in organism.evolution_log:
                    if ev.event_type == "died" and gene_id in ev.after_state.get("gene_id", ""):
                        if organism.generation > max_generation:
                            max_generation = organism.generation
                        parent_ids.append(oid)

        inherited_patterns = list(dict.fromkeys(inherited_patterns))
        inherited_associations = list(dict.fromkeys(inherited_associations))
        inherited_attack_chains = list(dict.fromkeys(inherited_attack_chains))

        gene_count = len(parent_genes)
        initial_vitality = min(1.0 + GENE_INHERITANCE_VITALITY_BOOST * gene_count, 1.0)
        generation = max_generation + 1

        return {
            "initial_vitality": initial_vitality,
            "generation": generation,
            "parent_ids": parent_ids,
            "patterns": inherited_patterns,
            "associations": inherited_associations,
            "attack_chains": inherited_attack_chains,
        }

    async def find_gene_matches(self, new_intelligence_data: Dict) -> List[IntelligenceGene]:
        if not self.genes:
            return []

        scored_genes: List[tuple] = []

        for gene_id, gene in self.genes.items():
            score = self._compute_gene_relevance(gene, new_intelligence_data)
            if score > 0:
                scored_genes.append((score, gene))

        scored_genes.sort(key=lambda x: x[0], reverse=True)
        return [gene for _, gene in scored_genes[:10]]

    async def get_genealogy(self, organism_id: str) -> GenealogyTree:
        organism = self.organisms.get(organism_id)
        if not organism:
            return GenealogyTree(
                organism_id=organism_id,
                current_generation=0,
                ancestors=[],
                total_ancestors=0,
                inherited_patterns=[],
                inherited_associations=[],
            )

        ancestors: List[Dict] = []
        inherited_patterns: List[str] = []
        inherited_associations: List[str] = []
        visited = {organism_id}
        queue = deque(organism.parent_ids)

        while queue:
            parent_id = queue.popleft()
            if parent_id in visited:
                continue
            visited.add(parent_id)

            parent = self.organisms.get(parent_id)
            if parent:
                died_at = ""
                for ev in reversed(parent.evolution_log):
                    if ev.event_type == "died":
                        died_at = ev.timestamp
                        break

                key_pattern = ""
                if parent.mutations:
                    key_pattern = str(parent.mutations[-1].get("changed_fields", ""))

                ancestors.append({
                    "id": parent.intelligence_id,
                    "generation": parent.generation,
                    "species": parent.species,
                    "key_pattern": key_pattern,
                    "died_at": died_at,
                })

                for pid in parent.parent_ids:
                    if pid not in visited:
                        queue.append(pid)

        for gene_id, gene in self.genes.items():
            for ancestor in ancestors:
                aid = ancestor["id"]
                a_organism = self.organisms.get(aid)
                if a_organism:
                    for ev in a_organism.evolution_log:
                        if ev.event_type == "died" and gene_id in str(ev.after_state.get("gene_id", "")):
                            inherited_patterns.extend(gene.patterns)
                            inherited_associations.extend(gene.associations)

        inherited_patterns = list(dict.fromkeys(inherited_patterns))
        inherited_associations = list(dict.fromkeys(inherited_associations))

        return GenealogyTree(
            organism_id=organism_id,
            current_generation=organism.generation,
            ancestors=ancestors,
            total_ancestors=len(ancestors),
            inherited_patterns=inherited_patterns,
            inherited_associations=inherited_associations,
        )

    async def run_lifecycle_check(self) -> Dict:
        results = {
            "checked": 0,
            "mutated": 0,
            "died": 0,
            "reborn": 0,
            "predictions_validated": 0,
        }

        now = datetime.now(timezone.utc)
        organisms_to_archive: List[str] = []

        for organism_id, organism in list(self.organisms.items()):
            if not organism.is_alive:
                continue

            results["checked"] += 1

            born_at = datetime.fromisoformat(organism.born_at)
            if born_at.tzinfo is None:
                born_at = born_at.replace(tzinfo=timezone.utc)
            age_hours = max((now - born_at).total_seconds() / 3600, 0)
            organism.current_age_hours = age_hours

            try:
                new_data = await self._fetch_organism_updates(organism)
                if new_data:
                    evolved = await self.evolve(organism_id, new_data, trigger="auto_monitor")
                    if evolved and evolved.mutations:
                        results["mutated"] += 1
            except Exception as exc:
                logger.warning(f"Failed to fetch updates for organism {organism_id}: {exc}")

            try:
                vitality_report = await self.check_vitality(organism_id)
                if not vitality_report.is_alive:
                    results["died"] += 1
                    organisms_to_archive.append(organism_id)
                elif vitality_report.vitality > organism.vitality + DEATH_THRESHOLD:
                    results["reborn"] += 1
            except Exception as exc:
                logger.warning(f"Vitality check failed for organism {organism_id}: {exc}")

            adaptive_half_life = self._adaptive_half_life.compute_adaptive_half_life(
                organism_id, organism.species, organism.half_life
            )
            next_check_delta = max(adaptive_half_life * 0.1, 1)
            organism.next_check_at = (now + timedelta(hours=next_check_delta)).isoformat()

        for organism_id in organisms_to_archive:
            try:
                await self.archive_organism(organism_id, cause="expired")
            except Exception as exc:
                logger.warning(f"Failed to archive organism {organism_id}: {exc}")

        try:
            validations = await self.validate_predictions()
            results["predictions_validated"] = len(validations)
        except Exception as exc:
            logger.warning(f"Prediction validation failed: {exc}")

        for organism_id, organism in list(self.organisms.items()):
            if organism.is_alive:
                continue

            try:
                reborn = await self._check_for_rebirth(organism_id)
                if reborn:
                    results["reborn"] += 1
            except Exception as exc:
                logger.warning(f"Rebirth check failed for organism {organism_id}: {exc}")

        logger.info(f"Lifecycle check complete: {results}")
        await self.save_to_disk()
        return results

    def _detect_significant_change(self, before: Dict, after: Dict) -> bool:
        for key in after:
            if key not in before:
                return True
            if self._field_change_magnitude(before.get(key), after.get(key)) > SIGNIFICANT_CHANGE_THRESHOLD:
                return True
        return False

    def _field_change_magnitude(self, old_val, new_val) -> float:
        if old_val is None or new_val is None:
            return 1.0 if (old_val is None) != (new_val is None) else 0.0

        if isinstance(old_val, (int, float)) and isinstance(new_val, (int, float)):
            if old_val == 0 and new_val == 0:
                return 0.0
            denominator = max(abs(old_val), abs(new_val), 1e-10)
            return abs(new_val - old_val) / denominator

        if isinstance(old_val, str) and isinstance(new_val, str):
            if old_val == new_val:
                return 0.0
            old_words = set(old_val.lower().split())
            new_words = set(new_val.lower().split())
            if not old_words and not new_words:
                return 0.0
            union = old_words | new_words
            intersection = old_words & new_words
            return 1.0 - (len(intersection) / len(union)) if union else 0.0

        if isinstance(old_val, list) and isinstance(new_val, list):
            old_set = set(str(x) for x in old_val)
            new_set = set(str(x) for x in new_val)
            if not old_set and not new_set:
                return 0.0
            union = old_set | new_set
            intersection = old_set & new_set
            return 1.0 - (len(intersection) / len(union)) if union else 0.0

        return 0.0 if old_val == new_val else 1.0

    def _determine_recommended_action(
        self, vitality: float, is_alive: bool, species: str
    ) -> str:
        if not is_alive:
            return "archive_and_preserve_genes"
        if vitality < 0.2:
            return "urgent_refresh_needed"
        if vitality < 0.5:
            return "schedule_refresh"
        if vitality < 0.8:
            return "monitor_normally"
        return "no_action_needed"

    async def _fetch_organism_updates(self, organism: IntelligenceOrganism) -> Dict:
        updates: Dict = {}

        try:
            entity = await self.knowledge_graph.get_entity(organism.intelligence_id)
            if entity:
                updates["confidence"] = entity.confidence
                updates["last_seen"] = entity.last_seen.isoformat() if entity.last_seen else ""
                if entity.context:
                    updates["context"] = entity.context
        except Exception as exc:
            logger.debug(f"Knowledge graph lookup failed for {organism.intelligence_id}: {exc}")

        try:
            results = await self.vector_store.search_intelligence(
                organism.intelligence_id, n_results=3
            )
            if results:
                updates["recent_intelligence_count"] = len(results)
                updates["latest_intelligence"] = results[0].get("document", "")[:200]
        except Exception as exc:
            logger.debug(f"Vector store search failed for {organism.intelligence_id}: {exc}")

        return updates

    async def _check_for_rebirth(self, organism_id: str) -> bool:
        organism = self.organisms.get(organism_id)
        if not organism or organism.is_alive:
            return False

        try:
            results = await self.vector_store.search_intelligence(
                organism.current_state.get("value", organism_id), n_results=3
            )
            if not results:
                return False

            now = datetime.now(timezone.utc)
            for result in results:
                metadata = result.get("metadata", {})
                collected_at = metadata.get("collected_at", "")
                if not collected_at:
                    continue
                try:
                    collected_time = datetime.fromisoformat(collected_at.replace("Z", "+00:00"))
                    if hasattr(collected_time, 'tzinfo') and collected_time.tzinfo:
                        from datetime import timezone
                        collected_time = collected_time.replace(tzinfo=None)
                except (ValueError, TypeError):
                    continue

                died_at = None
                for ev in reversed(organism.evolution_log):
                    if ev.event_type == "died":
                        died_at = datetime.fromisoformat(ev.timestamp)
                        break

                if died_at and collected_time > died_at:
                    organism.generation += 1
                    organism.is_alive = True
                    organism.vitality = min(
                        DEATH_THRESHOLD + REBORN_VITALITY_BOOST, 1.0
                    )
                    organism.mention_count += 1

                    self._adaptive_half_life.update_activity(
                        organism_id, 1, max(organism.current_age_hours, 0.1)
                    )

                    event = EvolutionEvent(
                        timestamp=now.isoformat(),
                        event_type="reborn",
                        description=f"New intelligence detected, reborn as generation {organism.generation}",
                        trigger="auto_monitor",
                        before_state={"is_alive": False, "vitality": 0.0},
                        after_state={"is_alive": True, "vitality": organism.vitality, "generation": organism.generation},
                        related_intelligence_ids=[result.get("id", "")],
                    )
                    organism.evolution_log.append(event)

                    logger.info(
                        f"Organism {organism_id} reborn as generation {organism.generation}"
                    )
                    return True
        except Exception as exc:
            logger.debug(f"Rebirth check failed for {organism_id}: {exc}")

        return False

    async def _search_evidence(
        self, predicted_action: str, entity_id: str, prediction_made_at: str
    ) -> tuple:
        evidence: List[str] = []
        actual_occurred = False
        time_to_occurrence: Optional[float] = None

        try:
            results = await self.vector_store.search_intelligence(
                predicted_action, n_results=5
            )
            for result in results:
                doc = result.get("document", "")
                metadata = result.get("metadata", {})
                if doc:
                    evidence.append(doc[:300])
                    collected_at = metadata.get("collected_at", "")
                    if collected_at and not actual_occurred:
                        try:
                            collected_time = datetime.fromisoformat(collected_at.replace("Z", "+00:00"))
                            if hasattr(collected_time, 'tzinfo') and collected_time.tzinfo:
                                from datetime import timezone
                                collected_time = collected_time.replace(tzinfo=None)
                            made_time = datetime.fromisoformat(prediction_made_at)
                            if collected_time > made_time:
                                actual_occurred = True
                                delta = collected_time - made_time
                                time_to_occurrence = delta.total_seconds() / 3600
                        except (ValueError, TypeError):
                            pass
        except Exception as exc:
            logger.debug(f"Vector store evidence search failed: {exc}")

        if not actual_occurred and evidence:
            actual_occurred = self._algorithmic_validate_occurrence(predicted_action, evidence)

        return evidence, actual_occurred, time_to_occurrence

    async def _heuristic_evidence_search(
        self, predicted_action: str, entity_id: str
    ) -> tuple:
        evidence: List[str] = []
        actual_occurred = False
        time_to_occurrence: Optional[float] = None

        try:
            results = await self.vector_store.search_intelligence(
                predicted_action, n_results=3
            )
            for result in results:
                doc = result.get("document", "")
                if doc:
                    evidence.append(doc[:300])
        except Exception:
            pass

        if evidence:
            actual_occurred = self._heuristic_occurrence_check(predicted_action, evidence)

        return evidence, actual_occurred, time_to_occurrence

    def _algorithmic_validate_occurrence(
        self, predicted_action: str, evidence: List[str]
    ) -> bool:
        action_terms = self._extract_key_terms(predicted_action)
        if not action_terms:
            return False

        total_score = 0.0
        for doc in evidence:
            doc_terms = self._extract_key_terms(doc)
            if not doc_terms:
                continue

            action_counter = Counter(action_terms)
            doc_counter = Counter(doc_terms)

            all_terms = set(action_counter.keys()) | set(doc_counter.keys())
            dot_product = sum(action_counter[t] * doc_counter[t] for t in all_terms)
            action_norm = math.sqrt(sum(v ** 2 for v in action_counter.values()))
            doc_norm = math.sqrt(sum(v ** 2 for v in doc_counter.values()))

            if action_norm > 0 and doc_norm > 0:
                cosine_sim = dot_product / (action_norm * doc_norm)
                total_score += cosine_sim

        avg_score = total_score / len(evidence) if evidence else 0.0
        return avg_score >= 0.25

    def _extract_key_terms(self, text: str) -> List[str]:
        stop_words = {
            "的", "了", "在", "是", "我", "有", "和", "就", "不", "人", "都", "一", "一个",
            "上", "也", "很", "到", "说", "要", "去", "你", "会", "着", "没有", "看", "好",
            "自己", "这", "the", "a", "an", "is", "are", "was", "were", "be", "been",
            "being", "have", "has", "had", "do", "does", "did", "will", "would",
            "could", "should", "may", "might", "shall", "can", "need", "dare",
            "ought", "used", "to", "of", "in", "for", "on", "with", "at", "by",
            "from", "as", "into", "through", "during", "before", "after", "above",
            "below", "between", "out", "off", "over", "under", "again", "further",
            "then", "once", "and", "but", "or", "nor", "not", "so", "yet", "both",
            "either", "neither", "each", "every", "all", "any", "few", "more",
            "most", "other", "some", "such", "no", "only", "own", "same", "than",
            "too", "very", "just", "because", "if", "when", "where", "how", "what",
            "which", "who", "whom", "this", "that", "these", "those", "it", "its",
        }

        import re
        tokens = re.findall(r'[a-zA-Z_]{2,}|[\u4e00-\u9fff]{2,}', text.lower())
        return [t for t in tokens if t not in stop_words]

    def _heuristic_occurrence_check(
        self, predicted_action: str, evidence: List[str]
    ) -> bool:
        action_words = set(predicted_action.lower().split())
        for doc in evidence:
            doc_words = set(doc.lower().split())
            overlap = action_words & doc_words
            if len(overlap) >= max(len(action_words) * 0.5, 2):
                return True
        return False

    def _has_new_evidence(self, tracker: PredictionTracker) -> bool:
        try:
            entity_id = tracker.entity_id
            organism = self.organisms.get(entity_id)
            if organism and organism.mention_count > 1:
                return True
            for step in tracker.predicted_steps:
                action = step.get("action", "")
                if action:
                    return True
            return False
        except Exception:
            return False

    def _update_calibration(self, tracker: PredictionTracker) -> Dict:
        calibration: Dict[str, Dict] = {}
        for v in tracker.validations:
            bucket = self._probability_bucket(v.predicted_probability)
            if bucket not in calibration:
                calibration[bucket] = {"total": 0, "occurred": 0}
            calibration[bucket]["total"] += 1
            if v.actual_occurred:
                calibration[bucket]["occurred"] += 1

        result = {}
        for bucket, data in calibration.items():
            rate = data["occurred"] / data["total"] if data["total"] > 0 else 0.0
            result[bucket] = {
                "predicted_range": bucket,
                "actual_rate": round(rate, 4),
                "sample_size": data["total"],
            }
        return result

    def _probability_bucket(self, probability: float) -> str:
        if probability < 0.1:
            return "0-10%"
        if probability < 0.2:
            return "10-20%"
        if probability < 0.3:
            return "20-30%"
        if probability < 0.4:
            return "30-40%"
        if probability < 0.5:
            return "40-50%"
        if probability < 0.6:
            return "50-60%"
        if probability < 0.7:
            return "60-70%"
        if probability < 0.8:
            return "70-80%"
        if probability < 0.9:
            return "80-90%"
        return "90-100%"

    def _compute_brier_score(self, trackers: List[PredictionTracker]) -> float:
        total = 0
        sum_squared_error = 0.0

        for tracker in trackers:
            for v in tracker.validations:
                actual = 1.0 if v.actual_occurred else 0.0
                sum_squared_error += (v.predicted_probability - actual) ** 2
                total += 1

        return sum_squared_error / total if total > 0 else 0.0

    def _extract_patterns(self, organism: IntelligenceOrganism) -> List[str]:
        patterns: List[str] = []

        for mutation in organism.mutations:
            changed = mutation.get("changed_fields", [])
            if isinstance(changed, list):
                patterns.extend(str(f) for f in changed)
            elif isinstance(changed, str):
                patterns.append(changed)

        for event in organism.evolution_log:
            if event.event_type == "mutated":
                trigger = event.trigger
                if trigger and trigger not in patterns:
                    patterns.append(f"trigger:{trigger}")

        if organism.species:
            patterns.append(f"species:{organism.species}")

        return list(dict.fromkeys(patterns))

    def _extract_associations(self, organism: IntelligenceOrganism) -> List[str]:
        associations: List[str] = []

        for event in organism.evolution_log:
            for rid in event.related_intelligence_ids:
                if rid and rid != organism.intelligence_id:
                    associations.append(rid)

        for offspring_id in organism.offspring:
            if offspring_id not in associations:
                associations.append(offspring_id)

        for parent_id in organism.parent_ids:
            if parent_id not in associations:
                associations.append(parent_id)

        related = organism.current_state.get("related_entities", [])
        if isinstance(related, list):
            for r in related:
                r_str = str(r)
                if r_str not in associations:
                    associations.append(r_str)

        return list(dict.fromkeys(associations))

    def _extract_attack_chains(self, organism: IntelligenceOrganism) -> List[str]:
        chains: List[str] = []

        chain = organism.current_state.get("attack_chain", [])
        if isinstance(chain, list):
            chains.extend(str(c) for c in chain)
        elif isinstance(chain, str):
            chains.append(chain)

        chain = organism.current_state.get("attack_chains", [])
        if isinstance(chain, list):
            chains.extend(str(c) for c in chain)
        elif isinstance(chain, str):
            chains.append(chain)

        ttp = organism.current_state.get("ttp", "")
        if ttp:
            chains.append(f"ttp:{ttp}")

        return list(dict.fromkeys(chains))

    def _compute_gene_relevance(self, gene: IntelligenceGene, new_data: Dict) -> float:
        score = 0.0

        new_species = new_data.get("species", new_data.get("type", ""))
        if new_species and new_species == gene.species:
            score += 0.4

        new_patterns = set()
        for key, val in new_data.items():
            new_patterns.add(str(key))
            if isinstance(val, str):
                new_patterns.update(val.lower().split())

        gene_pattern_set = set(p.lower() for p in gene.patterns)
        if new_patterns and gene_pattern_set:
            overlap = new_patterns & gene_pattern_set
            score += 0.3 * (len(overlap) / max(len(gene_pattern_set), 1))

        new_associations = set()
        for key in ("related_entities", "associations", "parent_ids"):
            val = new_data.get(key, [])
            if isinstance(val, list):
                new_associations.update(str(v) for v in val)

        gene_assoc_set = set(gene.associations)
        if new_associations and gene_assoc_set:
            overlap = new_associations & gene_assoc_set
            score += 0.2 * (len(overlap) / max(len(gene_assoc_set), 1))

        new_chains = set()
        for key in ("attack_chain", "attack_chains", "ttp"):
            val = new_data.get(key, [])
            if isinstance(val, list):
                new_chains.update(str(v) for v in val)
            elif isinstance(val, str) and val:
                new_chains.add(val)

        gene_chain_set = set(gene.attack_chains)
        if new_chains and gene_chain_set:
            overlap = new_chains & gene_chain_set
            score += 0.1 * (len(overlap) / max(len(gene_chain_set), 1))

        return score
