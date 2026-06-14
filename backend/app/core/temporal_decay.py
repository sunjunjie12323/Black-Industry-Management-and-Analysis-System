import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple

import numpy as np
from loguru import logger
from scipy.optimize import minimize

from app.core.vector_store import VectorStore


@dataclass
class DecayItem:
    id: str
    content: str
    source: str
    original_confidence: float
    current_confidence: float
    half_life_hours: float
    elapsed_hours: float
    threat_type: str
    status: str = "active"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "content": self.content[:100],
            "source": self.source,
            "original_confidence": round(self.original_confidence, 4),
            "current_confidence": round(self.current_confidence, 4),
            "half_life_hours": round(self.half_life_hours, 2),
            "elapsed_hours": round(self.elapsed_hours, 2),
            "threat_type": self.threat_type,
            "status": self.status,
        }


@dataclass
class DecayBatch:
    items: List[DecayItem] = field(default_factory=list)
    total_items: int = 0
    expired_items: int = 0
    critical_items: int = 0
    average_confidence: float = 0.0

    def to_dict(self) -> dict:
        return {
            "items": [i.to_dict() for i in self.items],
            "total_items": self.total_items,
            "expired_items": self.expired_items,
            "critical_items": self.critical_items,
            "average_confidence": round(self.average_confidence, 4),
        }


@dataclass
class DecayRecommendation:
    item_id: str
    action: str
    reason: str
    urgency: str = "low"

    def to_dict(self) -> dict:
        return {
            "item_id": self.item_id,
            "action": self.action,
            "reason": self.reason,
            "urgency": self.urgency,
        }


# Reference defaults - override via TEMPORAL_HALF_LIVES_JSON / TEMPORAL_THREAT_KEYWORDS_JSON env vars
DEFAULT_HALF_LIVES = {
    "malware": 24.0,
    "phishing": 48.0,
    "vulnerability": 720.0,
    "botnet": 168.0,
    "c2": 336.0,
    "data_breach": 720.0,
    "fraud": 168.0,
    "ransomware": 72.0,
    "apt": 2160.0,
    "spam": 12.0,
    "ddos": 6.0,
    "default": 168.0,
}

THREAT_TYPE_KEYWORDS = {
    "malware": ["malware", "木马", "恶意软件", "病毒", "蠕虫", "rat", "trojan"],
    "phishing": ["phishing", "钓鱼", "仿冒", "phish"],
    "vulnerability": ["vulnerability", "漏洞", "cve", "0day", "zero-day", "exploit"],
    "botnet": ["botnet", "僵尸网络", "肉鸡"],
    "c2": ["c2", "command and control", "控制服务器"],
    "data_breach": ["breach", "泄露", "脱库", "data leak"],
    "fraud": ["fraud", "诈骗", "杀猪盘", "套路贷", "fraud"],
    "ransomware": ["ransomware", "勒索", "加密"],
    "apt": ["apt", "advanced persistent", "高级持续威胁"],
    "spam": ["spam", "垃圾邮件"],
    "ddos": ["ddos", "拒绝服务"],
}


def _load_temporal_config():
    global DEFAULT_HALF_LIVES, THREAT_TYPE_KEYWORDS
    from app.config import settings
    if settings.TEMPORAL_HALF_LIVES_JSON:
        try:
            DEFAULT_HALF_LIVES = json.loads(settings.TEMPORAL_HALF_LIVES_JSON)
        except (json.JSONDecodeError, TypeError):
            pass
    if settings.TEMPORAL_THREAT_KEYWORDS_JSON:
        try:
            THREAT_TYPE_KEYWORDS = json.loads(settings.TEMPORAL_THREAT_KEYWORDS_JSON)
        except (json.JSONDecodeError, TypeError):
            pass


_load_temporal_config()


class TemporalDecay:
    MIN_OBSERVATIONS_FOR_MLE = 3

    def __init__(self, vector_store: VectorStore):
        self.vector_store = vector_store
        self._half_lives: Dict[str, float] = dict(DEFAULT_HALF_LIVES)
        self._observations: Dict[str, List[Tuple[float, float]]] = {}
        self._persist_dir = "./model_data/temporal_decay"
        os.makedirs(self._persist_dir, exist_ok=True)
        self._load_learned_half_lives()

    def _load_learned_half_lives(self):
        path = os.path.join(self._persist_dir, "learned_half_lives.json")
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    data = json.load(f)
                self._half_lives.update(data.get("half_lives", {}))
                self._observations = {}
                for threat_type, obs_list in data.get("observations", {}).items():
                    self._observations[threat_type] = [(o[0], o[1]) for o in obs_list]
                logger.info(f"Loaded learned half-lives: {len(data.get('half_lives', {}))} types updated")
            except Exception as exc:
                logger.warning(f"Failed to load learned half-lives: {exc}")

    def _save_learned_half_lives(self):
        path = os.path.join(self._persist_dir, "learned_half_lives.json")
        obs_serializable = {}
        for t, obs in self._observations.items():
            obs_serializable[t] = [[o[0], o[1]] for o in obs]
        data = {
            "half_lives": self._half_lives,
            "observations": obs_serializable,
            "saved_at": datetime.now(timezone.utc).isoformat(),
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        logger.info("Saved learned half-lives")

    def _classify_threat_type(self, content: str, source: str) -> str:
        text = (content + " " + source).lower()
        best_type = "default"
        best_score = 0
        for threat_type, keywords in THREAT_TYPE_KEYWORDS.items():
            score = sum(1 for kw in keywords if kw in text)
            if score > best_score:
                best_score = score
                best_type = threat_type
        return best_type

    def _decay(self, original_confidence: float, elapsed_hours: float, half_life: float) -> float:
        if half_life <= 0:
            return original_confidence
        return original_confidence * float(np.power(0.5, elapsed_hours / half_life))

    def record_observation(self, threat_type: str, elapsed_hours: float, observed_confidence: float):
        if threat_type not in self._observations:
            self._observations[threat_type] = []
        self._observations[threat_type].append((elapsed_hours, observed_confidence))

        if len(self._observations[threat_type]) >= self.MIN_OBSERVATIONS_FOR_MLE:
            estimated = self._estimate_half_life_mle(threat_type)
            if estimated is not None and 1.0 <= estimated <= 8760.0:
                old_hl = self._half_lives.get(threat_type, DEFAULT_HALF_LIVES.get("default", 168.0))
                self._half_lives[threat_type] = 0.7 * estimated + 0.3 * old_hl
                self._half_lives[threat_type] = max(1.0, min(self._half_lives[threat_type], 8760.0))
                logger.info(f"MLE updated half-life for {threat_type}: {old_hl:.1f}h -> {self._half_lives[threat_type]:.1f}h")
                self._save_learned_half_lives()

    def _estimate_half_life_mle(self, threat_type: str) -> Optional[float]:
        obs = self._observations.get(threat_type, [])
        if len(obs) < self.MIN_OBSERVATIONS_FOR_MLE:
            return None

        initial_hl = self._half_lives.get(threat_type, DEFAULT_HALF_LIVES.get("default", 168.0))

        data_driven_hl = self._estimate_half_life_from_data(obs)
        if data_driven_hl is not None:
            initial_hl = data_driven_hl

        initial_conf = obs[0][1] if obs[0][1] > 0 else 0.8

        def neg_log_likelihood(log_hl):
            hl = np.exp(log_hl)
            if hl <= 0:
                return 1e10
            residuals = []
            for elapsed, observed in obs:
                predicted = initial_conf * np.power(0.5, elapsed / hl)
                residuals.append(observed - predicted)
            residuals = np.array(residuals)
            n = len(residuals)
            sigma = np.std(residuals) if n > 1 else 0.1
            sigma = max(sigma, 1e-6)
            nll = 0.5 * np.sum((residuals / sigma) ** 2) + n * np.log(sigma)
            return nll

        try:
            result = minimize(
                neg_log_likelihood,
                x0=np.log(initial_hl),
                method="L-BFGS-B",
                bounds=[(np.log(1.0), np.log(8760.0))],
            )
            if result.success:
                estimated = float(np.exp(result.x[0]))
                if 1.0 <= estimated <= 8760.0:
                    return estimated
        except Exception as exc:
            logger.warning(f"MLE estimation failed for {threat_type}: {exc}")

        if data_driven_hl is not None:
            return data_driven_hl

        return None

    def _estimate_half_life_from_data(self, obs: List[Tuple[float, float]]) -> Optional[float]:
        if len(obs) < 2:
            return None

        initial_conf = obs[0][1] if obs[0][1] > 0 else 0.8

        half_life_estimates = []
        weights = []
        for elapsed, observed in obs:
            if observed <= 0 or elapsed <= 0 or initial_conf <= 0:
                continue
            ratio = observed / initial_conf
            if ratio <= 0 or ratio >= 1:
                continue
            hl = elapsed / (-np.log2(ratio))
            if 1.0 <= hl <= 8760.0:
                half_life_estimates.append(hl)
                weights.append(observed)

        if not half_life_estimates:
            return None

        total_weight = sum(weights)
        if total_weight <= 0:
            return None

        return sum(h * w for h, w in zip(half_life_estimates, weights)) / total_weight

    async def batch_decay(self) -> DecayBatch:
        items: List[DecayItem] = []
        now = datetime.now(timezone.utc)

        db_succeeded = False
        try:
            from app.db.database import async_session_factory
            from app.db.tables import RawIntelligenceTable
            from sqlalchemy import select as sa_select
            async with async_session_factory() as session:
                result = await session.execute(
                    sa_select(RawIntelligenceTable).order_by(RawIntelligenceTable.collected_at.desc())
                )
                all_intel = result.scalars().all()

            for row in all_intel:
                doc = row.content or ""
                if not doc:
                    continue
                item_id = row.id
                source = row.source or "unknown"
                collected_at = row.collected_at
                try:
                    raw_conf = float((row.metadata_json and json.loads(row.metadata_json).get("confidence", 0.8)) or 0.8)
                except (ValueError, TypeError, json.JSONDecodeError):
                    raw_conf = 0.8
                original_conf = raw_conf

                elapsed_hours = 0.0
                if collected_at:
                    try:
                        if collected_at.tzinfo is None:
                            collected_at = collected_at.replace(tzinfo=timezone.utc)
                        elapsed = now - collected_at
                        elapsed_hours = elapsed.total_seconds() / 3600
                    except Exception:
                        elapsed_hours = 0.0

                threat_type = self._classify_threat_type(doc, source)
                half_life = self._half_lives.get(threat_type, self._half_lives["default"])
                current_conf = self._decay(original_conf, elapsed_hours, half_life)

                status = "active"
                if current_conf < 0.1:
                    status = "expired"
                elif current_conf < 0.3:
                    status = "critical"

                items.append(DecayItem(
                    id=item_id,
                    content=doc,
                    source=source,
                    original_confidence=original_conf,
                    current_confidence=current_conf,
                    half_life_hours=half_life,
                    elapsed_hours=elapsed_hours,
                    threat_type=threat_type,
                    status=status,
                ))
            db_succeeded = True
        except Exception as exc:
            logger.warning(f"Database query for batch_decay failed, falling back to vector_store: {exc}")

        if not db_succeeded:
            try:
                results = await self.vector_store.search_intelligence("", n_results=100)
            except Exception:
                results = []

            for result in results:
                doc = result.get("document", "")
                metadata = result.get("metadata", {})
                if not doc:
                    continue

                item_id = result.get("id", "")
                source = metadata.get("source", "unknown")
                collected_at_str = metadata.get("collected_at", metadata.get("timestamp", ""))
                raw_conf = metadata.get("confidence", 0.8)
                try:
                    original_conf = float(raw_conf)
                except (ValueError, TypeError):
                    original_conf = 0.8

                elapsed_hours = 0.0
                if collected_at_str:
                    try:
                        if collected_at_str.endswith("Z"):
                            collected_at_str = collected_at_str[:-1] + "+00:00"
                        collected_at = datetime.fromisoformat(collected_at_str)
                        if collected_at.tzinfo is None:
                            collected_at = collected_at.replace(tzinfo=timezone.utc)
                        elapsed = now - collected_at
                        elapsed_hours = elapsed.total_seconds() / 3600
                    except Exception:
                        elapsed_hours = 0.0

                threat_type = self._classify_threat_type(doc, source)
                half_life = self._half_lives.get(threat_type, self._half_lives["default"])
                current_conf = self._decay(original_conf, elapsed_hours, half_life)

                status = "active"
                if current_conf < 0.1:
                    status = "expired"
                elif current_conf < 0.3:
                    status = "critical"

                items.append(DecayItem(
                    id=item_id,
                    content=doc,
                    source=source,
                    original_confidence=original_conf,
                    current_confidence=current_conf,
                    half_life_hours=half_life,
                    elapsed_hours=elapsed_hours,
                    threat_type=threat_type,
                    status=status,
                ))

        expired = sum(1 for i in items if i.status == "expired")
        critical = sum(1 for i in items if i.status == "critical")
        avg_conf = float(np.mean([i.current_confidence for i in items])) if items else 0.0

        return DecayBatch(
            items=items,
            total_items=len(items),
            expired_items=expired,
            critical_items=critical,
            average_confidence=avg_conf,
        )

    async def recommendations(self) -> List[DecayRecommendation]:
        batch = await self.batch_decay()
        recs: List[DecayRecommendation] = []

        for item in batch.items:
            if item.status == "expired":
                recs.append(DecayRecommendation(
                    item_id=item.id,
                    action="归档或删除",
                    reason=f"置信度已衰减至{item.current_confidence:.2f}（半衰期{item.half_life_hours:.0f}h，已过{item.elapsed_hours:.0f}h）",
                    urgency="low",
                ))
            elif item.status == "critical":
                recs.append(DecayRecommendation(
                    item_id=item.id,
                    action="重新验证或更新",
                    reason=f"置信度降至{item.current_confidence:.2f}，即将过期",
                    urgency="high",
                ))
            elif item.current_confidence < 0.5:
                recs.append(DecayRecommendation(
                    item_id=item.id,
                    action="考虑更新来源",
                    reason=f"置信度{item.current_confidence:.2f}，建议补充新情报",
                    urgency="medium",
                ))

        recs.sort(key=lambda r: {"high": 0, "medium": 1, "low": 2}.get(r.urgency, 2))
        return recs

    async def batch_decay_analysis(self) -> Dict:
        batch = await self.batch_decay()
        recs = await self.recommendations()
        return {
            "batch": batch.to_dict(),
            "recommendations": [r.to_dict() for r in recs],
            "half_lives": {k: round(v, 2) for k, v in self._half_lives.items()},
        }

    async def recommend_refresh(self, threshold: float = 0.3) -> List[Dict]:
        batch = await self.batch_decay()
        return [
            {"id": i.id, "confidence": round(i.current_confidence, 4), "threat_type": i.threat_type}
            for i in batch.items
            if i.current_confidence < threshold
        ]

    def get_half_lives_info(self) -> Dict:
        info = {}
        for threat_type, default_hl in DEFAULT_HALF_LIVES.items():
            current_hl = self._half_lives.get(threat_type, default_hl)
            obs_count = len(self._observations.get(threat_type, []))
            info[threat_type] = {
                "default_half_life_hours": default_hl,
                "current_half_life_hours": round(current_hl, 2),
                "learned": current_hl != default_hl,
                "observation_count": obs_count,
            }
        return info

    async def compute_current_confidence(self, intelligence_id: str) -> DecayItem:
        now = datetime.now(timezone.utc)
        try:
            results = await self.vector_store.search_intelligence("", n_results=1000)
        except Exception:
            results = []

        for result in results:
            if result.get("id", "") == intelligence_id:
                doc = result.get("document", "")
                metadata = result.get("metadata", {})
                source = metadata.get("source", "unknown")
                collected_at_str = metadata.get("collected_at", metadata.get("timestamp", ""))

                raw_conf = metadata.get("confidence", 0.8)
                try:
                    original_conf = float(raw_conf)
                except (ValueError, TypeError):
                    original_conf = 0.8

                elapsed_hours = 0.0
                if collected_at_str:
                    try:
                        if collected_at_str.endswith("Z"):
                            collected_at_str = collected_at_str[:-1] + "+00:00"
                        collected_at = datetime.fromisoformat(collected_at_str)
                        if collected_at.tzinfo is None:
                            collected_at = collected_at.replace(tzinfo=timezone.utc)
                        elapsed = now - collected_at
                        elapsed_hours = elapsed.total_seconds() / 3600
                    except Exception:
                        elapsed_hours = 0.0

                threat_type = self._classify_threat_type(doc, source)
                half_life = self._half_lives.get(threat_type, self._half_lives["default"])
                current_conf = self._decay(original_conf, elapsed_hours, half_life)

                status = "active"
                if current_conf < 0.1:
                    status = "expired"
                elif current_conf < 0.3:
                    status = "critical"

                return DecayItem(
                    id=intelligence_id,
                    content=doc,
                    source=source,
                    original_confidence=original_conf,
                    current_confidence=current_conf,
                    half_life_hours=half_life,
                    elapsed_hours=elapsed_hours,
                    threat_type=threat_type,
                    status=status,
                )

        return DecayItem(
            id=intelligence_id,
            content="",
            source="unknown",
            original_confidence=0.0,
            current_confidence=0.0,
            half_life_hours=0.0,
            elapsed_hours=0.0,
            threat_type="unknown",
            status="unknown",
        )

    async def compute_decay_curve(self, intelligence_id: str, hours: int = 168, step: int = 6) -> Dict:
        item = await self.compute_current_confidence(intelligence_id)
        if item.status == "unknown":
            return {
                "intelligence_id": intelligence_id,
                "curve": [],
                "half_life_hours": 0,
                "threat_type": "unknown",
            }

        curve = []
        half_life = item.half_life_hours
        original_conf = item.original_confidence
        elapsed = item.elapsed_hours

        for h in range(0, hours + step, step):
            total_elapsed = elapsed + h
            conf = self._decay(original_conf, total_elapsed, half_life)
            curve.append({
                "hours_ahead": h,
                "total_elapsed_hours": round(total_elapsed, 1),
                "confidence": round(conf, 4),
            })

        return {
            "intelligence_id": intelligence_id,
            "curve": curve,
            "half_life_hours": round(half_life, 2),
            "threat_type": item.threat_type,
            "current_confidence": round(item.current_confidence, 4),
            "original_confidence": round(item.original_confidence, 4),
        }
