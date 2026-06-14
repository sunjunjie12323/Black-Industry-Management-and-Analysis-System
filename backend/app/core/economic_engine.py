"""
DEPRECATED — 本模块已弃用
经济系统API已从路由中移除（见 api/economic.py 返回 "经济系统已移除"）。
本模块保留仅供内部参考或未来可能的重启使用，不应在新代码中引入新的依赖。
如需经济影响评估功能，请使用情报分析相关模块替代。
Deprecated since: 2025-05. Do not add new callers.
"""

"""
Economic Engine — 黑灰产经济系统引擎
跟踪黑灰产市场规模、交易流向、经济损失评估、市场趋势分析
与情报分析Agent深度集成，将分析结果转化为经济影响指标
支持数据库持久化（生产）和JSON文件持久化（开发回退）
"""
import json
import math
import os
import random
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4
from loguru import logger

from app.config import settings


MARKET_SECTORS = {
    "fraud": "诈骗",
    "gambling": "赌博",
    "phishing": "钓鱼",
    "money_laundering": "洗钱",
    "account_trading": "账号交易",
    "tool_sales": "工具销售",
    "data_broker": "数据贩卖",
    "ransomware": "勒索软件",
    "ddos_service": "DDoS服务",
    "phishing_kit": "钓鱼工具包",
}

THREAT_TO_SECTOR_MAP: Dict[str, List[str]] = {
    "fraud": ["fraud"],
    "gambling": ["gambling"],
    "hacking": ["tool_sales", "ddos_service"],
    "money_laundering": ["money_laundering"],
    "data_theft": ["data_broker", "account_trading"],
    "phishing": ["phishing", "phishing_kit"],
    "ransomware": ["ransomware"],
    "drug": ["fraud"],
    "other": ["tool_sales"],
}

# Reference defaults - override via ECONOMIC_BASE_LOSS_JSON / ECONOMIC_BASE_AFFECTED_USERS_JSON / ECONOMIC_RISK_MULTIPLIERS_JSON env vars
RISK_LEVEL_MULTIPLIERS: Dict[str, float] = {
    "critical": 1.0,
    "high": 0.6,
    "medium": 0.3,
    "low": 0.1,
    "info": 0.02,
}

BASE_LOSS_ESTIMATES: Dict[str, float] = {
    "fraud": 800000,
    "gambling": 500000,
    "phishing": 300000,
    "money_laundering": 1000000,
    "account_trading": 200000,
    "tool_sales": 150000,
    "data_broker": 400000,
    "ransomware": 600000,
    "ddos_service": 100000,
    "phishing_kit": 80000,
}

BASE_AFFECTED_USERS: Dict[str, int] = {
    "fraud": 5000,
    "gambling": 3000,
    "phishing": 2000,
    "money_laundering": 10000,
    "account_trading": 1000,
    "tool_sales": 500,
    "data_broker": 8000,
    "ransomware": 3000,
    "ddos_service": 200,
    "phishing_kit": 1500,
}

VALID_SECTORS = set(MARKET_SECTORS.keys())
VALID_THREAT_LEVELS = {"critical", "high", "medium", "low", "info"}
VALID_TX_TYPES = {"buy", "sell", "transfer", "payment", "fee"}


def _load_economic_config():
    global BASE_LOSS_ESTIMATES, BASE_AFFECTED_USERS, RISK_LEVEL_MULTIPLIERS
    from app.config import settings
    if settings.ECONOMIC_BASE_LOSS_JSON:
        try:
            BASE_LOSS_ESTIMATES = json.loads(settings.ECONOMIC_BASE_LOSS_JSON)
        except (json.JSONDecodeError, TypeError):
            pass
    if settings.ECONOMIC_BASE_AFFECTED_USERS_JSON:
        try:
            BASE_AFFECTED_USERS = json.loads(settings.ECONOMIC_BASE_AFFECTED_USERS_JSON)
        except (json.JSONDecodeError, TypeError):
            pass
    if settings.ECONOMIC_RISK_MULTIPLIERS_JSON:
        try:
            RISK_LEVEL_MULTIPLIERS = json.loads(settings.ECONOMIC_RISK_MULTIPLIERS_JSON)
        except (json.JSONDecodeError, TypeError):
            pass


_load_economic_config()

GEO_KEYWORD_MAP: Dict[str, List[str]] = {
    "中国": ["中国", "国内", "大陆", "境内", "全国", "各省", "省级", "地市"],
    "东南亚": ["东南亚", "缅甸", "柬埔寨", "菲律宾", "泰国", "越南", "老挝", "马来西亚", "印尼"],
    "东亚": ["日本", "韩国", "台湾", "香港", "澳门"],
    "北美": ["美国", "加拿大", "北美"],
    "欧洲": ["欧洲", "英国", "德国", "法国", "欧盟"],
    "全球": ["全球", "国际", "跨国", "跨境", "多国"],
}

SECTOR_DURATION_DEFAULTS: Dict[str, int] = {
    "phishing": 14,
    "phishing_kit": 14,
    "ransomware": 30,
    "money_laundering": 90,
    "fraud": 60,
    "gambling": 45,
    "account_trading": 30,
    "tool_sales": 21,
    "data_broker": 30,
    "ddos_service": 7,
}


@dataclass
class MarketState:
    sector: str
    sector_name: str
    price_index: float = 100.0
    volume_24h: float = 0.0
    volatility: float = 0.15
    trend: str = "stable"
    risk_score: float = 0.0
    market_cap_estimate: float = 0.0
    active_entities: int = 0
    last_updated: str = ""

    def to_dict(self):
        return asdict(self)


@dataclass
class Transaction:
    tx_id: str
    sector: str
    tx_type: str
    amount: float
    price: float
    total_value: float
    fee: float
    from_entity: str
    to_entity: str
    risk_score: float
    intelligence_ids: List[str]
    timestamp: str
    description: str = ""

    def to_dict(self):
        return asdict(self)


@dataclass
class EconomicImpact:
    impact_id: str
    sector: str
    estimated_loss: float
    affected_users: int
    geographic_scope: List[str]
    duration_days: int
    confidence: float
    intelligence_source_ids: List[str]
    threat_categories: List[str]
    assessed_at: str

    def to_dict(self):
        return asdict(self)


@dataclass
class MarketAlert:
    alert_id: str
    sector: str
    alert_type: str
    severity: str
    message: str
    related_intelligence_ids: List[str]
    economic_impact_ids: List[str]
    created_at: str
    is_resolved: bool = False

    def to_dict(self):
        return asdict(self)


@dataclass
class SectorFlow:
    from_sector: str
    to_sector: str
    flow_volume: float
    transaction_count: int
    risk_indicators: List[str]

    def to_dict(self):
        return asdict(self)


@dataclass
class EconomicDashboard:
    total_estimated_loss: float
    total_affected_users: int
    active_alerts: int
    market_states: List[Dict]
    sector_flows: List[Dict]
    recent_transactions: List[Dict]
    impacts: List[Dict]
    alerts: List[Dict]
    updated_at: str

    def to_dict(self):
        return asdict(self)


@dataclass
class MonteCarloResult:
    mean_loss: float
    median_loss: float
    p5_loss: float
    p95_loss: float
    var_95: float
    expected_shortfall_95: float
    confidence_interval_90: Tuple[float, float]
    simulation_count: int
    sector: str
    distribution_percentiles: Dict[str, float]

    def to_dict(self):
        d = asdict(self)
        d["confidence_interval_90"] = list(self.confidence_interval_90)
        return d


@dataclass
class RiskNarrative:
    narrative_id: str
    impact_id: str
    summary: str
    key_drivers: List[str]
    potential_scenarios: List[str]
    recommended_actions: List[str]
    confidence_assessment: str
    generated_at: str

    def to_dict(self):
        return asdict(self)


class LLMEconomicAnalyzer:

    def __init__(self, llm_service=None):
        self._llm = llm_service

    async def assess_economic_impact(
        self,
        threat_categories: List[str],
        threat_level: str,
        content_summary: str,
    ) -> Optional[Dict]:
        if not self._llm:
            return None
        try:
            prompt = (
                f"请分析以下黑灰产威胁的经济影响，以JSON格式返回：\n"
                f"威胁类型: {', '.join(threat_categories)}\n"
                f"威胁等级: {threat_level}\n"
                f"情报摘要: {content_summary[:1000]}\n\n"
                f"请返回如下JSON格式：\n"
                f'{{"estimated_loss_range": [最低损失, 最高损失], '
                f'"affected_users_range": [最少用户, 最多用户], '
                f'"geographic_scope": ["地区1", "地区2"], '
                f'"duration_days_estimate": 预估持续天数, '
                f'"confidence": 置信度0到1, '
                f'"key_factors": ["关键因素1", "关键因素2"], '
                f'"sector_impacts": {{"行业key": {{"loss_multiplier": 倍数, "user_impact_ratio": 比率}}}}}}\n'
                f"行业key可选: {', '.join(MARKET_SECTORS.keys())}"
            )
            result = await self._llm.generate_json(
                prompt=prompt,
                system_prompt="你是黑灰产经济影响分析专家。根据威胁情报评估经济损失、影响用户数和地理范围。只返回JSON。",
                temperature=settings.LLM_TEMPERATURE_CREATIVE,
            )
            return result
        except Exception as exc:
            logger.warning(f"LLM经济影响评估失败: {exc}")
            return None

    async def analyze_market_impact(self, sector: str, threat_info: Dict) -> Optional[Dict]:
        if not self._llm:
            return None
        try:
            prompt = (
                f"请分析以下黑灰产威胁对特定市场行业的影响，以JSON格式返回：\n"
                f"行业: {sector} ({MARKET_SECTORS.get(sector, sector)})\n"
                f"威胁信息: {json.dumps(threat_info, ensure_ascii=False)[:800]}\n\n"
                f"请返回如下JSON格式：\n"
                f'{{"price_impact_pct": 价格指数变化百分比, '
                f'"volume_impact_pct": 交易量变化百分比, '
                f'"volatility_change": 波动率变化, '
                f'"trend_direction": "rising"/"falling"/"stable", '
                f'"risk_score_delta": 风险分数变化, '
                f'"downstream_effects": [{{"sector": "行业", "impact_pct": 百分比}}], '
                f'"market_narrative": "简短市场影响描述"}}'
            )
            result = await self._llm.generate_json(
                prompt=prompt,
                system_prompt="你是黑灰产市场经济分析专家。分析威胁对市场指标的影响。只返回JSON。",
                temperature=settings.LLM_TEMPERATURE_CREATIVE,
            )
            return result
        except Exception as exc:
            logger.warning(f"LLM市场影响分析失败: {exc}")
            return None

    async def generate_risk_narrative(self, impact: EconomicImpact) -> Optional[RiskNarrative]:
        if not self._llm:
            return None
        try:
            prompt = (
                f"请为以下经济影响生成风险叙事报告，以JSON格式返回：\n"
                f"行业: {impact.sector} ({MARKET_SECTORS.get(impact.sector, impact.sector)})\n"
                f"预估损失: {impact.estimated_loss:,.0f}\n"
                f"影响用户数: {impact.affected_users:,}\n"
                f"地理范围: {', '.join(impact.geographic_scope)}\n"
                f"持续天数: {impact.duration_days}\n"
                f"置信度: {impact.confidence}\n"
                f"威胁类别: {', '.join(impact.threat_categories)}\n\n"
                f'请返回: {{"summary": "风险概述", '
                f'"key_drivers": ["驱动因素1", "驱动因素2"], '
                f'"potential_scenarios": ["场景1", "场景2"], '
                f'"recommended_actions": ["建议1", "建议2"], '
                f'"confidence_assessment": "置信度评估说明"}}'
            )
            result = await self._llm.generate_json(
                prompt=prompt,
                system_prompt="你是黑灰产风险分析专家。生成专业的风险叙事报告。只返回JSON。",
                temperature=settings.LLM_TEMPERATURE_NARRATIVE,
            )
            return RiskNarrative(
                narrative_id=f"narr-{uuid4().hex[:12]}",
                impact_id=impact.impact_id,
                summary=result.get("summary", ""),
                key_drivers=result.get("key_drivers", []),
                potential_scenarios=result.get("potential_scenarios", []),
                recommended_actions=result.get("recommended_actions", []),
                confidence_assessment=result.get("confidence_assessment", ""),
                generated_at=datetime.now(timezone.utc).isoformat(),
            )
        except Exception as exc:
            logger.warning(f"LLM风险叙事生成失败: {exc}")
            return None


class DynamicBaselineCalculator:

    def __init__(self, ewma_alpha: float = 0.3, min_samples: int = 5):
        self._alpha = ewma_alpha
        self._min_samples = min_samples
        self._max_sectors = 100
        self._max_users = 1000
        self._loss_baselines: Dict[str, float] = {}
        self._user_baselines: Dict[str, float] = {}
        self._loss_counts: Dict[str, int] = defaultdict(int)
        self._user_counts: Dict[str, int] = defaultdict(int)
        self._seasonal_factors: Dict[str, Dict[int, float]] = {}
        self._trend_adjustments: Dict[str, float] = {}

    def update_baselines(self, sector: str, observed_loss: float, observed_users: int):
        self._loss_counts[sector] += 1
        self._user_counts[sector] += 1

        if len(self._loss_baselines) > self._max_sectors:
            oldest_sector = next(iter(self._loss_baselines))
            self._loss_counts.pop(oldest_sector, None)
            self._seasonal_factors.pop(oldest_sector, None)
            self._trend_adjustments.pop(oldest_sector, None)
            del self._loss_baselines[oldest_sector]

        if len(self._user_baselines) > self._max_users:
            oldest_user = next(iter(self._user_baselines))
            self._user_counts.pop(oldest_user, None)
            del self._user_baselines[oldest_user]

        if sector in self._loss_baselines:
            self._loss_baselines[sector] = (
                self._alpha * observed_loss + (1 - self._alpha) * self._loss_baselines[sector]
            )
        else:
            self._loss_baselines[sector] = observed_loss

        if sector in self._user_baselines:
            self._user_baselines[sector] = (
                self._alpha * observed_users + (1 - self._alpha) * self._user_baselines[sector]
            )
        else:
            self._user_baselines[sector] = observed_users

        self._update_seasonal_factor(sector)
        self._update_trend_adjustment(sector, observed_loss)

    def get_loss_baseline(self, sector: str) -> float:
        if self._loss_counts.get(sector, 0) >= self._min_samples:
            base = self._loss_baselines.get(sector, BASE_LOSS_ESTIMATES.get(sector, 100000))
            seasonal = self._get_seasonal_factor(sector)
            trend = self._trend_adjustments.get(sector, 0.0)
            return base * seasonal * (1 + trend)
        return BASE_LOSS_ESTIMATES.get(sector, 100000)

    def get_user_baseline(self, sector: str) -> int:
        if self._user_counts.get(sector, 0) >= self._min_samples:
            base = self._user_baselines.get(sector, BASE_AFFECTED_USERS.get(sector, 1000))
            seasonal = self._get_seasonal_factor(sector)
            return max(1, int(base * seasonal))
        return BASE_AFFECTED_USERS.get(sector, 1000)

    def _update_seasonal_factor(self, sector: str):
        month = datetime.now().month
        if sector not in self._seasonal_factors:
            self._seasonal_factors[sector] = {m: 1.0 for m in range(1, 13)}

        high_season_months = {
            "fraud": [1, 2, 11, 12],
            "gambling": [1, 2, 12],
            "phishing": [3, 9, 11],
            "money_laundering": [3, 6, 9, 12],
            "ransomware": [4, 10],
        }
        if sector in high_season_months:
            for m in range(1, 13):
                if m in high_season_months[sector]:
                    self._seasonal_factors[sector][m] = 1.2
                else:
                    self._seasonal_factors[sector][m] = 0.95

    def _get_seasonal_factor(self, sector: str) -> float:
        month = datetime.now().month
        return self._seasonal_factors.get(sector, {}).get(month, 1.0)

    def _update_trend_adjustment(self, sector: str, observed_loss: float):
        current = self._trend_adjustments.get(sector, 0.0)
        baseline = self._loss_baselines.get(sector, BASE_LOSS_ESTIMATES.get(sector, 100000))
        if baseline > 0:
            deviation = (observed_loss - baseline) / baseline
            self._trend_adjustments[sector] = current * 0.8 + deviation * 0.2
        else:
            self._trend_adjustments[sector] = current * 0.8

    def get_baseline_stats(self) -> Dict:
        return {
            "loss_baselines": dict(self._loss_baselines),
            "user_baselines": dict(self._user_baselines),
            "loss_counts": dict(self._loss_counts),
            "user_counts": dict(self._user_counts),
            "trend_adjustments": dict(self._trend_adjustments),
        }


class MonteCarloRiskSimulator:

    def __init__(self, default_simulations: int = 10000, random_seed: Optional[int] = None):
        self._default_simulations = default_simulations
        self._rng = random.Random(random_seed)

    def simulate_loss_distribution(
        self,
        sector: str,
        base_loss: float,
        risk_multiplier: float,
        volatility: float = 0.3,
        simulations: Optional[int] = None,
        correlated_shocks: Optional[Dict[str, float]] = None,
    ) -> MonteCarloResult:
        n = simulations or self._default_simulations
        losses = []
        for _ in range(n):
            z = self._rng.gauss(0, 1)
            log_loss = math.log(max(1.0, base_loss)) + z * volatility
            loss = math.exp(log_loss) * risk_multiplier
            if correlated_shocks:
                shock = correlated_shocks.get(sector, 0.0)
                loss *= (1 + shock)
            losses.append(max(0.0, loss))

        losses.sort()
        mean_loss = sum(losses) / n
        median_loss = losses[n // 2]
        p5_idx = max(0, int(n * 0.05))
        p95_idx = min(n - 1, int(n * 0.95))
        p5_loss = losses[p5_idx]
        p95_loss = losses[p95_idx]
        var_95 = p95_loss
        tail_losses = losses[int(n * 0.95):]
        expected_shortfall = sum(tail_losses) / max(1, len(tail_losses))

        percentiles = {}
        for p in [1, 5, 10, 25, 50, 75, 90, 95, 99]:
            idx = min(n - 1, int(n * p / 100))
            percentiles[f"p{p}"] = losses[idx]

        return MonteCarloResult(
            mean_loss=mean_loss,
            median_loss=median_loss,
            p5_loss=p5_loss,
            p95_loss=p95_loss,
            var_95=var_95,
            expected_shortfall_95=expected_shortfall,
            confidence_interval_90=(p5_loss, p95_loss),
            simulation_count=n,
            sector=sector,
            distribution_percentiles=percentiles,
        )

    def simulate_multi_factor(
        self,
        sector_risks: Dict[str, Tuple[float, float, float]],
        correlation_matrix: Dict[str, Dict[str, float]],
        simulations: Optional[int] = None,
    ) -> Dict[str, MonteCarloResult]:
        n = simulations or self._default_simulations
        sectors = list(sector_risks.keys())
        sector_losses: Dict[str, List[float]] = {s: [] for s in sectors}

        for _ in range(n):
            base_z = self._rng.gauss(0, 1)
            sector_z = {}
            for s in sectors:
                correlated_z = base_z * 0.3 + self._rng.gauss(0, 1) * 0.7
                for other_s, corr in correlation_matrix.get(s, {}).items():
                    if other_s in sector_z:
                        correlated_z += corr * sector_z[other_s] * 0.2
                sector_z[s] = correlated_z

            for s in sectors:
                base_loss, risk_mult, vol = sector_risks[s]
                log_loss = math.log(max(1.0, base_loss)) + sector_z[s] * vol
                loss = math.exp(log_loss) * risk_mult
                sector_losses[s].append(max(0.0, loss))

        results = {}
        for s in sectors:
            losses = sorted(sector_losses[s])
            mean_loss = sum(losses) / n
            median_loss = losses[n // 2]
            p5_idx = max(0, int(n * 0.05))
            p95_idx = min(n - 1, int(n * 0.95))
            p5_loss = losses[p5_idx]
            p95_loss = losses[p95_idx]
            var_95 = p95_loss
            tail_losses = losses[int(n * 0.95):]
            expected_shortfall = sum(tail_losses) / max(1, len(tail_losses))

            percentiles = {}
            for p in [1, 5, 10, 25, 50, 75, 90, 95, 99]:
                idx = min(n - 1, int(n * p / 100))
                percentiles[f"p{p}"] = losses[idx]

            results[s] = MonteCarloResult(
                mean_loss=mean_loss,
                median_loss=median_loss,
                p5_loss=p5_loss,
                p95_loss=p95_loss,
                var_95=var_95,
                expected_shortfall_95=expected_shortfall,
                confidence_interval_90=(p5_loss, p95_loss),
                simulation_count=n,
                sector=s,
                distribution_percentiles=percentiles,
            )

        return results


class AdaptiveCorrelationEngine:

    def __init__(self, window_size: int = 50, structural_change_threshold: float = 0.3):
        self._window_size = window_size
        self._structural_change_threshold = structural_change_threshold
        self._max_sectors = 100
        self._max_history_per_pair = 500
        self._co_movement_history: Dict[str, Dict[str, List[Tuple[float, float]]]] = defaultdict(
            lambda: defaultdict(list)
        )
        self._base_correlations: Dict[str, Dict[str, float]] = {}

    def set_base_correlations(self, correlations: Dict[str, Dict[str, float]]):
        self._base_correlations = correlations

    def record_co_movement(self, sector_a: str, delta_a: float, sector_b: str, delta_b: float):
        self._co_movement_history[sector_a][sector_b].append((delta_a, delta_b))
        if len(self._co_movement_history) > self._max_sectors:
            oldest_sector = next(iter(self._co_movement_history))
            del self._co_movement_history[oldest_sector]
            self._base_correlations.pop(oldest_sector, None)
        pair_history = self._co_movement_history[sector_a][sector_b]
        if len(pair_history) > self._max_history_per_pair:
            pair_history[:] = pair_history[-self._max_history_per_pair:]
        if len(self._co_movement_history[sector_a][sector_b]) > self._window_size:
            self._co_movement_history[sector_a][sector_b] = (
                self._co_movement_history[sector_a][sector_b][-self._window_size:]
            )

    def compute_adaptive_correlations(self) -> Dict[str, Dict[str, float]]:
        result = {}
        for sector_a, targets in self._base_correlations.items():
            result[sector_a] = {}
            for sector_b, base_corr in targets.items():
                history = self._co_movement_history.get(sector_a, {}).get(sector_b, [])
                if len(history) >= 5:
                    empirical = self._pearson_correlation(history)
                    if empirical is not None:
                        weight = min(1.0, len(history) / self._window_size)
                        adapted = base_corr * (1 - weight) + empirical * weight
                        if abs(adapted - base_corr) > self._structural_change_threshold:
                            logger.info(
                                f"结构性相关性变化: {sector_a}-{sector_b} "
                                f"基线={base_corr:.3f} 适应={adapted:.3f}"
                            )
                        result[sector_a][sector_b] = max(-1.0, min(1.0, adapted))
                    else:
                        result[sector_a][sector_b] = base_corr
                else:
                    result[sector_a][sector_b] = base_corr
        return result

    def _pearson_correlation(self, history: List[Tuple[float, float]]) -> Optional[float]:
        n = len(history)
        if n < 3:
            return None
        sum_x = sum(h[0] for h in history)
        sum_y = sum(h[1] for h in history)
        sum_xy = sum(h[0] * h[1] for h in history)
        sum_x2 = sum(h[0] ** 2 for h in history)
        sum_y2 = sum(h[1] ** 2 for h in history)
        denom = math.sqrt((n * sum_x2 - sum_x ** 2) * (n * sum_y2 - sum_y ** 2))
        if denom == 0:
            return None
        return (n * sum_xy - sum_x * sum_y) / denom

    def get_correlation_stats(self) -> Dict:
        stats = {}
        for sector_a, targets in self._co_movement_history.items():
            stats[sector_a] = {}
            for sector_b, history in targets.items():
                stats[sector_a][sector_b] = len(history)
        return stats


class EconomicEngine:
    PERSIST_DIR = "./economic_data"
    PERSIST_FILE = "economic_state.json"
    MAX_TRANSACTIONS = 500
    MAX_IMPACTS = 200
    MAX_ALERTS = 200
    MAX_FLOWS = 100

    def __init__(self, persist_dir: str = None, volatility: float = 0.15, use_db: bool = False, data_provider=None, llm_service=None):
        self.persist_dir = persist_dir or self.PERSIST_DIR
        self.volatility = max(0.01, min(1.0, volatility))
        self.use_db = use_db
        self._data_provider = data_provider
        self.market_states: Dict[str, MarketState] = {}
        self.transactions: List[Transaction] = []
        self.impacts: List[EconomicImpact] = []
        self.alerts: List[MarketAlert] = []
        self.sector_flows: List[SectorFlow] = []
        self._sector_correlations: Dict[str, Dict[str, float]] = {}
        self._max_sectors = 100
        self._data_file = "./model_data/economic/market_states.json"
        self._llm_analyzer = LLMEconomicAnalyzer(llm_service)
        self._baseline_calculator = DynamicBaselineCalculator()
        self._mc_simulator = MonteCarloRiskSimulator()
        self._adaptive_corr_engine = AdaptiveCorrelationEngine()
        self._risk_narratives: List[RiskNarrative] = []
        self._initialize_markets()
        self._initialize_correlations()
        self._train_baselines_from_history()
        if not use_db:
            self._load_from_disk()

    def _initialize_markets(self):
        if self._load_market_states():
            logger.info(f"Loaded market states from {self._data_file}")
            return
        for sector_key, sector_name in MARKET_SECTORS.items():
            base_val = BASE_LOSS_ESTIMATES.get(sector_key, 100000)
            self.market_states[sector_key] = MarketState(
                sector=sector_key,
                sector_name=sector_name,
                price_index=100.0,
                volume_24h=base_val,
                volatility=self.volatility,
                risk_score=0.3,
                market_cap_estimate=base_val * 10,
                active_entities=50,
                last_updated=datetime.now(timezone.utc).isoformat(),
            )
        self._save_market_states()

    def _load_market_states(self) -> bool:
        try:
            with open(self._data_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            for k, v in data.items():
                self.market_states[k] = MarketState(**v)
            return len(self.market_states) > 0
        except Exception:
            return False

    def _save_market_states(self):
        try:
            os.makedirs(os.path.dirname(self._data_file), exist_ok=True)
            data = {}
            for k, v in self.market_states.items():
                data[k] = {
                    "sector": v.sector, "sector_name": v.sector_name,
                    "price_index": v.price_index, "volume_24h": v.volume_24h,
                    "volatility": v.volatility, "risk_score": v.risk_score,
                    "market_cap_estimate": v.market_cap_estimate,
                    "active_entities": v.active_entities,
                    "last_updated": v.last_updated,
                }
            with open(self._data_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as exc:
            logger.warning(f"Failed to save market states: {exc}")

    def _initialize_correlations(self):
        self._sector_correlations = {
            "fraud": {"money_laundering": 0.8, "account_trading": 0.6, "phishing": 0.5},
            "phishing": {"fraud": 0.5, "phishing_kit": 0.7, "account_trading": 0.4},
            "money_laundering": {"fraud": 0.8, "gambling": 0.6, "ransomware": 0.5},
            "ransomware": {"money_laundering": 0.5, "tool_sales": 0.6, "data_broker": 0.4},
            "tool_sales": {"ransomware": 0.6, "ddos_service": 0.5, "phishing_kit": 0.7},
            "data_broker": {"account_trading": 0.7, "phishing": 0.5, "fraud": 0.4},
            "gambling": {"money_laundering": 0.6, "fraud": 0.3},
            "account_trading": {"data_broker": 0.7, "fraud": 0.6, "phishing": 0.4},
            "ddos_service": {"tool_sales": 0.5, "ransomware": 0.3},
            "phishing_kit": {"phishing": 0.7, "tool_sales": 0.7},
        }
        self._adaptive_corr_engine.set_base_correlations(self._sector_correlations)
        if len(self._sector_correlations) > self._max_sectors:
            oldest_sector = next(iter(self._sector_correlations))
            del self._sector_correlations[oldest_sector]

    def _train_baselines_from_history(self):
        for impact in self.impacts:
            self._baseline_calculator.update_baselines(
                impact.sector, impact.estimated_loss, impact.affected_users
            )

    def _load_from_disk(self):
        persist_path = Path(self.persist_dir) / self.PERSIST_FILE
        if not persist_path.exists():
            return
        try:
            with open(persist_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            for sid, sdata in raw.get("market_states", {}).items():
                self.market_states[sid] = MarketState(**sdata)
            for tdata in raw.get("transactions", []):
                self.transactions.append(Transaction(**tdata))
            for idata in raw.get("impacts", []):
                self.impacts.append(EconomicImpact(**idata))
            for adata in raw.get("alerts", []):
                self.alerts.append(MarketAlert(**adata))
            for fdata in raw.get("sector_flows", []):
                self.sector_flows.append(SectorFlow(**fdata))
            logger.info(
                f"EconomicEngine loaded from disk: {len(self.market_states)} sectors, "
                f"{len(self.transactions)} tx, {len(self.impacts)} impacts"
            )
        except Exception as exc:
            logger.warning(f"Failed to load economic data from disk: {exc}")

    async def load_from_db(self, db_session=None):
        if db_session is None:
            from app.db.database import async_session_factory
            async with async_session_factory() as session:
                return await self.load_from_db(db_session=session)
        from app.db.economic_tables import (
            EconomicImpactTable, MarketTransactionTable,
            MarketStateTable, EconomicAlertTable,
        )
        from sqlalchemy import select

        try:
            state_result = await db_session.execute(select(MarketStateTable))
            for row in state_result.scalars().all():
                self.market_states[row.sector] = MarketState(
                    sector=row.sector,
                    sector_name=row.sector_name,
                    price_index=row.price_index,
                    volume_24h=row.volume_24h,
                    volatility=row.volatility,
                    trend=row.trend,
                    risk_score=row.risk_score,
                    market_cap_estimate=row.market_cap_estimate,
                    active_entities=row.active_entities,
                    last_updated=row.last_updated.isoformat() if hasattr(row.last_updated, 'isoformat') else str(row.last_updated),
                )

            tx_result = await db_session.execute(
                select(MarketTransactionTable).order_by(MarketTransactionTable.timestamp.desc()).limit(self.MAX_TRANSACTIONS)
            )
            for row in tx_result.scalars().all():
                self.transactions.append(Transaction(
                    tx_id=row.id,
                    sector=row.sector,
                    tx_type=row.tx_type,
                    amount=row.amount,
                    price=row.price,
                    total_value=row.total_value,
                    fee=row.fee,
                    from_entity=row.from_entity or "",
                    to_entity=row.to_entity or "",
                    risk_score=row.risk_score,
                    intelligence_ids=json.loads(row.intelligence_ids) if row.intelligence_ids else [],
                    timestamp=row.timestamp.isoformat() if hasattr(row.timestamp, 'isoformat') else str(row.timestamp),
                    description=row.description or "",
                ))

            impact_result = await db_session.execute(
                select(EconomicImpactTable).order_by(EconomicImpactTable.assessed_at.desc()).limit(self.MAX_IMPACTS)
            )
            for row in impact_result.scalars().all():
                self.impacts.append(EconomicImpact(
                    impact_id=row.id,
                    sector=row.sector,
                    estimated_loss=row.estimated_loss,
                    affected_users=row.affected_users,
                    geographic_scope=json.loads(row.geographic_scope) if row.geographic_scope else [],
                    duration_days=row.duration_days,
                    confidence=row.confidence,
                    intelligence_source_ids=json.loads(row.intelligence_source_ids) if row.intelligence_source_ids else [],
                    threat_categories=json.loads(row.threat_categories) if row.threat_categories else [],
                    assessed_at=row.assessed_at.isoformat() if hasattr(row.assessed_at, 'isoformat') else str(row.assessed_at),
                ))

            alert_result = await db_session.execute(
                select(EconomicAlertTable).order_by(EconomicAlertTable.created_at.desc()).limit(self.MAX_ALERTS)
            )
            for row in alert_result.scalars().all():
                self.alerts.append(MarketAlert(
                    alert_id=row.id,
                    sector=row.sector,
                    alert_type=row.alert_type,
                    severity=row.severity,
                    message=row.message,
                    related_intelligence_ids=json.loads(row.related_intelligence_ids) if row.related_intelligence_ids else [],
                    economic_impact_ids=json.loads(row.economic_impact_ids) if row.economic_impact_ids else [],
                    created_at=row.created_at.isoformat() if hasattr(row.created_at, 'isoformat') else str(row.created_at),
                    is_resolved=bool(row.is_resolved),
                ))

            self._train_baselines_from_history()
            logger.info(
                f"EconomicEngine loaded from DB: {len(self.market_states)} sectors, "
                f"{len(self.transactions)} tx, {len(self.impacts)} impacts, {len(self.alerts)} alerts"
            )
        except Exception as exc:
            logger.warning(f"Failed to load economic data from DB, falling back to disk: {exc}")
            self._load_from_disk()

    def save_to_disk(self):
        persist_dir = Path(self.persist_dir)
        persist_dir.mkdir(parents=True, exist_ok=True)
        persist_path = persist_dir / self.PERSIST_FILE
        try:
            data = {
                "market_states": {k: v.to_dict() for k, v in self.market_states.items()},
                "transactions": [t.to_dict() for t in self.transactions[-self.MAX_TRANSACTIONS:]],
                "impacts": [i.to_dict() for i in self.impacts[-self.MAX_IMPACTS:]],
                "alerts": [a.to_dict() for a in self.alerts[-self.MAX_ALERTS:]],
                "sector_flows": [f.to_dict() for f in self.sector_flows[-self.MAX_FLOWS:]],
                "saved_at": datetime.now(timezone.utc).isoformat(),
            }
            tmp_path = persist_path.with_suffix(".tmp")
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, default=str)
            tmp_path.replace(persist_path)
        except Exception as exc:
            logger.error(f"Failed to save economic data to disk: {exc}")

    async def save_to_db(self, db_session=None):
        if db_session is None:
            from app.db.database import async_session_factory
            async with async_session_factory() as session:
                return await self.save_to_db(db_session=session)
        from app.db.economic_tables import (
            EconomicImpactTable, MarketTransactionTable,
            MarketStateTable, EconomicAlertTable,
        )
        from sqlalchemy import select as sa_select
        from uuid import uuid4

        try:
            for sector_key, state in self.market_states.items():
                existing = await db_session.execute(
                    sa_select(MarketStateTable).where(MarketStateTable.sector == sector_key)
                )
                row = existing.scalar_one_or_none()
                if row:
                    row.sector_name = state.sector_name
                    row.price_index = state.price_index
                    row.volume_24h = state.volume_24h
                    row.volatility = state.volatility
                    row.trend = state.trend
                    row.risk_score = state.risk_score
                    row.market_cap_estimate = state.market_cap_estimate
                    row.active_entities = state.active_entities
                else:
                    db_session.add(MarketStateTable(
                        sector=state.sector,
                        sector_name=state.sector_name,
                        price_index=state.price_index,
                        volume_24h=state.volume_24h,
                        volatility=state.volatility,
                        trend=state.trend,
                        risk_score=state.risk_score,
                        market_cap_estimate=state.market_cap_estimate,
                        active_entities=state.active_entities,
                    ))
            await db_session.commit()
        except Exception as exc:
            logger.warning(f"Failed to save market states to DB: {exc}")

    async def _persist_impact(self, impact: EconomicImpact, db_session=None):
        if db_session is None:
            from app.db.database import async_session_factory
            async with async_session_factory() as session:
                return await self._persist_impact(impact, db_session=session)
        from app.db.economic_tables import EconomicImpactTable

        try:
            db_session.add(EconomicImpactTable(
                id=impact.impact_id,
                sector=impact.sector,
                estimated_loss=impact.estimated_loss,
                affected_users=impact.affected_users,
                geographic_scope=json.dumps(impact.geographic_scope, ensure_ascii=False),
                duration_days=impact.duration_days,
                confidence=impact.confidence,
                intelligence_source_ids=json.dumps(impact.intelligence_source_ids, ensure_ascii=False),
                threat_categories=json.dumps(impact.threat_categories, ensure_ascii=False),
            ))
            await db_session.commit()
        except Exception as exc:
            logger.warning(f"Failed to persist impact to DB: {exc}")

    async def _persist_alert(self, alert: MarketAlert, db_session=None):
        if db_session is None:
            from app.db.database import async_session_factory
            async with async_session_factory() as session:
                return await self._persist_alert(alert, db_session=session)
        from app.db.economic_tables import EconomicAlertTable

        try:
            db_session.add(EconomicAlertTable(
                id=alert.alert_id,
                sector=alert.sector,
                alert_type=alert.alert_type,
                severity=alert.severity,
                message=alert.message,
                related_intelligence_ids=json.dumps(alert.related_intelligence_ids, ensure_ascii=False),
                economic_impact_ids=json.dumps(alert.economic_impact_ids, ensure_ascii=False),
                is_resolved=alert.is_resolved,
            ))
            await db_session.commit()
        except Exception as exc:
            logger.warning(f"Failed to persist alert to DB: {exc}")

    async def _persist_transaction(self, tx: Transaction, db_session=None):
        if db_session is None:
            from app.db.database import async_session_factory
            async with async_session_factory() as session:
                return await self._persist_transaction(tx, db_session=session)
        from app.db.economic_tables import MarketTransactionTable

        try:
            db_session.add(MarketTransactionTable(
                id=tx.tx_id,
                sector=tx.sector,
                tx_type=tx.tx_type,
                amount=tx.amount,
                price=tx.price,
                total_value=tx.total_value,
                fee=tx.fee,
                from_entity=tx.from_entity,
                to_entity=tx.to_entity,
                risk_score=tx.risk_score,
                intelligence_ids=json.dumps(tx.intelligence_ids, ensure_ascii=False),
                description=tx.description,
            ))
            await db_session.commit()
        except Exception as exc:
            logger.warning(f"Failed to persist transaction to DB: {exc}")

    async def persist(self):
        if self.use_db:
            await self.save_to_db()
        else:
            self.save_to_disk()

    def update_market(self, sector: str, risk_delta: float = 0.0, llm_market_analysis: Optional[Dict] = None):
        if sector not in VALID_SECTORS:
            return
        state = self.market_states.get(sector)
        if not state:
            return

        if llm_market_analysis:
            price_impact = llm_market_analysis.get("price_impact_pct", 0)
            state.price_index = max(1.0, state.price_index * (1 + price_impact / 100))
            vol_change = llm_market_analysis.get("volatility_change", 0)
            state.volatility = max(0.01, min(1.0, state.volatility + vol_change))
            risk_delta_llm = llm_market_analysis.get("risk_score_delta", 0)
            state.risk_score = max(0.0, min(1.0, state.risk_score + risk_delta_llm))
            volume_impact = llm_market_analysis.get("volume_impact_pct", 0)
            state.volume_24h = max(0.0, state.volume_24h * (1 + volume_impact / 100))
        else:
            elasticity = 0.05 + state.volatility * 0.1
            momentum = 0.02 if state.trend == "rising" else (-0.02 if state.trend == "falling" else 0)
            price_change = risk_delta * elasticity + momentum * risk_delta
            state.price_index = max(1.0, state.price_index * (1 + price_change))

            if risk_delta > 0:
                state.risk_score = min(1.0, state.risk_score + risk_delta * 0.1)
                state.volatility = min(1.0, state.volatility + risk_delta * 0.02)
            else:
                state.risk_score = max(0.0, state.risk_score * 0.99)
                state.volatility = max(0.05, state.volatility * 0.995)

        if state.price_index > 110:
            state.trend = "rising"
        elif state.price_index < 90:
            state.trend = "falling"
        else:
            state.trend = "stable"
        state.last_updated = datetime.now(timezone.utc).isoformat()
        self._save_market_states()
        self._propagate_correlation(sector, risk_delta * 0.3)

    def _propagate_correlation(self, source_sector: str, delta: float):
        adapted_correlations = self._adaptive_corr_engine.compute_adaptive_correlations()
        correlations = adapted_correlations.get(source_sector, self._sector_correlations.get(source_sector, {}))
        for target_sector, corr in correlations.items():
            target_state = self.market_states.get(target_sector)
            if target_state:
                propagated_delta = delta * corr
                target_state.risk_score = min(1.0, target_state.risk_score + propagated_delta * 0.05)
                target_state.last_updated = datetime.now(timezone.utc).isoformat()
                self._adaptive_corr_engine.record_co_movement(
                    source_sector, delta, target_sector, propagated_delta
                )

    def infer_geographic_scope(self, content: str, threat_categories: List[str]) -> List[str]:
        if not content and not threat_categories:
            return ["中国"]

        detected_regions = set()
        content_lower = content.lower() if content else ""

        for region, keywords in GEO_KEYWORD_MAP.items():
            for kw in keywords:
                if kw in content_lower:
                    detected_regions.add(region)
                    break

        category_geo_hints = {
            "money_laundering": ["中国", "东南亚"],
            "fraud": ["中国", "东南亚"],
            "gambling": ["中国", "东南亚"],
            "phishing": ["中国"],
            "ransomware": ["全球"],
            "data_theft": ["全球"],
            "hacking": ["全球"],
        }
        for cat in threat_categories:
            hints = category_geo_hints.get(cat, [])
            for hint in hints:
                detected_regions.add(hint)

        if not detected_regions:
            detected_regions.add("中国")

        return sorted(detected_regions)

    async def process_intelligence_findings(
        self,
        threat_categories: List[str],
        threat_level: str,
        intelligence_ids: List[str],
        content_summary: str = "",
    ) -> Tuple[List[EconomicImpact], List[MarketAlert]]:
        if threat_level not in VALID_THREAT_LEVELS:
            logger.warning(f"Invalid threat_level: {threat_level}")
            return [], []
        if not threat_categories:
            return [], []

        new_impacts: List[EconomicImpact] = []
        new_alerts: List[MarketAlert] = []

        llm_assessment = await self._llm_analyzer.assess_economic_impact(
            threat_categories, threat_level, content_summary
        )

        affected_sectors: Dict[str, float] = {}
        for cat in threat_categories:
            sectors = THREAT_TO_SECTOR_MAP.get(cat, [])
            multiplier = RISK_LEVEL_MULTIPLIERS.get(threat_level, 0.1)
            for sector in sectors:
                affected_sectors[sector] = max(affected_sectors.get(sector, 0), multiplier)

        geographic_scope = self.infer_geographic_scope(content_summary, threat_categories)

        for sector, risk_mult in affected_sectors.items():
            llm_market_analysis = await self._llm_analyzer.analyze_market_impact(
                sector, {"threat_categories": threat_categories, "threat_level": threat_level, "summary": content_summary[:500]}
            )
            self.update_market(sector, risk_delta=risk_mult, llm_market_analysis=llm_market_analysis)

            estimated_loss = 0.0
            loss_basis = ""
            if self._data_provider:
                estimated_loss, loss_basis = self._data_provider.compute_loss_estimate(sector, threat_level)

            if llm_assessment:
                sector_impacts = llm_assessment.get("sector_impacts", {})
                sector_impact = sector_impacts.get(sector, {})
                loss_multiplier = sector_impact.get("loss_multiplier", risk_mult)
                user_impact_ratio = sector_impact.get("user_impact_ratio", risk_mult)
                loss_range = llm_assessment.get("estimated_loss_range", [])
                if len(loss_range) == 2 and estimated_loss <= 0:
                    estimated_loss = (loss_range[0] + loss_range[1]) / 2 * loss_multiplier
                    loss_basis = "基于LLM评估"
                user_range = llm_assessment.get("affected_users_range", [])
                if len(user_range) == 2:
                    affected_users = int((user_range[0] + user_range[1]) / 2 * user_impact_ratio)
                else:
                    affected_users = 0
                llm_confidence = llm_assessment.get("confidence", None)
                llm_geo = llm_assessment.get("geographic_scope", [])
                if llm_geo:
                    geographic_scope = list(set(geographic_scope + llm_geo))
            else:
                loss_multiplier = risk_mult
                user_impact_ratio = risk_mult
                llm_confidence = None

            if estimated_loss <= 0:
                base_loss = self._baseline_calculator.get_loss_baseline(sector)
                estimated_loss = base_loss * risk_mult
                loss_basis = f"基于动态基线估算"

            if not llm_assessment or affected_users <= 0:
                base_users = self._baseline_calculator.get_user_baseline(sector)
                affected_users = int(base_users * risk_mult)

            if llm_confidence is not None:
                confidence = llm_confidence
            else:
                confidence = 0.7 if threat_level in ("critical", "high") else 0.5

            mc_result = self._mc_simulator.simulate_loss_distribution(
                sector=sector,
                base_loss=self._baseline_calculator.get_loss_baseline(sector),
                risk_multiplier=risk_mult,
                volatility=self.market_states.get(sector, MarketState(sector=sector, sector_name="")).volatility,
            )
            mc_adjusted_loss = mc_result.mean_loss
            if mc_adjusted_loss > 0:
                estimated_loss = (estimated_loss + mc_adjusted_loss) / 2

            duration_days = llm_assessment.get("duration_days_estimate", None) if llm_assessment else None
            if duration_days is None:
                duration_days = SECTOR_DURATION_DEFAULTS.get(sector, 30)

            impact = EconomicImpact(
                impact_id=f"imp-{uuid4().hex[:12]}",
                sector=sector,
                estimated_loss=max(0.0, estimated_loss),
                affected_users=max(0, affected_users),
                geographic_scope=sorted(set(geographic_scope)),
                duration_days=duration_days,
                confidence=max(0.0, min(1.0, confidence)),
                intelligence_source_ids=intelligence_ids[:20],
                threat_categories=threat_categories[:10],
                assessed_at=datetime.now(timezone.utc).isoformat(),
            )
            self.impacts.append(impact)
            new_impacts.append(impact)
            self._baseline_calculator.update_baselines(sector, estimated_loss, affected_users)

            narrative = await self._llm_analyzer.generate_risk_narrative(impact)
            if narrative:
                self._risk_narratives.append(narrative)

            severity_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info"}
            alert = MarketAlert(
                alert_id=f"ealert-{uuid4().hex[:12]}",
                sector=sector,
                alert_type=f"economic_{threat_level}",
                severity=severity_map.get(threat_level, "medium"),
                message=content_summary[:500] or f"检测到{MARKET_SECTORS.get(sector, sector)}领域{threat_level}级别经济风险",
                related_intelligence_ids=intelligence_ids[:20],
                economic_impact_ids=[impact.impact_id],
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            self.alerts.append(alert)
            new_alerts.append(alert)

            self._update_sector_flows(sector, threat_categories, risk_mult)

        if new_impacts or new_alerts:
            if self.use_db:
                for impact in new_impacts:
                    await self._persist_impact(impact)
                for alert in new_alerts:
                    await self._persist_alert(alert)
                await self.save_to_db()
            else:
                self.save_to_disk()

        logger.info(
            f"EconomicEngine processed: {len(affected_sectors)} sectors affected, "
            f"{len(new_impacts)} impacts, {len(new_alerts)} alerts"
        )
        return new_impacts, new_alerts

    def _update_sector_flows(self, primary_sector: str, threat_categories: List[str], intensity: float):
        correlations = self._sector_correlations.get(primary_sector, {})
        for target_sector, corr in correlations.items():
            flow = SectorFlow(
                from_sector=primary_sector,
                to_sector=target_sector,
                flow_volume=max(0.0, intensity * corr * BASE_LOSS_ESTIMATES.get(primary_sector, 100000)),
                transaction_count=max(1, int(intensity * 10)),
                risk_indicators=threat_categories[:3],
            )
            self.sector_flows.append(flow)

    async def create_transaction(
        self,
        sector: str,
        tx_type: str,
        amount: float,
        price: float,
        from_entity: str = "",
        to_entity: str = "",
        risk_score: float = 0.0,
        intelligence_ids: List[str] | None = None,
        description: str = "",
    ) -> Transaction:
        if sector not in VALID_SECTORS:
            raise ValueError(f"Invalid sector: {sector}. Must be one of {VALID_SECTORS}")
        if tx_type not in VALID_TX_TYPES:
            raise ValueError(f"Invalid tx_type: {tx_type}. Must be one of {VALID_TX_TYPES}")
        if amount < 0:
            raise ValueError("amount must be non-negative")
        if price < 0:
            raise ValueError("price must be non-negative")
        risk_score = max(0.0, min(1.0, risk_score))

        fee_rate = 0.001
        total_value = amount * price
        fee = total_value * fee_rate
        tx = Transaction(
            tx_id=f"tx-{uuid4().hex[:12]}",
            sector=sector,
            tx_type=tx_type,
            amount=amount,
            price=price,
            total_value=total_value,
            fee=fee,
            from_entity=from_entity[:128],
            to_entity=to_entity[:128],
            risk_score=risk_score,
            intelligence_ids=intelligence_ids or [],
            timestamp=datetime.now(timezone.utc).isoformat(),
            description=description[:1000],
        )
        self.transactions.append(tx)
        state = self.market_states.get(sector)
        if state:
            state.volume_24h += total_value
            state.active_entities += 1

        if self.use_db:
            await self._persist_transaction(tx)
            await self.save_to_db()
        else:
            self.save_to_disk()
        return tx

    def get_dashboard(self) -> EconomicDashboard:
        total_loss = sum(i.estimated_loss for i in self.impacts)
        total_affected = sum(i.affected_users for i in self.impacts)
        active_alerts = sum(1 for a in self.alerts if not a.is_resolved)
        return EconomicDashboard(
            total_estimated_loss=total_loss,
            total_affected_users=total_affected,
            active_alerts=active_alerts,
            market_states=[s.to_dict() for s in self.market_states.values()],
            sector_flows=[f.to_dict() for f in self.sector_flows[-50:]],
            recent_transactions=[t.to_dict() for t in self.transactions[-20:]],
            impacts=[i.to_dict() for i in self.impacts[-50:]],
            alerts=[a.to_dict() for a in self.alerts[-20:]],
            updated_at=datetime.now(timezone.utc).isoformat(),
        )

    def get_market_state(self, sector: str) -> Optional[Dict]:
        state = self.market_states.get(sector)
        return state.to_dict() if state else None

    def get_all_market_states(self) -> List[Dict]:
        return [s.to_dict() for s in self.market_states.values()]

    def get_impacts(self, sector: Optional[str] = None) -> List[Dict]:
        if sector:
            if sector not in VALID_SECTORS:
                return []
            return [i.to_dict() for i in self.impacts if i.sector == sector]
        return [i.to_dict() for i in self.impacts]

    def get_alerts(self, resolved: bool = False, severity: Optional[str] = None) -> List[Dict]:
        result = self.alerts
        if not resolved:
            result = [a for a in result if not a.is_resolved]
        else:
            result = [a for a in result if a.is_resolved]
        if severity:
            if severity not in VALID_THREAT_LEVELS:
                return []
            result = [a for a in result if a.severity == severity]
        return [a.to_dict() for a in result]

    async def resolve_alert(self, alert_id: str, db_session=None) -> bool:
        for alert in self.alerts:
            if alert.alert_id == alert_id:
                alert.is_resolved = True
                if self.use_db:
                    from app.db.economic_tables import EconomicAlertTable
                    from sqlalchemy import select as sa_select
                    try:
                        if db_session is not None:
                            result = await db_session.execute(
                                sa_select(EconomicAlertTable).where(EconomicAlertTable.id == alert_id)
                            )
                            row = result.scalar_one_or_none()
                            if row:
                                row.is_resolved = True
                                await db_session.commit()
                        else:
                            from app.db.database import async_session_factory
                            async with async_session_factory() as session:
                                result = await session.execute(
                                    sa_select(EconomicAlertTable).where(EconomicAlertTable.id == alert_id)
                                )
                                row = result.scalar_one_or_none()
                                if row:
                                    row.is_resolved = True
                                    await session.commit()
                    except Exception as exc:
                        logger.warning(f"Failed to update alert in DB: {exc}")
                    await self.save_to_db()
                else:
                    self.save_to_disk()
                return True
        return False

    def get_sector_flows(self, sector: Optional[str] = None) -> List[Dict]:
        if sector:
            if sector not in VALID_SECTORS:
                return []
            return [f.to_dict() for f in self.sector_flows if f.from_sector == sector or f.to_sector == sector]
        return [f.to_dict() for f in self.sector_flows]

    def get_transactions(self, sector: Optional[str] = None, min_risk: float = 0.0, limit: int = 50) -> List[Dict]:
        limit = max(1, min(200, limit))
        min_risk = max(0.0, min(1.0, min_risk))
        result = self.transactions
        if sector:
            if sector not in VALID_SECTORS:
                return []
            result = [t for t in result if t.sector == sector]
        if min_risk > 0:
            result = [t for t in result if t.risk_score >= min_risk]
        return [t.to_dict() for t in result[-limit:]]

    def get_correlation_matrix(self) -> Dict[str, Dict[str, float]]:
        return self._sector_correlations

    def get_adaptive_correlation_matrix(self) -> Dict[str, Dict[str, float]]:
        return self._adaptive_corr_engine.compute_adaptive_correlations()

    def get_economic_summary(self) -> Dict:
        total_loss = sum(i.estimated_loss for i in self.impacts)
        total_affected = sum(i.affected_users for i in self.impacts)
        active_alerts = sum(1 for a in self.alerts if not a.is_resolved)
        sector_risks = {k: v.risk_score for k, v in self.market_states.items()}
        top_risk_sectors = sorted(sector_risks.items(), key=lambda x: x[1], reverse=True)[:5]
        return {
            "total_estimated_loss": total_loss,
            "total_affected_users": total_affected,
            "active_alerts": active_alerts,
            "total_transactions": len(self.transactions),
            "total_impacts": len(self.impacts),
            "top_risk_sectors": [
                {"sector": k, "sector_name": MARKET_SECTORS.get(k, k), "risk_score": v}
                for k, v in top_risk_sectors
            ],
            "sector_count": len(self.market_states),
        }

    def simulate_sector_risk(
        self,
        sector: str,
        risk_multiplier: Optional[float] = None,
        simulations: Optional[int] = None,
    ) -> Optional[MonteCarloResult]:
        if sector not in VALID_SECTORS:
            return None
        state = self.market_states.get(sector)
        if not state:
            return None
        base_loss = self._baseline_calculator.get_loss_baseline(sector)
        mult = risk_multiplier or RISK_LEVEL_MULTIPLIERS.get("medium", 0.3)
        return self._mc_simulator.simulate_loss_distribution(
            sector=sector,
            base_loss=base_loss,
            risk_multiplier=mult,
            volatility=state.volatility,
            simulations=simulations,
        )

    def simulate_multi_sector_risks(
        self,
        threat_level: str = "high",
        simulations: Optional[int] = None,
    ) -> Dict[str, MonteCarloResult]:
        mult = RISK_LEVEL_MULTIPLIERS.get(threat_level, 0.3)
        sector_risks = {}
        for sector, state in self.market_states.items():
            base_loss = self._baseline_calculator.get_loss_baseline(sector)
            sector_risks[sector] = (base_loss, mult, state.volatility)
        adapted_corr = self._adaptive_corr_engine.compute_adaptive_correlations()
        return self._mc_simulator.simulate_multi_factor(
            sector_risks=sector_risks,
            correlation_matrix=adapted_corr,
            simulations=simulations,
        )

    def get_risk_narratives(self, impact_id: Optional[str] = None) -> List[Dict]:
        if impact_id:
            return [n.to_dict() for n in self._risk_narratives if n.impact_id == impact_id]
        return [n.to_dict() for n in self._risk_narratives]

    def get_baseline_stats(self) -> Dict:
        return self._baseline_calculator.get_baseline_stats()

    def get_monte_carlo_summary(self, sector: Optional[str] = None) -> Dict:
        if sector:
            if sector not in VALID_SECTORS:
                return {}
            result = self.simulate_sector_risk(sector)
            return result.to_dict() if result else {}
        results = {}
        for s in VALID_SECTORS:
            r = self.simulate_sector_risk(s, risk_multiplier=0.3, simulations=1000)
            if r:
                results[s] = r.to_dict()
        return results
